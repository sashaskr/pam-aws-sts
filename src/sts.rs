use crate::config::AwsConfig;
use crate::credentials::StsCredentials;

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{
    sign, SignableBody, SignableRequest, SignatureLocation, SigningParams, SigningSettings,
};
use aws_sigv4::sign::v4;
use aws_smithy_runtime_api::client::identity::Identity;
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct CallerIdentity {
    pub account: String,
    pub arn: String,
    #[allow(dead_code)]
    pub user_id: String,
}

pub struct StsClient {
    endpoint: String,
    region: String,
    timeout_secs: u64,
}

impl StsClient {
    pub fn new(config: &AwsConfig) -> Self {
        Self {
            // Single source of truth for endpoint resolution, so partition and
            // FIPS handling cannot drift from Config::sts_endpoint().
            endpoint: config.resolved_endpoint(),
            region: config.region.clone(),
            timeout_secs: config.timeout_secs,
        }
    }

    pub fn get_caller_identity(&self, creds: &StsCredentials) -> Result<CallerIdentity, String> {
        let body = "Action=GetCallerIdentity&Version=2011-06-15";

        let aws_creds = Credentials::new(
            &creds.access_key_id,
            &creds.secret_access_key,
            Some(creds.session_token.clone()),
            None,
            "pam_aws_sts",
        );

        let (signed_headers, signed_body) = self.sign_request(body, &aws_creds)?;
        let response = self.do_request(&signed_headers, &signed_body)?;
        parse_get_caller_identity_response(&response)
    }

    fn sign_request(
        &self,
        body: &str,
        credentials: &Credentials,
    ) -> Result<(Vec<(String, String)>, String), String> {
        let mut settings = SigningSettings::default();
        settings.signature_location = SignatureLocation::Headers;

        let identity = Identity::from(credentials.clone());
        let signing_params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name("sts")
            .time(SystemTime::now())
            .settings(settings)
            .build()
            .map_err(|e| format!("signing params error: {}", e))?;

        let signable_request = SignableRequest::new(
            "POST",
            &self.endpoint,
            std::iter::once(("content-type", "application/x-www-form-urlencoded")),
            SignableBody::Bytes(body.as_bytes()),
        )
        .map_err(|e| format!("signable request error: {}", e))?;

        let signing_params = SigningParams::V4(signing_params);
        let (signing_instructions, _signature) = sign(signable_request, &signing_params)
            .map_err(|e| format!("SigV4 signing failed: {}", e))?
            .into_parts();

        let mut request = http::Request::builder()
            .method("POST")
            .uri(&self.endpoint)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(())
            .map_err(|e| format!("request build error: {}", e))?;

        signing_instructions.apply_to_request_http1x(&mut request);

        let mut headers = Vec::new();
        for (name, value) in request.headers() {
            headers.push((
                name.as_str().to_string(),
                value
                    .to_str()
                    .map_err(|e| format!("header encoding error: {}", e))?
                    .to_string(),
            ));
        }

        Ok((headers, body.to_string()))
    }

    fn do_request(&self, headers: &[(String, String)], body: &str) -> Result<String, String> {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .build();

        let mut request = agent.post(&self.endpoint);
        for (name, value) in headers {
            request = request.set(name, value);
        }

        let response = request
            .send_string(body)
            .map_err(|e| format!("STS request failed: {}", e))?;

        let status = response.status();
        let response_body = response
            .into_string()
            .map_err(|e| format!("failed to read response: {}", e))?;

        if status != 200 {
            return Err(format!(
                "STS HTTP {}: {}",
                status,
                truncate(&response_body, 200)
            ));
        }

        Ok(response_body)
    }
}

const RESPONSE_ROOT: &str = "GetCallerIdentityResponse";
const RESULT_ELEMENT: &str = "GetCallerIdentityResult";

/// Records a field value, rejecting a second occurrence.
///
/// A genuine STS response carries each field exactly once. A duplicate means
/// the document is not what we think it is, and silently letting the last one
/// win would make which identity is used depend on element order.
fn set_once(slot: &mut Option<String>, field: &str, value: String) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("duplicate <{}> in STS response", field));
    }
    *slot = Some(value);
    Ok(())
}

/// Extracts the caller identity from a `GetCallerIdentity` response.
///
/// Field recognition is anchored to the exact element path
/// `GetCallerIdentityResponse/GetCallerIdentityResult/{Account,Arn,UserId}`.
/// The previous implementation tracked only the most recent start tag and
/// never cleared it on a closing tag, so it accepted these names from
/// anywhere in the document and could attribute text to the wrong element
/// when they were nested. Since the endpoint is operator-configurable and the
/// identity decision rests entirely on this parse, the structure is checked
/// rather than assumed.
fn parse_get_caller_identity_response(xml: &str) -> Result<CallerIdentity, String> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut path: Vec<String> = Vec::new();
    let mut root: Option<String> = None;
    let mut text_buf = String::new();

    let mut account = None;
    let mut arn = None;
    let mut user_id = None;
    let mut error_code = None;
    let mut error_message = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                // local_name() drops any namespace prefix.
                let name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                if path.is_empty() {
                    root = Some(name.clone());
                }
                path.push(name);
                text_buf.clear();
            }
            Ok(Event::Text(ref t)) => {
                // Appended rather than assigned: one element's value arrives
                // as several events when it contains entity references.
                //
                // Text content is already literal here. quick-xml reports
                // entity references as separate GeneralRef events, so
                // unescaping this would be wrong as well as redundant.
                let chunk = t
                    .xml10_content()
                    .map_err(|e| format!("XML decode error: {}", e))?;
                text_buf.push_str(&chunk);
            }
            Ok(Event::GeneralRef(ref r)) => {
                // `&#38;` and `&#x26;` resolve directly; the predefined named
                // references (amp, lt, gt, quot, apos) go through unescape.
                match r
                    .resolve_char_ref()
                    .map_err(|e| format!("XML character reference error: {}", e))?
                {
                    Some(ch) => text_buf.push(ch),
                    None => {
                        let name = r.decode().map_err(|e| format!("XML decode error: {}", e))?;
                        let entity = format!("&{};", name);
                        let resolved = quick_xml::escape::unescape(&entity)
                            .map_err(|e| format!("unknown XML entity '{}': {}", entity, e))?;
                        text_buf.push_str(&resolved);
                    }
                }
            }
            Ok(Event::CData(ref c)) => {
                text_buf.push_str(&String::from_utf8_lossy(c.as_ref()));
            }
            Ok(Event::End(_)) => {
                if path.len() == 3 {
                    let value = std::mem::take(&mut text_buf);
                    if path[0] == RESPONSE_ROOT && path[1] == RESULT_ELEMENT {
                        match path[2].as_str() {
                            "Account" => set_once(&mut account, "Account", value)?,
                            "Arn" => set_once(&mut arn, "Arn", value)?,
                            "UserId" => set_once(&mut user_id, "UserId", value)?,
                            _ => {}
                        }
                    } else if path[0] == "ErrorResponse" && path[1] == "Error" {
                        match path[2].as_str() {
                            "Code" => error_code = Some(value),
                            "Message" => error_message = Some(value),
                            _ => {}
                        }
                    }
                }
                path.pop();
                text_buf.clear();
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {}", e)),
            _ => {}
        }
    }

    // STS can return an error document with HTTP 200, so report it as an error
    // rather than as a missing field.
    if let Some(code) = error_code {
        return Err(match error_message {
            Some(message) => format!("STS error {}: {}", code, message),
            None => format!("STS error {}", code),
        });
    }

    match root.as_deref() {
        Some(RESPONSE_ROOT) => {}
        Some(other) => {
            return Err(format!(
                "unexpected STS response root element '{}' (expected {})",
                other, RESPONSE_ROOT
            ))
        }
        None => return Err("STS response contained no XML elements".into()),
    }

    Ok(CallerIdentity {
        account: account.ok_or("missing Account in STS response")?,
        arn: arn.ok_or("missing Arn in STS response")?,
        user_id: user_id.ok_or("missing UserId in STS response")?,
    })
}

/// Truncates `s` to at most `max_len` **bytes** without splitting a character.
///
/// Slicing a `str` at an index that is not a character boundary panics. This
/// function is applied to STS error bodies, which are remote input, so a naive
/// `&s[..max_len]` is reachable by anything that returns a non-ASCII error
/// page (a proxy, a WAF, a localized gateway message). A panic here aborts the
/// PostgreSQL backend, so the boundary is walked back instead.
fn truncate(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        return s;
    }
    let mut end = max_len;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_response() {
        let xml = r#"<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::111122223333:assumed-role/MyRole/session</Arn>
    <UserId>AROAEXAMPLE:session</UserId>
    <Account>111122223333</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata><RequestId>aaa-bbb</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>"#;
        let id = parse_get_caller_identity_response(xml).unwrap();
        assert_eq!(id.account, "111122223333");
        assert_eq!(
            id.arn,
            "arn:aws:sts::111122223333:assumed-role/MyRole/session"
        );
        assert_eq!(id.user_id, "AROAEXAMPLE:session");
    }

    #[test]
    fn parse_missing_account() {
        let xml = r#"<GetCallerIdentityResponse><GetCallerIdentityResult>
    <Arn>arn:aws:sts::111122223333:assumed-role/R/s</Arn>
    <UserId>U:s</UserId>
  </GetCallerIdentityResult></GetCallerIdentityResponse>"#;
        assert!(parse_get_caller_identity_response(xml)
            .unwrap_err()
            .contains("missing Account"));
    }

    #[test]
    fn parse_missing_arn() {
        let xml = r#"<GetCallerIdentityResponse><GetCallerIdentityResult>
    <UserId>U:s</UserId>
    <Account>111122223333</Account>
  </GetCallerIdentityResult></GetCallerIdentityResponse>"#;
        assert!(parse_get_caller_identity_response(xml)
            .unwrap_err()
            .contains("missing Arn"));
    }

    #[test]
    fn parse_missing_user_id() {
        let xml = r#"<GetCallerIdentityResponse><GetCallerIdentityResult>
    <Arn>arn:aws:sts::111122223333:assumed-role/R/s</Arn>
    <Account>111122223333</Account>
  </GetCallerIdentityResult></GetCallerIdentityResponse>"#;
        assert!(parse_get_caller_identity_response(xml)
            .unwrap_err()
            .contains("missing UserId"));
    }

    #[test]
    fn parse_error_response() {
        let xml =
            r#"<ErrorResponse><Error><Code>ExpiredTokenException</Code></Error></ErrorResponse>"#;
        assert!(parse_get_caller_identity_response(xml).is_err());
    }

    #[test]
    fn parse_empty_xml() {
        assert!(parse_get_caller_identity_response("").is_err());
    }

    #[test]
    fn parse_garbage() {
        assert!(parse_get_caller_identity_response("not xml {{}").is_err());
    }

    // --- structural hardening ---

    fn wrap(inner: &str) -> String {
        format!(
            "<GetCallerIdentityResponse><GetCallerIdentityResult>{}\
             </GetCallerIdentityResult></GetCallerIdentityResponse>",
            inner
        )
    }

    const GOOD_FIELDS: &str = "<Arn>arn:aws:sts::111122223333:assumed-role/R/s</Arn>\
                               <UserId>AROAEXAMPLE:s</UserId>\
                               <Account>111122223333</Account>";

    #[test]
    fn namespaced_elements_are_accepted() {
        let xml = r#"<sts:GetCallerIdentityResponse xmlns:sts="https://sts.amazonaws.com/doc/2011-06-15/">
  <sts:GetCallerIdentityResult>
    <sts:Arn>arn:aws:sts::111122223333:assumed-role/R/s</sts:Arn>
    <sts:UserId>AROAEXAMPLE:s</sts:UserId>
    <sts:Account>111122223333</sts:Account>
  </sts:GetCallerIdentityResult>
</sts:GetCallerIdentityResponse>"#;
        let id = parse_get_caller_identity_response(xml).unwrap();
        assert_eq!(id.account, "111122223333");
    }

    // Previously these names were honored from anywhere in the document.
    #[test]
    fn fields_outside_the_result_element_are_ignored() {
        let xml = r#"<GetCallerIdentityResponse>
  <ResponseMetadata>
    <Account>999999999999</Account>
    <Arn>arn:aws:sts::999999999999:assumed-role/Attacker/s</Arn>
    <UserId>AROAEVIL:s</UserId>
  </ResponseMetadata>
</GetCallerIdentityResponse>"#;
        let err = parse_get_caller_identity_response(xml).unwrap_err();
        assert!(err.contains("missing"), "unexpected error: {}", err);
    }

    #[test]
    fn stray_fields_do_not_override_the_real_ones() {
        let xml = format!(
            "<GetCallerIdentityResponse><GetCallerIdentityResult>{}\
             </GetCallerIdentityResult>\
             <ResponseMetadata><Account>999999999999</Account></ResponseMetadata>\
             </GetCallerIdentityResponse>",
            GOOD_FIELDS
        );
        let id = parse_get_caller_identity_response(&xml).unwrap();
        assert_eq!(id.account, "111122223333");
    }

    #[test]
    fn unexpected_root_element_rejected() {
        let xml = format!(
            "<SomethingElse><GetCallerIdentityResult>{}</GetCallerIdentityResult></SomethingElse>",
            GOOD_FIELDS
        );
        let err = parse_get_caller_identity_response(&xml).unwrap_err();
        assert!(
            err.contains("unexpected STS response root element"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn duplicate_field_rejected() {
        let xml = wrap(
            "<Account>111122223333</Account><Arn>arn:aws:sts::111122223333:assumed-role/R/s</Arn>\
             <UserId>U:s</UserId><Account>999999999999</Account>",
        );
        let err = parse_get_caller_identity_response(&xml).unwrap_err();
        assert!(err.contains("duplicate <Account>"), "got: {}", err);
    }

    #[test]
    fn error_response_reports_code_and_message() {
        let xml = r#"<ErrorResponse><Error>
            <Code>ExpiredTokenException</Code>
            <Message>The security token included in the request is expired</Message>
          </Error></ErrorResponse>"#;
        let err = parse_get_caller_identity_response(xml).unwrap_err();
        assert!(err.contains("ExpiredTokenException"), "got: {}", err);
        assert!(err.contains("expired"), "got: {}", err);
    }

    #[test]
    fn error_response_without_message_still_reports_code() {
        let xml =
            r#"<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>"#;
        let err = parse_get_caller_identity_response(xml).unwrap_err();
        assert!(err.contains("InvalidClientTokenId"), "got: {}", err);
    }

    // A nested child used to leave current_element pointing at the child, so
    // the parent's text was dropped or misattributed.
    #[test]
    fn nested_child_does_not_corrupt_the_parent_value() {
        let xml = wrap(
            "<Arn><Decoy>junk</Decoy>arn:aws:sts::111122223333:assumed-role/R/s</Arn>\
             <UserId>AROAEXAMPLE:s</UserId><Account>111122223333</Account>",
        );
        let id = parse_get_caller_identity_response(&xml).unwrap();
        assert_eq!(id.arn, "arn:aws:sts::111122223333:assumed-role/R/s");
    }

    // An entity reference splits one element's value across several parser
    // events, so the value has to be accumulated rather than assigned.
    #[test]
    fn entity_escaped_value_is_reassembled() {
        let xml = wrap(
            "<Arn>arn:aws:sts::111122223333:assumed-role/My&amp;Role/s</Arn>\
             <UserId>U:s</UserId><Account>111122223333</Account>",
        );
        let id = parse_get_caller_identity_response(&xml).unwrap();
        assert_eq!(id.arn, "arn:aws:sts::111122223333:assumed-role/My&Role/s");
    }

    #[test]
    fn numeric_character_references_are_resolved() {
        for (encoded, expected) in [("&#38;", "&"), ("&#x26;", "&"), ("&#65;", "A")] {
            let xml = wrap(&format!(
                "<Arn>a{}b</Arn><UserId>U:s</UserId><Account>111122223333</Account>",
                encoded
            ));
            let id = parse_get_caller_identity_response(&xml).unwrap();
            assert_eq!(id.arn, format!("a{}b", expected), "for {}", encoded);
        }
    }

    #[test]
    fn all_predefined_entities_are_resolved() {
        for (encoded, expected) in [
            ("&amp;", "&"),
            ("&lt;", "<"),
            ("&gt;", ">"),
            ("&quot;", "\""),
            ("&apos;", "'"),
        ] {
            let xml = wrap(&format!(
                "<Arn>x{}y</Arn><UserId>U:s</UserId><Account>111122223333</Account>",
                encoded
            ));
            let id = parse_get_caller_identity_response(&xml).unwrap();
            assert_eq!(id.arn, format!("x{}y", expected), "for {}", encoded);
        }
    }

    #[test]
    fn multiple_entities_in_one_value() {
        let xml =
            wrap("<Arn>a&amp;b&lt;c&gt;d</Arn><UserId>U:s</UserId><Account>111122223333</Account>");
        let id = parse_get_caller_identity_response(&xml).unwrap();
        assert_eq!(id.arn, "a&b<c>d");
    }

    #[test]
    fn cdata_value_is_read() {
        let xml = wrap(
            "<Arn><![CDATA[arn:aws:sts::111122223333:assumed-role/R/s]]></Arn>\
             <UserId>U:s</UserId><Account>111122223333</Account>",
        );
        let id = parse_get_caller_identity_response(&xml).unwrap();
        assert_eq!(id.arn, "arn:aws:sts::111122223333:assumed-role/R/s");
    }

    #[test]
    fn empty_response_body_rejected() {
        assert!(parse_get_caller_identity_response("")
            .unwrap_err()
            .contains("no XML elements"));
    }

    #[test]
    fn truncate_short() {
        assert_eq!(truncate("hi", 10), "hi");
    }

    #[test]
    fn truncate_long() {
        assert_eq!(truncate("hello world", 5), "hello");
    }

    #[test]
    fn truncate_exact() {
        assert_eq!(truncate("exact", 5), "exact");
    }

    // Regression: this input previously panicked with
    // "byte index 200 is not a char boundary".
    #[test]
    fn truncate_does_not_split_multibyte_char() {
        let mut body = "x".repeat(199);
        body.push('\u{2014}'); // em dash, 3 bytes spanning indices 199..202
        body.push_str(&"y".repeat(50));

        let out = truncate(&body, 200);
        assert_eq!(out.len(), 199, "should stop before the multibyte char");
        assert!(out.chars().all(|c| c == 'x'));
    }

    #[test]
    fn truncate_handles_all_multibyte() {
        // Every char is 4 bytes, so no boundary lands on an odd index.
        let body = "\u{1F600}".repeat(10); // 40 bytes
        assert_eq!(truncate(&body, 7).len(), 4);
        assert_eq!(truncate(&body, 4).len(), 4);
        assert_eq!(truncate(&body, 3).len(), 0);
    }

    #[test]
    fn truncate_zero_len() {
        assert_eq!(truncate("anything", 0), "");
    }

    #[test]
    fn truncate_realistic_sts_error_body_is_not_a_panic() {
        // A localized or proxy-generated error page reaching the >200 byte path.
        let body = format!("<html><body>{}</body></html>", "é".repeat(400));
        let out = truncate(&body, 200);
        assert!(out.len() <= 200);
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }
}
