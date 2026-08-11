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
        let endpoint = config
            .sts_endpoint
            .clone()
            .unwrap_or_else(|| format!("https://sts.{}.amazonaws.com", config.region));

        Self {
            endpoint,
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
                value.to_str().map_err(|e| format!("header encoding error: {}", e))?.to_string(),
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
            return Err(format!("STS HTTP {}: {}", status, truncate(&response_body, 200)));
        }

        Ok(response_body)
    }
}

fn parse_get_caller_identity_response(xml: &str) -> Result<CallerIdentity, String> {
    use quick_xml::events::Event;
    use quick_xml::reader::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut account = None;
    let mut arn = None;
    let mut user_id = None;
    let mut current_element = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                current_element = String::from_utf8_lossy(e.name().as_ref()).to_string();
            }
            Ok(Event::Text(ref e)) => {
                let text = e.unescape().map_err(|e| format!("XML decode error: {}", e))?.to_string();
                match current_element.as_str() {
                    "Account" => account = Some(text),
                    "Arn" => arn = Some(text),
                    "UserId" => user_id = Some(text),
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {}", e)),
            _ => {}
        }
    }

    Ok(CallerIdentity {
        account: account.ok_or("missing Account in STS response")?,
        arn: arn.ok_or("missing Arn in STS response")?,
        user_id: user_id.ok_or("missing UserId in STS response")?,
    })
}

fn truncate(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len { s } else { &s[..max_len] }
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
        assert_eq!(id.arn, "arn:aws:sts::111122223333:assumed-role/MyRole/session");
        assert_eq!(id.user_id, "AROAEXAMPLE:session");
    }

    #[test]
    fn parse_missing_account() {
        let xml = r#"<GetCallerIdentityResponse><GetCallerIdentityResult>
    <Arn>arn:aws:sts::111122223333:assumed-role/R/s</Arn>
    <UserId>U:s</UserId>
  </GetCallerIdentityResult></GetCallerIdentityResponse>"#;
        assert!(parse_get_caller_identity_response(xml).unwrap_err().contains("missing Account"));
    }

    #[test]
    fn parse_missing_arn() {
        let xml = r#"<GetCallerIdentityResponse><GetCallerIdentityResult>
    <UserId>U:s</UserId>
    <Account>111122223333</Account>
  </GetCallerIdentityResult></GetCallerIdentityResponse>"#;
        assert!(parse_get_caller_identity_response(xml).unwrap_err().contains("missing Arn"));
    }

    #[test]
    fn parse_missing_user_id() {
        let xml = r#"<GetCallerIdentityResponse><GetCallerIdentityResult>
    <Arn>arn:aws:sts::111122223333:assumed-role/R/s</Arn>
    <Account>111122223333</Account>
  </GetCallerIdentityResult></GetCallerIdentityResponse>"#;
        assert!(parse_get_caller_identity_response(xml).unwrap_err().contains("missing UserId"));
    }

    #[test]
    fn parse_error_response() {
        let xml = r#"<ErrorResponse><Error><Code>ExpiredTokenException</Code></Error></ErrorResponse>"#;
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
}
