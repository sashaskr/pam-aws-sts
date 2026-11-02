use crate::config::Config;
use crate::sts::CallerIdentity;

pub fn validate_identity(
    pam_username: &str,
    identity: &CallerIdentity,
    config: &Config,
) -> Result<(), String> {
    if !config.aws.allowed_account_ids.contains(&identity.account) {
        return Err(format!(
            "account '{}' not in allowed_account_ids",
            identity.account
        ));
    }

    let role_name = extract_role_name(&identity.arn)?;

    // Scoped by account, not role name alone. IAM guarantees role name
    // uniqueness only within an account, so with several allowed accounts a
    // bare role-name lookup would let a role in the least trusted account
    // resolve to a mapping intended for the most trusted one.
    let allowed_users = config
        .allowed_users_for(&identity.account, &role_name)
        .ok_or_else(|| {
            format!(
                "role '{}' in account '{}' has no mapping in config",
                role_name, identity.account
            )
        })?;

    if !allowed_users.iter().any(|u| u == pam_username) {
        return Err(format!(
            "role '{}' not authorized for pg user '{}' (allowed: {:?})",
            role_name, pam_username, allowed_users
        ));
    }

    Ok(())
}

fn extract_role_name(arn: &str) -> Result<String, String> {
    let parts: Vec<&str> = arn.split(':').collect();
    if parts.len() < 6 {
        return Err(format!("invalid ARN: '{}'", arn));
    }

    let resource = parts[5];

    if let Some(rest) = resource.strip_prefix("assumed-role/") {
        return rest
            .split('/')
            .next()
            .map(|s| s.to_string())
            .ok_or_else(|| format!("cannot parse role from: '{}'", resource));
    }

    if let Some(rest) = resource.strip_prefix("role/") {
        return rest
            .rsplit('/')
            .next()
            .map(|s| s.to_string())
            .ok_or_else(|| format!("cannot parse role from: '{}'", resource));
    }

    Err(format!("unsupported ARN resource type: '{}'", resource))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn cfg() -> Config {
        Config::from_str(
            r#"
[aws]
region = "us-east-1"
allowed_account_ids = ["111122223333"]

[role_mapping]
"AdminRole" = ["dbadmin"]
"MultiRole" = ["analyst", "viewer"]
"#,
        )
        .unwrap()
    }

    fn id(account: &str, arn: &str) -> CallerIdentity {
        CallerIdentity {
            account: account.into(),
            arn: arn.into(),
            user_id: "U:s".into(),
        }
    }

    #[test]
    fn valid_assumed_role() {
        let c = cfg();
        let i = id(
            "111122223333",
            "arn:aws:sts::111122223333:assumed-role/AdminRole/sess",
        );
        assert!(validate_identity("dbadmin", &i, &c).is_ok());
    }

    #[test]
    fn valid_iam_role() {
        let c = cfg();
        let i = id("111122223333", "arn:aws:iam::111122223333:role/AdminRole");
        assert!(validate_identity("dbadmin", &i, &c).is_ok());
    }

    #[test]
    fn valid_role_with_path() {
        let c = cfg();
        let i = id(
            "111122223333",
            "arn:aws:iam::111122223333:role/org/team/AdminRole",
        );
        assert!(validate_identity("dbadmin", &i, &c).is_ok());
    }

    #[test]
    fn wrong_account_rejected() {
        let c = cfg();
        let i = id(
            "999999999999",
            "arn:aws:sts::999999999999:assumed-role/AdminRole/s",
        );
        assert!(validate_identity("dbadmin", &i, &c)
            .unwrap_err()
            .contains("not in allowed_account_ids"));
    }

    #[test]
    fn unmapped_role_rejected() {
        let c = cfg();
        let i = id(
            "111122223333",
            "arn:aws:sts::111122223333:assumed-role/UnknownRole/s",
        );
        assert!(validate_identity("dbadmin", &i, &c)
            .unwrap_err()
            .contains("no mapping"));
    }

    #[test]
    fn wrong_pg_username_rejected() {
        let c = cfg();
        let i = id(
            "111122223333",
            "arn:aws:sts::111122223333:assumed-role/AdminRole/s",
        );
        assert!(validate_identity("viewer", &i, &c)
            .unwrap_err()
            .contains("not authorized"));
    }

    #[test]
    fn multi_user_mapping_first() {
        let c = cfg();
        let i = id(
            "111122223333",
            "arn:aws:sts::111122223333:assumed-role/MultiRole/s",
        );
        assert!(validate_identity("analyst", &i, &c).is_ok());
    }

    #[test]
    fn multi_user_mapping_second() {
        let c = cfg();
        let i = id(
            "111122223333",
            "arn:aws:sts::111122223333:assumed-role/MultiRole/s",
        );
        assert!(validate_identity("viewer", &i, &c).is_ok());
    }

    #[test]
    fn multi_user_mapping_wrong() {
        let c = cfg();
        let i = id(
            "111122223333",
            "arn:aws:sts::111122223333:assumed-role/MultiRole/s",
        );
        assert!(validate_identity("dbadmin", &i, &c).is_err());
    }

    #[test]
    fn extract_assumed_role() {
        assert_eq!(
            extract_role_name("arn:aws:sts::123:assumed-role/Foo/bar").unwrap(),
            "Foo"
        );
    }

    #[test]
    fn extract_iam_role() {
        assert_eq!(
            extract_role_name("arn:aws:iam::123:role/Bar").unwrap(),
            "Bar"
        );
    }

    #[test]
    fn extract_iam_role_with_path() {
        assert_eq!(
            extract_role_name("arn:aws:iam::123:role/a/b/c/Deep").unwrap(),
            "Deep"
        );
    }

    #[test]
    fn extract_invalid_arn() {
        assert!(extract_role_name("garbage").is_err());
    }

    #[test]
    fn extract_short_arn() {
        assert!(extract_role_name("arn:aws:sts::123").is_err());
    }

    #[test]
    fn extract_user_arn_rejected() {
        assert!(extract_role_name("arn:aws:iam::123:user/Bob")
            .unwrap_err()
            .contains("unsupported"));
    }

    #[test]
    fn extract_group_arn_rejected() {
        assert!(extract_role_name("arn:aws:iam::123:group/Admins").is_err());
    }

    #[test]
    fn extract_federated_user_rejected() {
        assert!(extract_role_name("arn:aws:sts::123:federated-user/alice").is_err());
    }

    // --- account-scoped mapping ---

    fn multi_account_cfg() -> Config {
        Config::from_str(
            r#"
[aws]
region = "us-east-1"
allowed_account_ids = ["111122223333", "444455556666"]

[role_mapping."111122223333"]
"AdminRole" = ["dbadmin"]

[role_mapping."444455556666"]
"ReportingRole" = ["analyst"]
"#,
        )
        .unwrap()
    }

    #[test]
    fn per_account_mapping_allows_its_own_account() {
        let c = multi_account_cfg();
        let i = id(
            "111122223333",
            "arn:aws:sts::111122223333:assumed-role/AdminRole/s",
        );
        assert!(validate_identity("dbadmin", &i, &c).is_ok());
    }

    // The privilege escalation this change exists to prevent: the same role
    // name in a different allowed account must not inherit the mapping.
    #[test]
    fn same_role_name_in_another_allowed_account_is_rejected() {
        let c = multi_account_cfg();
        let i = id(
            "444455556666",
            "arn:aws:sts::444455556666:assumed-role/AdminRole/s",
        );
        let err = validate_identity("dbadmin", &i, &c).unwrap_err();
        assert!(
            err.contains("no mapping"),
            "AdminRole in account 444455556666 must not reach the 111122223333 \
             mapping, got: {}",
            err
        );
    }

    #[test]
    fn per_account_mapping_is_not_cross_wired() {
        let c = multi_account_cfg();
        // analyst is mapped in 444455556666, not in 111122223333
        let i = id(
            "111122223333",
            "arn:aws:sts::111122223333:assumed-role/ReportingRole/s",
        );
        assert!(validate_identity("analyst", &i, &c).is_err());

        let i = id(
            "444455556666",
            "arn:aws:sts::444455556666:assumed-role/ReportingRole/s",
        );
        assert!(validate_identity("analyst", &i, &c).is_ok());
    }

    #[test]
    fn disallowed_account_still_rejected_before_mapping_lookup() {
        let c = multi_account_cfg();
        let i = id(
            "999999999999",
            "arn:aws:sts::999999999999:assumed-role/AdminRole/s",
        );
        assert!(validate_identity("dbadmin", &i, &c)
            .unwrap_err()
            .contains("not in allowed_account_ids"));
    }

    // Single account plus flat mapping stays supported and unambiguous.
    #[test]
    fn flat_mapping_still_works_for_single_account() {
        let c = cfg();
        let i = id(
            "111122223333",
            "arn:aws:sts::111122223333:assumed-role/AdminRole/s",
        );
        assert!(validate_identity("dbadmin", &i, &c).is_ok());
    }
}
