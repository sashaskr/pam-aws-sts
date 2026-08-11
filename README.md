# pam_aws_sts

A PAM module that authenticates PostgreSQL users with AWS STS temporary credentials.

Any IAM identity that can produce valid STS credentials can authenticate to your self-managed PostgreSQL. The module calls `sts:GetCallerIdentity`, verifies the account and role, and maps it to a PostgreSQL username.

## Why

You run PostgreSQL on bare metal, EC2, or Docker — not RDS. You want IAM-based authentication without rewriting your application or adding middleware. This module slots into PostgreSQL's existing PAM support and gives you:

- Centralized access control via IAM roles
- No static database passwords
- Audit trail (who connected, which IAM role, when)
- Works with any source of STS credentials

Good fit for organizations migrating from on-premise to the AWS ecosystem incrementally — your PostgreSQL stays where it is, but auth moves to IAM.

## How it works

```
Client (any STS credential source) → psql -U dbadmin (password = JSON creds)
    → PostgreSQL → PAM → pam_aws_sts.so
        → STS GetCallerIdentity (validates credentials)
        → Check account ID allowlist
        → Extract IAM role from ARN
        → Map role → PostgreSQL username
        → PAM_SUCCESS or PAM_AUTH_ERR
```

## Getting credentials (client side)

The module accepts any valid STS temporary credentials as the password. The JSON format:

```json
{"AccessKeyId":"ASIA...","SecretAccessKey":"...","SessionToken":"...","Expiration":"..."}
```

### From EC2 instance metadata (instance role)

```bash
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
CREDS=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE)
PGPASSWORD="$CREDS" psql -h your-pg-host -U dbadmin -d mydb
```

### From IMDSv2 (recommended on EC2)

```bash
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
CREDS=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE)
PGPASSWORD="$CREDS" psql -h your-pg-host -U dbadmin -d mydb
```

### From AWS CLI (any configured profile)

```bash
CREDS=$(aws sts assume-role --role-arn arn:aws:iam::123456789012:role/MyRole \
  --role-session-name pg-session --output json \
  | jq '.Credentials | {AccessKeyId, SecretAccessKey, SessionToken, Expiration}')
PGPASSWORD="$CREDS" psql -h your-pg-host -U dbadmin -d mydb
```

### From IAM Roles Anywhere + YubiKey (regulated environments)

For environments requiring hardware-bound credentials (PCI-DSS, SOC2, FedRAMP):

```bash
CREDS=$(aws_signing_helper credential-process \
  --trust-anchor-arn "arn:aws:rolesanywhere:REGION:ACCOUNT:trust-anchor/ID" \
  --profile-arn "arn:aws:rolesanywhere:REGION:ACCOUNT:profile/ID" \
  --role-arn "arn:aws:iam::ACCOUNT:role/ROLE_NAME" \
  --pkcs11-lib /path/to/libykcs11.so \
  --certificate "pkcs11:object=X.509%20Certificate%20for%20PIV%20Authentication")
PGPASSWORD="$CREDS" psql -h your-pg-host -U dbadmin -d mydb
```

This binds authentication to a physical hardware token — credentials cannot be extracted or copied.

## Installation (server side)

Prerequisites: Linux server running PostgreSQL 16+ (compiled with `--with-pam`, which official packages include). PostgreSQL versions below 16 have a 1000-byte password buffer limit which is too small for STS credential JSON.

1. **Copy the module** to your PAM directory:
   ```bash
   cp libpam_aws_sts.so /usr/lib/x86_64-linux-gnu/security/pam_aws_sts.so
   ```

2. **Create PAM service** `/etc/pam.d/awssts`:
   ```
   auth    required    pam_aws_sts.so    config=/etc/pam_aws_sts.toml
   account required    pam_aws_sts.so    config=/etc/pam_aws_sts.toml
   ```

3. **Create config** `/etc/pam_aws_sts.toml` (from `config/pam_aws_sts.toml.sample`):
   ```toml
   [aws]
   region = "us-east-1"
   allowed_account_ids = ["123456789012"]
   timeout_secs = 5
   grace_period_secs = 30

   [role_mapping]
   "MyRole" = ["dbadmin"]
   "AnalystRole" = ["analyst"]

   [logging]
   level = "info"
   facility = "auth"
   ```

4. **Create PostgreSQL roles** that match your mapping:
   ```sql
   CREATE ROLE dbadmin LOGIN;
   CREATE ROLE analyst LOGIN;
   ```

5. **Update `pg_hba.conf`**:
   ```
   # Keep trust for superuser
   local   all   postgres                 trust
   # PAM for everything else
   host    all   all        0.0.0.0/0     pam    pamservice=awssts
   ```

6. **Reload PostgreSQL**:
   ```bash
   psql -U postgres -c "SELECT pg_reload_conf();"
   ```

## Building

Requires Rust 1.94+ and `libpam0g-dev`.

```bash
# Native Linux build
cargo build --release
# Output: target/release/libpam_aws_sts.so

# Or use the Docker builder
docker compose up -d builder
./scripts/build.sh
```

## Development setup

```bash
docker compose up -d          # vanilla postgres + rust builder
./scripts/build.sh            # compile .so
./scripts/install.sh          # deploy to running postgres container
./scripts/test.sh             # verify from host
```

## Configuration reference

`/etc/pam_aws_sts.toml`:

| Section | Key | Description |
|---------|-----|-------------|
| `[aws]` | `region` | AWS region for STS endpoint |
| | `allowed_account_ids` | Account IDs accepted (array) |
| | `sts_endpoint` | Optional override (for testing) |
| | `timeout_secs` | HTTP timeout (default: 5) |
| | `grace_period_secs` | Reject tokens expiring within this window (default: 30) |
| `[role_mapping]` | `"RoleName" = ["pguser"]` | IAM role → allowed PG usernames |
| `[logging]` | `level` | debug, info, warn, error |
| | `facility` | syslog facility |

## Security

- Credentials (`SecretAccessKey`, `SessionToken`) are zeroized in memory after use
- No credential caching — every connection validates against STS
- TLS enforced for STS calls
- Secrets are never logged
- Minimal unsafe code — only at the PAM FFI boundary

## Project structure

```
src/
├── lib.rs           — auth orchestration
├── config.rs        — TOML config parsing
├── credentials.rs   — STS credential JSON parsing + zeroize
├── sts.rs           — GetCallerIdentity with SigV4 signing
├── validation.rs    — account/role validation + username mapping
├── logging.rs       — syslog integration
└── pam_ffi.rs       — PAM entry points (Linux only)
tests/
└── auth_flow.rs     — integration tests
config/
├── pam_aws_sts.toml.sample
├── pam.d/awssts
└── pg_hba.conf
scripts/
├── build.sh
├── install.sh
├── test.sh
└── pg-connect.sh
```

## License

MIT
