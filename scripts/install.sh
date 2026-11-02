#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Copying .so to postgres container..."
docker compose cp builder:/app/target/release/libpam_aws_sts.so /tmp/libpam_aws_sts.so
docker compose cp /tmp/libpam_aws_sts.so postgres:/usr/lib/aarch64-linux-gnu/security/pam_aws_sts.so
rm -f /tmp/libpam_aws_sts.so

echo "Writing /etc/pam.d/awssts..."
printf 'auth    required    pam_aws_sts.so    config=/etc/pam_aws_sts.toml\naccount required    pam_aws_sts.so    config=/etc/pam_aws_sts.toml\n' | \
    docker compose exec -T postgres tee /etc/pam.d/awssts > /dev/null

echo "Writing /etc/pam_aws_sts.toml..."
docker compose cp config/pam_aws_sts.integration.toml postgres:/etc/pam_aws_sts.toml

echo "Creating dbadmin role..."
docker compose exec postgres psql -U postgres -d testdb -c \
    "DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='dbadmin') THEN CREATE ROLE dbadmin LOGIN; END IF; END \$\$;"

# PAM sends the password (here: live STS credentials) in cleartext, so the dev
# loop runs over TLS too. Keeping dev aligned with the shipped pg_hba.conf is
# deliberate: a test harness that demonstrates plaintext auth is how the
# insecure pattern gets copied into production.
echo "Generating a self-signed server certificate (dev only)..."
docker compose exec -T postgres bash -c '
    set -e
    cd /var/lib/postgresql/data
    if [ ! -f server.crt ]; then
        openssl req -new -x509 -days 365 -nodes -text \
            -out server.crt -keyout server.key -subj "/CN=localhost" 2>/dev/null
    fi
    chmod 600 server.key
    chown postgres:postgres server.key server.crt
'

echo "Enabling TLS..."
docker compose exec -T postgres bash -c '
    set -e
    conf=/var/lib/postgresql/data/postgresql.conf
    grep -q "^ssl = on" "$conf" || printf "\nssl = on\nssl_cert_file = '"'"'server.crt'"'"'\nssl_key_file = '"'"'server.key'"'"'\n" >> "$conf"
'

echo "Updating pg_hba.conf..."
docker compose exec -T postgres bash -c 'cat > /var/lib/postgresql/data/pg_hba.conf << EOF
local     all   postgres                 trust
hostssl   all   postgres   0.0.0.0/0     trust
hostssl   all   all        0.0.0.0/0     pam    pamservice=awssts
host      all   all        0.0.0.0/0     reject
local     all   all                      pam    pamservice=awssts
EOF'

echo "Restarting PostgreSQL to pick up TLS..."
docker compose restart postgres
docker compose exec -T postgres sh -c 'until pg_isready -q; do sleep 1; done'

echo "Verifying plaintext connections are refused..."
if PGSSLMODE=disable docker compose exec -T postgres \
    psql -h 127.0.0.1 -U dbadmin -d testdb -c 'select 1' >/dev/null 2>&1; then
    echo "ERROR: a plaintext connection succeeded; pg_hba.conf is not enforcing TLS" >&2
    exit 1
fi
echo "  plaintext refused as expected"

echo "Done. PAM is active over TLS."
