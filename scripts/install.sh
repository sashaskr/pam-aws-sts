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

echo "Updating pg_hba.conf..."
docker compose exec postgres bash -c 'cat > /var/lib/postgresql/data/pg_hba.conf << EOF
local   all   postgres                 trust
host    all   postgres   0.0.0.0/0     trust
host    all   all        0.0.0.0/0     pam    pamservice=awssts
local   all   all                      pam    pamservice=awssts
EOF'

echo "Reloading PostgreSQL..."
docker compose exec postgres psql -U postgres -c "SELECT pg_reload_conf();"

echo "Done. PAM is active."
