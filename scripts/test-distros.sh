#!/bin/bash
# test-distros.sh — Test release artifacts on AL2023 and Rocky Linux 9
# Requires: docker, psql, and a valid PGPASSWORD (STS creds)
#
# Usage:
#   PGPASSWORD='<sts-json>' ./scripts/test-distros.sh

set -euo pipefail

RELEASE_URL="https://github.com/sashaskr/pam-aws-sts/releases/download/v0.1.0"

if [ -z "${PGPASSWORD:-}" ]; then
    echo "ERROR: Set PGPASSWORD to STS credential JSON before running."
    echo "Example: PGPASSWORD=\$(aws_signing_helper credential-process ...) ./scripts/test-distros.sh"
    exit 1
fi

cleanup() {
    echo "Cleaning up..."
    docker rm -f al2023-pg el9-pg 2>/dev/null || true
}
trap cleanup EXIT

test_distro() {
    local NAME=$1
    local IMAGE=$2
    local ARTIFACT=$3
    local PAM_PATH=$4
    local PG_PKG=$5
    local PG_SETUP=$6

    echo ""
    echo "=============================="
    echo "Testing: $NAME"
    echo "=============================="

    docker rm -f "$NAME" 2>/dev/null || true
    docker run -d --name "$NAME" -p 5432:5432 "$IMAGE" sleep infinity

    echo "Installing PostgreSQL..."
    docker exec "$NAME" bash -c "$PG_PKG"
    docker exec "$NAME" bash -c "$PG_SETUP"

    echo "Downloading release artifact..."
    docker exec "$NAME" bash -c "
        mkdir -p /tmp/pam && cd /tmp/pam &&
        curl -sL ${RELEASE_URL}/${ARTIFACT}.tar.gz -o release.tar.gz &&
        tar xzf release.tar.gz
    "

    echo "Installing PAM module..."
    docker exec "$NAME" bash -c "
        cp /tmp/pam/pam_aws_sts.so ${PAM_PATH}/pam_aws_sts.so &&
        cp /tmp/pam/awssts /etc/pam.d/awssts &&
        cat > /etc/pam_aws_sts.toml << 'CONF'
[aws]
region = \"eu-central-1\"
allowed_account_ids = [\"370684328700\"]
timeout_secs = 5
grace_period_secs = 30

[role_mapping]
\"YubiKeyKMSRole\" = [\"dbadmin\"]

[logging]
level = \"debug\"
facility = \"auth\"
CONF
    "

    echo "Configuring PostgreSQL for PAM..."
    docker exec "$NAME" bash -c "
        su - postgres -c \"psql -c \\\"CREATE ROLE dbadmin LOGIN\\\"\" 2>/dev/null || true
        su - postgres -c \"psql -c \\\"CREATE DATABASE testdb\\\"\" 2>/dev/null || true
    "

    docker exec "$NAME" bash -c '
        PG_HBA=$(su - postgres -c "psql -t -c \"SHOW hba_file\"" | tr -d " ")
        cat > "$PG_HBA" << EOF
local   all   postgres                 trust
host    all   postgres   0.0.0.0/0     trust
host    all   all        0.0.0.0/0     pam    pamservice=awssts
local   all   all                      pam    pamservice=awssts
EOF
        su - postgres -c "psql -c \"SELECT pg_reload_conf()\""
    '

    echo "Testing garbage password (should fail)..."
    if PGPASSWORD="garbage" psql -h localhost -p 5432 -U dbadmin -d testdb -c "SELECT 1" 2>/dev/null; then
        echo "  FAIL: garbage accepted"
        return 1
    else
        echo "  PASS: garbage rejected"
    fi

    echo "Testing real STS creds..."
    if psql -h localhost -p 5432 -U dbadmin -d testdb -c "SELECT current_user;" 2>&1; then
        echo "  PASS: authenticated"
    else
        echo "  FAIL: auth failed"
        docker exec "$NAME" bash -c "cat /var/log/messages 2>/dev/null || journalctl -u postgresql 2>/dev/null || true"
        return 1
    fi

    echo "$NAME: ALL PASSED"
    docker rm -f "$NAME"
}

# --- Amazon Linux 2023 ---
test_distro "al2023-pg" "amazonlinux:2023" "pam_aws_sts-al2023-amd64" "/usr/lib64/security" \
    "dnf install -y postgresql16-server postgresql16 pam" \
    "postgresql-setup --initdb && su - postgres -c 'pg_ctl start -D /var/lib/pgsql/data -l /tmp/pg.log' && sleep 2"

# --- Rocky Linux 9 ---
test_distro "el9-pg" "rockylinux:9" "pam_aws_sts-el9-amd64" "/usr/lib64/security" \
    "dnf install -y postgresql-server postgresql pam" \
    "postgresql-setup --initdb && su - postgres -c 'pg_ctl start -D /var/lib/pgsql/data -l /tmp/pg.log' && sleep 2"

echo ""
echo "All distro tests passed."
