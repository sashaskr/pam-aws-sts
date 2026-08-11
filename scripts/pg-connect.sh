#!/bin/bash
# pg-connect.sh — Connect to PostgreSQL using AWS STS credentials
#
# Usage:
#   ./pg-connect.sh [pg_username] [psql args...]
#
# Configure the variables below for your environment.

set -euo pipefail

PG_USER="${1:-dbadmin}"
shift 2>/dev/null || true

# --- Configure these for your environment ---
TRUST_ANCHOR_ARN="arn:aws:rolesanywhere:REGION:ACCOUNT_ID:trust-anchor/TRUST_ANCHOR_ID"
PROFILE_ARN="arn:aws:rolesanywhere:REGION:ACCOUNT_ID:profile/PROFILE_ID"
ROLE_ARN="arn:aws:iam::ACCOUNT_ID:role/YOUR_ROLE_NAME"
PG_HOST="localhost"
PG_PORT="5432"

# Detect PKCS#11 library path (for YubiKey)
if [[ "$(uname)" == "Darwin" ]]; then
    PKCS11_LIB="/opt/homebrew/lib/libykcs11.dylib"
else
    PKCS11_LIB="/usr/lib/x86_64-linux-gnu/libykcs11.so"
fi

CERT_URI="pkcs11:object=X.509%20Certificate%20for%20PIV%20Authentication"
# --- End configuration ---

echo "Obtaining STS credentials..." >&2

CREDS=$(aws_signing_helper credential-process \
    --trust-anchor-arn "$TRUST_ANCHOR_ARN" \
    --profile-arn "$PROFILE_ARN" \
    --role-arn "$ROLE_ARN" \
    --pkcs11-lib "$PKCS11_LIB" \
    --certificate "$CERT_URI")

echo "Connecting to PostgreSQL as '$PG_USER'..." >&2

PGPASSWORD="$CREDS" exec psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" "$@"
