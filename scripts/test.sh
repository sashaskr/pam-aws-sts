#!/bin/bash
set -euo pipefail

echo "--- postgres (trust) ---"
psql -h localhost -p 5432 -U postgres -d testdb -c "SELECT 'ok';"

echo ""
echo "--- dbadmin with garbage password ---"
PGPASSWORD="garbage" psql -h localhost -p 5432 -U dbadmin -d testdb -c "SELECT 1" 2>&1 || true

echo ""
echo "--- dbadmin with expired creds ---"
PGPASSWORD='{"AccessKeyId":"X","SecretAccessKey":"X","SessionToken":"X","Expiration":"2020-01-01T00:00:00Z"}' \
    psql -h localhost -p 5432 -U dbadmin -d testdb -c "SELECT 1" 2>&1 || true
