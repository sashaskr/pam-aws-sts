#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Compiling libpam_aws_sts.so..."
docker compose exec builder cargo build --release
echo "Done."
