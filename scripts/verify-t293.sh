#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

command -v nuclei >/dev/null
YSCAN_REAL_E2E=1 go test -count=1 -run TestT293RealLegacyUpgradeAndScan ./internal/workflow
