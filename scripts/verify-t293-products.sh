#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
compose_file="$repo_root/internal/workflow/testdata/t293/products/compose.yaml"
fixture_dir="$repo_root/internal/workflow/testdata/t293/products"

if ! command -v docker >/dev/null 2>&1; then
  echo "T293 real-product acceptance requires Docker with Compose v2." >&2
  exit 2
fi
if ! docker info >/dev/null 2>&1; then
  echo "T293 Docker daemon is unavailable. In WSL, enable Docker Desktop integration for this distribution." >&2
  exit 2
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "T293 real-product acceptance requires Docker Compose v2." >&2
  exit 2
fi
command -v nuclei >/dev/null 2>&1 || { echo "T293 real-product acceptance requires nuclei in PATH." >&2; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo "T293 real-product acceptance requires openssl." >&2; exit 2; }

cert_dir=$(mktemp -d)
project="caasm-t293-$$"
cleanup() {
  YSCAN_T293_CERT_DIR="$cert_dir" YSCAN_T293_FIXTURE_DIR="$fixture_dir" docker compose --project-name "$project" --file "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$cert_dir"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=127.0.0.1" -keyout "$cert_dir/key.pem" -out "$cert_dir/cert.pem" >/dev/null 2>&1
export YSCAN_T293_CERT_DIR="$cert_dir"
export YSCAN_T293_FIXTURE_DIR="$fixture_dir"
docker compose --project-name "$project" --file "$compose_file" up --detach --pull always

for port in 22 80 443 3306 6379 8080; do
  ready=false
  for _ in $(seq 1 180); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      exec 3>&-
      ready=true
      break
    fi
    sleep 1
  done
  if [[ "$ready" != true ]]; then
    echo "T293 product endpoint 127.0.0.1:$port did not become ready." >&2
    docker compose --project-name "$project" --file "$compose_file" ps >&2
    exit 1
  fi
done

cd "$repo_root"
YSCAN_PRODUCT_E2E=1 go test -count=1 -run TestT293RealProductServices ./internal/workflow
