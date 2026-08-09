#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
templates_path=${YSCAN_T330_TEMPLATES:-/home/yuhua/nuclei-templates}
api_addr=${YSCAN_T330_API_ADDR:-127.0.0.1:19091}
port_spec=${YSCAN_T330_PORT_SPEC:-22222,6379,26379,28080,28081,28082}
chromium_path=${YSCAN_T330_CHROMIUM:-/home/yuhua/.cache/ms-playwright/chromium-1200/chrome-linux64/chrome}
validation_root=$(mktemp -d /tmp/caasm-t330-XXXXXX)
runtime_dir="$validation_root/runtime"
api_pid=""
fixture_pid=""
service_pids=()

cleanup() {
  if [ -n "$api_pid" ]; then
    kill "$api_pid" 2>/dev/null || true
    wait "$api_pid" 2>/dev/null || true
  fi
  for pid in "${service_pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  if [ -n "$fixture_pid" ]; then
    kill "$fixture_pid" 2>/dev/null || true
  fi
  for pid in "${service_pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  if [ -n "$fixture_pid" ]; then
    wait "$fixture_pid" 2>/dev/null || true
  fi
  chmod -R u+w "$validation_root" 2>/dev/null || true
  rm -rf "$validation_root"
}
trap cleanup EXIT

command -v curl >/dev/null
command -v jq >/dev/null
command -v nuclei >/dev/null
command -v php >/dev/null
command -v python3 >/dev/null
python3 -c 'import flask, werkzeug'
test -d "$templates_path"
test -x "$chromium_path"
(cd "$repo_root" && YSCAN_REAL_NUCLEI_TEMPLATES="$templates_path" go test -count=1 -run TestRealNucleiTemplateIndexCoverage ./internal/planner)

if [ "${YSCAN_T330_EXTERNAL_SERVICES:-0}" != "1" ]; then
  php_root="$validation_root/php"
  mkdir "$php_root"
  cat > "$php_root/index.php" <<'PHP'
<?php header('X-Powered-By: PHP/8.1.2'); ?>
<html><title>T330 PHP</title><body>PHP runtime fixture</body></html>
PHP
  python3 "$repo_root/scripts/t330_fixture_services.py" > "$validation_root/fixtures.log" 2>&1 &
  fixture_pid=$!
  php -S 127.0.0.1:28080 -t "$php_root" > "$validation_root/php-28080.log" 2>&1 &
  service_pids+=("$!")
  php -S 127.0.0.1:28081 -t "$php_root" > "$validation_root/php-28081.log" 2>&1 &
  service_pids+=("$!")
fi

IFS=',' read -r -a expected_ports <<< "$port_spec"
for port in "${expected_ports[@]}"; do
  listening=0
  for _ in $(seq 1 30); do
    if timeout 1 bash -c "</dev/tcp/127.0.0.1/$port" 2>/dev/null; then
      listening=1
      break
    fi
    sleep 0.2
  done
  if [ "$listening" -ne 1 ]; then
    printf 'required real service is not listening on 127.0.0.1:%s\n' "$port" >&2
    exit 1
  fi
done

mkdir "$runtime_dir"
(cd "$repo_root" && go build -trimpath -o "$runtime_dir/caasm" .)
cd "$runtime_dir"

./caasm fingerprint list > fingerprint-sources.txt
test -s asm.db
test "$(tail -n +2 fingerprint-sources.txt | wc -l)" -eq 10

create_output=$(./caasm --templates "$templates_path" schedule create \
  --target 127.0.0.1 \
  --scan-type ip \
  --mode scheduled \
  --cron '* * * * *' \
  --timezone Asia/Shanghai \
  --port-spec "$port_spec" \
  --vuln)
task_id=$(sed -n 's/^ScanTask \([0-9][0-9]*\) created.*/\1/p' <<< "$create_output")
test -n "$task_id"

./caasm --templates "$templates_path" api "$api_addr" > api.log 2>&1 &
api_pid=$!
base_url="http://$api_addr"
for _ in $(seq 1 30); do
  if curl --fail --silent "$base_url/api/scan-tasks/$task_id" > task.json; then
    break
  fi
  sleep 1
done
test -s task.json

run1=""
run2=""
for _ in $(seq 1 180); do
  curl --fail --silent "$base_url/api/scan-tasks/$task_id/runs" > runs.json
  success_count=$(jq '[.[] | select(.status == "success")] | length' runs.json)
  if [ "$success_count" -ge 2 ]; then
    run1=$(jq -r '[.[] | select(.status == "success")] | sort_by(.sequence) | .[0].id' runs.json)
    run2=$(jq -r '[.[] | select(.status == "success")] | sort_by(.sequence) | .[1].id' runs.json)
    break
  fi
  sleep 2
done
test -n "$run1"
test -n "$run2"
curl --fail --silent --request POST "$base_url/api/scan-tasks/$task_id/pause" > paused-task.json
jq -e '.status == "paused"' paused-task.json >/dev/null

curl --fail --silent "$base_url/api/assets/127.0.0.1" > asset.json
jq -e --argjson run_id "$run2" '
  ([.ports[] | select(.port == 22222 or .port == 6379 or .port == 26379 or .port == 28080 or .port == 28081 or .port == 28082)] | length) == 6 and
  all(.ports[] | select(.port == 22222 or .port == 6379 or .port == 26379 or .port == 28080 or .port == 28081 or .port == 28082); .observation_run_id == $run_id) and
  any(.ports[]; .port == 6379 and .service == "redis" and any(.technologies[]; .product_key == "redis" and .role == "network_service")) and
  any(.ports[]; .port == 26379 and .service == "redis" and any(.technologies[]; .product_key == "redis" and .role == "network_service")) and
  any(.ports[]; .port == 22222 and any(.technologies[]; .product_key == "dropbear") and all(.technologies[]; .product_key != "openssh")) and
  any(.ports[]; .port == 28080 and any(.technologies[]; .product_key == "php" and .role == "runtime")) and
  any(.ports[]; .port == 28081 and any(.technologies[]; .product_key == "php" and .role == "runtime")) and
	  any(.ports[]; .port == 28082 and any(.technologies[]; .product_key == "flask" and .role == "framework")) and
	  all(.ports[] | select(.port == 22222 or .port == 6379 or .port == 26379 or .port == 28080 or .port == 28081 or .port == 28082); (.endpoint_validations | length) == 1) and
	  any(.ports[]; .port == 22222 and .validation.status == "no_candidates" and (.validation.reason == "mapping_missing" or .validation.reason == "policy_filtered")) and
	  all(.ports[] | select(.port == 6379 or .port == 26379); .endpoint_validations[0].status == "success" and .endpoint_validations[0].executed_template_count == 1 and .endpoint_validations[0].finding_count == 1)
' asset.json >/dev/null

run_path="$base_url/api/scan-tasks/$task_id/runs/$run2"
curl --fail --silent "$run_path/findings?page=1&page_size=100" > findings.json
jq -e '
  .validation.status == "success" and
	  .validation.identified_product_count > 0 and
	  .validation.mapped_product_count > 0 and
	  .validation.candidate_endpoint_count == 2 and
	  .validation.executed_endpoint_count == 2 and
	  .validation.template_count == 1 and
	  .validation.executed_template_count == 1 and
  .total == 2 and
  ([.items[] | select(.template_id == "exposed-redis" and .severity == "high" and (.target_port == 6379 or .target_port == 26379))] | length) == 2 and
  all(.items[]; .target_port != 28081 and .target_port != 28082)
' findings.json >/dev/null

curl --fail --silent "$run_path/report" > user-report.md
curl --fail --silent "$run_path/audit-report" > audit-report.md
curl --fail --silent "$base_url/assets" > assets.html
rg -q '^## Endpoint Profiles$' user-report.md
rg -q 'exposed-redis|Redis' user-report.md
! rg -q 'Frozen Fingerprint Revisions|projection_sha256|matcher_id' user-report.md
rg -q '^## Frozen Fingerprint Revisions$' audit-report.md
rg -q '^## Validation Plan$' audit-report.md
rg -q 'protocol_evidence' assets.html
rg -q 'technologies' assets.html
(cd "$repo_root" && go run ./internal/web/cmd/t330browser \
  --base-url "$base_url" \
  --ip 127.0.0.1 \
  --browser "$chromium_path" \
  --expected-ports 6 \
  --expected-validations 6 \
  --expected-findings 2)

curl --fail --silent "$run_path/changes?baseline_run_id=$run1" > changes.json
jq -e --argjson task_id "$task_id" --argjson run1 "$run1" --argjson run2 "$run2" '
  .scan_task_id == $task_id and
  .baseline_run_id == $run1 and
  .current_run_id == $run2 and
  .config_changed == false and
  (.host_changes.new_hosts | length) == 0 and
  (.host_changes.inactive_hosts | length) == 0 and
  (.port_changes.opened | length) == 0 and
  (.port_changes.closed | length) == 0 and
  (.vulnerability_changes.new | length) == 0 and
  (.vulnerability_changes.resolved | length) == 0
' changes.json >/dev/null

printf 'T330 real user journey verified: task=%s baseline_run=%s current_run=%s\n' "$task_id" "$run1" "$run2"
printf 'Endpoint profiles: %s; findings: %s; template revision: %s\n' \
  "$(jq '.ports | length' asset.json)" \
  "$(jq '.total' findings.json)" \
	  "$(jq -r '.validation.executed_template_count' findings.json) exact template executed"
