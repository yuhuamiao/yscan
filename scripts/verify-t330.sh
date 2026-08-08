#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
templates_path=${YSCAN_T330_TEMPLATES:-/home/yuhua/nuclei-templates}
api_addr=${YSCAN_T330_API_ADDR:-127.0.0.1:19091}
port_spec=${YSCAN_T330_PORT_SPEC:-22222,6379,26379,28080,28081,28082}
validation_root=$(mktemp -d /tmp/caasm-t330-XXXXXX)
runtime_dir="$validation_root/runtime"
api_pid=""

cleanup() {
  if [ -n "$api_pid" ]; then
    kill "$api_pid" 2>/dev/null || true
    wait "$api_pid" 2>/dev/null || true
  fi
  chmod -R u+w "$validation_root" 2>/dev/null || true
  rm -rf "$validation_root"
}
trap cleanup EXIT

command -v curl >/dev/null
command -v jq >/dev/null
command -v nuclei >/dev/null
test -d "$templates_path"

IFS=',' read -r -a expected_ports <<< "$port_spec"
for port in "${expected_ports[@]}"; do
  timeout 2 bash -c "</dev/tcp/127.0.0.1/$port" 2>/dev/null || {
    printf 'required real service is not listening on 127.0.0.1:%s\n' "$port" >&2
    exit 1
  }
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
  any(.ports[]; .port == 22222 and .validation.status == "no_candidates" and .validation.reason == "mapping_missing")
' asset.json >/dev/null

run_path="$base_url/api/scan-tasks/$task_id/runs/$run2"
curl --fail --silent "$run_path/findings?page=1&page_size=100" > findings.json
jq -e '
  .validation.status == "success" and
  .validation.identified_product_count > 0 and
  .validation.mapped_product_count > 0 and
  .validation.executed_template_count > 0 and
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
  "$(jq -r '.validation.executed_template_count' findings.json) templates executed"
