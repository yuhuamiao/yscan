#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work_dir=$(mktemp -d)
cleanup() { rm -rf "$work_dir"; }
trap cleanup EXIT

cd "$repo_root"
go build -o "$work_dir/yscan" .

cd "$work_dir"
measure_rss() {
  local label=$1
  local limit=$2
  shift 2
  /usr/bin/time -f '%M' -o "$work_dir/$label.rss" "$@" >/dev/null
  local actual
  actual=$(cat "$work_dir/$label.rss")
  echo "$label rss_kb=$actual limit_kb=$limit"
  if (( actual > limit )); then
    echo "$label RSS exceeded limit" >&2
    exit 1
  fi
}

measure_rss cold 196608 ./yscan fingerprint list
measure_rss warm 65536 ./yscan fingerprint list
measure_rss closed_port 98304 ./yscan schedule create --target 127.0.0.1 --scan-type ip --mode once --port-spec 1

cd "$repo_root"
benchmark=$(go test -run '^$' -bench '^BenchmarkT307IndexedActiveMatch$' -benchtime=100x ./internal/fingerprint)
echo "$benchmark"
candidate_rules=$(awk '/BenchmarkT307IndexedActiveMatch/ { for (i=1; i<=NF; i++) if ($(i+1)=="candidate_rules") print $i }' <<<"$benchmark" | tail -n 1)
nanoseconds=$(awk '/BenchmarkT307IndexedActiveMatch/ { for (i=1; i<=NF; i++) if ($(i+1)=="ns/op") print $i }' <<<"$benchmark" | tail -n 1)
if [[ -z "$candidate_rules" || -z "$nanoseconds" ]]; then
  echo "unable to parse T307 benchmark metrics" >&2
  exit 1
fi
awk -v value="$candidate_rules" 'BEGIN { if (value > 15000) exit 1 }' || { echo "candidate rule threshold exceeded: $candidate_rules" >&2; exit 1; }
awk -v value="$nanoseconds" 'BEGIN { if (value > 10000000) exit 1 }' || { echo "match latency threshold exceeded: $nanoseconds ns/op" >&2; exit 1; }
