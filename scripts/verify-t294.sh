#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
validation_root=$(mktemp -d /tmp/yscan-t294-XXXXXX)
fresh_clone="$validation_root/fresh"
runtime_dir="$validation_root/runtime"
worktree_patch="$validation_root/worktree.patch"

cleanup() {
  chmod -R u+w "$validation_root" 2>/dev/null || true
  rm -rf "$validation_root"
}
trap cleanup EXIT

cd "$repo_root"
git clone --quiet --no-hardlinks "$repo_root" "$fresh_clone"
git diff --binary HEAD -- . > "$worktree_patch"
if [ -s "$worktree_patch" ]; then
  git -C "$fresh_clone" apply "$worktree_patch"
fi

test -z "$(git -C "$fresh_clone" ls-files --others --exclude-standard)"
test ! -e "$fresh_clone/asm.db"
test ! -e "$fresh_clone/yscan"
test ! -e "$fresh_clone/reports"
test ! -e "$fresh_clone/AGENTS.md"
test ! -e "$fresh_clone/技术设计方案-v2.md"
! rg -q '\]\((AGENTS|技术设计方案-v2|技术设计方案|产品调研)\.md\)' "$fresh_clone/README.md"
rg -q 'fingerprint upgrade' "$fresh_clone/README.md"
rg -q -- '--allow-cidr' "$fresh_clone/README.md"
rg -q '内置指纹规则' "$fresh_clone/README.md"
rg -q 'fingerprint cleanup' "$fresh_clone/README.md"

(cd "$fresh_clone" && go build -trimpath -o yscan .)
mkdir "$runtime_dir"
(cd "$runtime_dir" && "$fresh_clone/yscan" fingerprint list > fingerprint-sources.txt)

test -s "$fresh_clone/yscan"
test -s "$runtime_dir/asm.db"
test "$(tail -n +2 "$runtime_dir/fingerprint-sources.txt" | wc -l)" -eq 10
rg -q '^fingerprinthub-service-yaml' "$runtime_dir/fingerprint-sources.txt"
rg -q '^wappalyzer' "$runtime_dir/fingerprint-sources.txt"

printf 'T294 fresh clone verified: %s\n' "$fresh_clone"
printf 'Fingerprint sources initialized: %s\n' "$(tail -n +2 "$runtime_dir/fingerprint-sources.txt" | wc -l)"
