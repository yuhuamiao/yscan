#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
validation_root=$(mktemp -d /tmp/yscan-t294-XXXXXX)
fresh_clone="$validation_root/fresh"
runtime_dir="$validation_root/runtime"
other_cwd="$validation_root/other-cwd"
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
rg -q '内置指纹' "$fresh_clone/README.md"
rg -q 'fingerprint cleanup' "$fresh_clone/README.md"

(cd "$fresh_clone" && go build -trimpath -o yscan .)
mkdir "$runtime_dir" "$other_cwd"
cp "$fresh_clone/yscan" "$runtime_dir/yscan"
(cd "$other_cwd" && "$runtime_dir/yscan" fingerprint list > "$runtime_dir/fingerprint-sources.txt")

test -s "$runtime_dir/yscan"
test -s "$runtime_dir/data/asm.db"
test ! -e "$other_cwd/asm.db"
test ! -e "$other_cwd/data/asm.db"
(cd "$fresh_clone" && "$runtime_dir/yscan" fingerprint list > "$runtime_dir/fingerprint-sources-second.txt")
cmp "$runtime_dir/fingerprint-sources.txt" "$runtime_dir/fingerprint-sources-second.txt"
test "$(tail -n +2 "$runtime_dir/fingerprint-sources.txt" | wc -l)" -eq 10
rg -q '^fingerprinthub-service-yaml' "$runtime_dir/fingerprint-sources.txt"
rg -q '^wappalyzer' "$runtime_dir/fingerprint-sources.txt"

printf 'T294 fresh clone verified: %s\n' "$fresh_clone"
printf 'Database initialized at executable home: %s\n' "$runtime_dir/data/asm.db"
printf 'Fingerprint sources initialized: %s\n' "$(tail -n +2 "$runtime_dir/fingerprint-sources.txt" | wc -l)"
