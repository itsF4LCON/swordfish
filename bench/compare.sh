#!/usr/bin/env bash
set -euo pipefail

BENCH_REPO="${BENCH_REPO:-https://github.com/rails/rails}"
BENCH_DIR="${BENCH_DIR:-$(pwd)/target/bench-repos}"
RUNS="${RUNS:-5}"
SWORDFISH="${SWORDFISH:-$(pwd)/target/release/swordfish}"

for tool in hyperfine gitleaks git; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done
[ -x "$SWORDFISH" ] || { echo "build first: cargo build --release" >&2; exit 2; }

name="$(basename "${BENCH_REPO%.git}")"
repo="$BENCH_DIR/$name"
if [ ! -d "$repo" ]; then
  mkdir -p "$BENCH_DIR"
  git clone --mirror "$BENCH_REPO" "$repo"
fi

echo "repository: $BENCH_REPO"
echo "commits:    $(git -C "$repo" rev-list --all | wc -l)"
echo "size:       $(du -sh "$repo" | cut -f1)"
echo

hyperfine \
  --warmup 1 \
  --runs "$RUNS" \
  --ignore-failure \
  --export-markdown "$BENCH_DIR/$name-results.md" \
  -n swordfish "$SWORDFISH scan '$repo' --format json > /dev/null" \
  -n gitleaks  "gitleaks git --no-banner --log-level error --log-opts='--all' --report-format json --report-path /dev/null '$repo'"

echo
echo "results written to $BENCH_DIR/$name-results.md"
