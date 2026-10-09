#!/usr/bin/env bash
# Accuracy benchmark: swordfish vs gitleaks on a labeled synthetic corpus.
#
# Requirements: python3, git, gitleaks (v8.19+ for the `git` subcommand), and a
# release build of swordfish (`cargo build --release`).
#
# Usage:
#   bench/accuracy/run.sh                  # seed 20261009, writes bench/accuracy/RESULTS.md
#   SEED=7 OUT=/tmp/r.md bench/accuracy/run.sh
#
# The corpus (fake secrets) is generated under target/accuracy/ and is never
# committed. Nothing here touches the network.
set -euo pipefail

SEED="${SEED:-20261009}"
WORK="${WORK:-$(pwd)/target/accuracy/seed-$SEED}"
OUT="${OUT:-$(pwd)/bench/accuracy/RESULTS.md}"
SWORDFISH="${SWORDFISH:-$(pwd)/target/release/swordfish}"
GITLEAKS="${GITLEAKS:-gitleaks}"
HERE="$(cd "$(dirname "$0")" && pwd)"

command -v "$GITLEAKS" >/dev/null || { echo "missing required tool: gitleaks" >&2; exit 2; }
[ -x "$SWORDFISH" ] || { echo "build first: cargo build --release" >&2; exit 2; }

rm -rf "$WORK"
python3 -I "$HERE/gen_corpus.py" "$WORK" --seed "$SEED"

# Both tools see every ref. Exit code 1 means "findings", not failure.
"$SWORDFISH" scan "$WORK/repo" --format json --show-secrets > "$WORK/swordfish.json" 2>/dev/null || [ $? -eq 1 ]
"$GITLEAKS" git --no-banner --log-level error --log-opts=--all --exit-code 0 \
  --report-format json --report-path "$WORK/gitleaks.json" "$WORK/repo"

python3 -I "$HERE/score.py" "$WORK/labels.json" "$WORK/swordfish.json" "$WORK/gitleaks.json" \
  --meta "seed=$SEED" \
  --meta "corpus HEAD=$(git -C "$WORK/repo" rev-parse HEAD)" \
  --meta "swordfish=$("$SWORDFISH" --version) @ $(git rev-parse --short HEAD)" \
  --meta "gitleaks=$("$GITLEAKS" version)" > "$OUT"
echo "results written to $OUT"
