#!/usr/bin/env bash
set -euo pipefail

SEED="${SEED:-20261009}"
WORK="${WORK:-$(pwd)/target/accuracy/seed-$SEED}"
OUT="${OUT:-$(pwd)/bench/accuracy/RESULTS.md}"
SWORDFISH="${SWORDFISH:-$(pwd)/target/release/swordfish}"
GITLEAKS="${GITLEAKS:-gitleaks}"
GITLEAKS_LOG_OPTS="${GITLEAKS_LOG_OPTS:---all}"
HERE="$(cd "$(dirname "$0")" && pwd)"

command -v "$GITLEAKS" >/dev/null || { echo "missing required tool: gitleaks" >&2; exit 2; }
[ -x "$SWORDFISH" ] || { echo "build first: cargo build --release" >&2; exit 2; }

rm -rf "$WORK"
python3 -I "$HERE/gen_corpus.py" "$WORK" --seed "$SEED"

"$SWORDFISH" scan "$WORK/repo" --format json --show-secrets > "$WORK/swordfish.json" 2>/dev/null || [ $? -eq 1 ]
"$GITLEAKS" git --no-banner --log-level error --log-opts="$GITLEAKS_LOG_OPTS" --exit-code 0 \
  --report-format json --report-path "$WORK/gitleaks.json" "$WORK/repo"

python3 -I "$HERE/score.py" "$WORK/labels.json" "$WORK/swordfish.json" "$WORK/gitleaks.json" \
  --meta "seed=$SEED" \
  --meta "corpus HEAD=$(git -C "$WORK/repo" rev-parse HEAD)" \
  --meta "swordfish=$("$SWORDFISH" --version) @ $(git rev-parse --short HEAD)" \
  --meta "gitleaks=$("$GITLEAKS" version) git --log-opts=\"$GITLEAKS_LOG_OPTS\"" \
  --meta "python=$(python3 --version)" \
  --meta "git=$(git --version)" > "$OUT"
echo "results written to $OUT"
