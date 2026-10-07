# Benchmark: swordfish vs gitleaks

```sh
cargo build --release
bench/compare.sh                                         # rails/rails by default
BENCH_REPO=https://github.com/rust-lang/cargo bench/compare.sh
RUNS=10 BENCH_DIR=/data/bench bench/compare.sh
```

You need [hyperfine](https://github.com/sharkdp/hyperfine),
[gitleaks](https://github.com/gitleaks/gitleaks) v8.19 or later, and git.
The script mirror-clones the repository once into `target/bench-repos/` and
then times both tools scanning **all refs**:

- swordfish: `swordfish scan <repo> --format json`
- gitleaks: `gitleaks git --log-opts=--all --report-format json`

The results table is written next to the clone as `<name>-results.md`.

## Reading the numbers fairly

- **Work model.** gitleaks scans `git log -p` output, so each diff hunk is
  scanned for every commit that introduces it. swordfish scans each unique
  blob once, then derives timelines from tree diffs. The gap grows with
  history length and with the number of branches that share history.
- **Different rule sets.** gitleaks ships about 150 provider rules, while
  swordfish v0.1 has 11. For a like-for-like comparison of the engines, pass
  the same rules to both: swordfish accepts gitleaks-style TOML through
  `--rules`.
- **Threads.** swordfish uses every core through rayon. Set
  `RAYON_NUM_THREADS=1` for a single-threaded comparison.
- **Exit codes.** Both tools exit 1 when they find something, so the script
  passes `--ignore-failure` to hyperfine.

Development reference point (not a gitleaks comparison):
`rust-lang/cargo`, mirror clone, 34,889 commits, 9,769 refs, 70,866 unique
blobs: 1.1 s on 20 threads, 4.7 s with `RAYON_NUM_THREADS=2`.
