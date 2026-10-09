# Accuracy: swordfish vs gitleaks

```sh
cargo build --release
bench/accuracy/run.sh                 # seed 20261009 → bench/accuracy/RESULTS.md
SEED=7 OUT=/tmp/seed7.md bench/accuracy/run.sh
```

You need python3 (standard library only), git and
[gitleaks](https://github.com/gitleaks/gitleaks) v8.19 or later. The script
builds a labeled repository under `target/accuracy/`, scans it with both tools
on every ref, and scores the findings against the labels. A run takes a few
seconds and makes no network calls.

Full tables for the default seed are in [RESULTS.md](RESULTS.md).

## Summary

Measured with swordfish 0.1.0 and gitleaks 8.30.1 (default config) on six
seeds. Each cell is swordfish / gitleaks.

| seed | in-scope recall | ... excluding merge-only secrets | other-provider recall | precision |
|---|---|---|---|---|
| 20261009 | 92.6% / 84.7% | 92.0% / 91.4% | 70.0% / 100.0% | 91.2% / 92.7% |
| 1 | 94.3% / 86.9% | 94.4% / 94.4% | 60.0% / 100.0% | 90.3% / 92.8% |
| 2 | 92.6% / 81.2% | 91.7% / 91.1% | 72.0% / 100.0% | 90.9% / 92.5% |
| 3 | 93.8% / 85.8% | 93.8% / 93.2% | 64.0% / 100.0% | 91.6% / 93.2% |
| 4 | 93.2% / 84.1% | 92.5% / 92.5% | 64.0% / 100.0% | 91.2% / 92.6% |
| 5 | 94.9% / 83.5% | 94.2% / 94.2% | 68.0% / 98.0% | 91.0% / 92.6% |

What the numbers say:

- **For secret types swordfish has a rule for, recall is about the same**,
  within one point of gitleaks, once merge commits are left out. Deleted
  files, unmerged branches, tag-only commits and duplicates are found equally
  by both.
- **Secrets that exist only in a merge commit**: swordfish finds 94 of 96
  across the six seeds, and gitleaks finds none. swordfish's two misses are
  generic passwords it would miss anywhere. gitleaks reads `git log -p`, and
  git prints no diff for merge commits by default, so content introduced
  while resolving a merge (an "evil merge") is never scanned. swordfish diffs
  every commit's tree against its first parent, merges included. This
  scenario is 7–11% of the in-scope corpus, which is a choice of the corpus,
  not a measured real-world rate. It accounts for most of the gap in the
  first column.
- **gitleaks covers far more providers.** For the ten providers swordfish
  has no rule for, swordfish only catches a token when it sits in a
  `KEY=value` style assignment that the generic rule recognises (60–72%).
  It caught none of 30 OpenAI project keys. gitleaks catches 98–100%.
- **gitleaks is slightly more precise** (about 92.7% vs 91%). Both flag
  content hashes, pinned commit SHAs and Stripe publishable keys sitting in
  `key:`-style assignments, plus the jwt.io example token. swordfish also
  flags base64 public keys in `"publicKey": ...` fields (4 of 8 public-key
  decoys). gitleaks flags all 4 UUID idempotency keys, swordfish 2–4. Every
  swordfish false positive in these runs comes from its generic rule, plus
  the jwt.io example token.
- **Both tools miss**, pooled over six seeds: most passwords containing
  symbols such as `&`, `@` or `*` (swordfish 9 of 39, gitleaks 8 of 39);
  every generic password or AWS secret key in .NET-style
  `<add key="..." value="..."/>` XML (0 of 20); AWS secret keys pasted
  without a variable name (0 of 10); secrets in binary blobs; and commits
  reachable only from the reflog. Provider-prefixed tokens in the same XML
  are still found.
- **Blobs over 1 MiB**: swordfish skips them by default (`--max-blob-size`);
  gitleaks found 3 of 4 secrets there.

## How the corpus is built

`gen_corpus.py` writes a git repository and a `labels.json` ground truth from
a seeded RNG with fixed dates and identities, so a seed always produces the
same commit IDs (the corpus HEAD is recorded in RESULTS.md). The fake secrets
are generated at run time and never committed, so this repository does not
trip secret scanning on itself.

**Planted secrets** (238 per seed):

- 11 in-scope families, 16 each: AWS access key ID and secret key, GitHub
  classic tokens (with a valid CRC32 checksum) and fine-grained PATs, Slack
  tokens and webhooks, Stripe secret keys, Google API keys, private key blocks
  (RSA, EC, OpenSSH, PKCS#8), JWTs, and generic passwords and secrets. The
  generic ones are a third alphanumeric, a third with symbols and a third
  base64.
- 10 providers swordfish has no rule for, 5 each: OpenAI, Anthropic, GitLab,
  SendGrid, Twilio, npm, PyPI, Shopify, DigitalOcean, Databricks.
- 12 edge cases: secrets in binary blobs, in a blob over 1 MiB, and in a
  commit reachable only from the reflog.

Token shapes follow each provider's published format, not either tool's rule
regexes. Each secret goes into a random context: `.env`, quoted `.env`, shell
`export`, YAML, JSON, Python, JavaScript, Terraform, INI, Dockerfile `ENV`,
.NET XML config, a `curl -H "Authorization: Bearer ..."` snippet, a
connection-string URL, or a bare comment with no variable name.

**History scenarios** for in-scope secrets: still in HEAD; deleted in a later
commit; only on an unmerged branch; only on a tag whose branch was deleted;
only in a merge commit's tree; committed in two files.

**Decoys** (57, not secrets): published example values (AWS docs, jwt.io),
placeholders, variable references (`${...}`, `process.env.X`,
`${{ secrets.X }}`), pinned action SHAs and cache keys, content hashes, UUID
idempotency keys, public keys (base64, `ssh-ed25519`, PEM), Stripe publishable
keys, OAuth client IDs, low-entropy test fixtures, code expressions, UI
strings, a data URI and an SRI hash. Lockfiles (`package-lock.json`,
`Cargo.lock`, `go.sum`) and 30 filler source files full of words like `key`,
`token` and `password` round it out. A finding in those counts as an
unlabeled false positive.

## How findings are scored

- **Unit: one unique secret value per tool.** gitleaks reports a row per
  commit that adds a secret, and swordfish one per secret, so both are
  deduplicated first.
- **Matching** is containment after removing whitespace and literal `\n`, so
  a private key reported as an escaped JSON string or an indented YAML block
  still matches. A finding that is only a shorter piece of a secret (at least
  8 characters) counts as found but is reported as *partial*. There were no
  partial matches in these runs.
- **Recall** is counted per planted secret, whichever rule fired. A GitLab
  token caught by swordfish's generic rule counts as found.
- **Precision** is unique true-positive findings divided by unique findings.
  A finding that matches no planted secret is a false positive, attributed to
  a decoy where one matches.
- gitleaks rule IDs are mapped to swordfish's families for the per-family
  precision table (`score.py`, `GITLEAKS_FAMILY`). gitleaks rules for other
  providers fall into `other-provider`.
- Both tools run with their defaults on every ref: swordfish `scan --format
  json --show-secrets`; gitleaks `git --log-opts=--all`. No custom rules or
  allowlists are passed, and neither tool's rules were changed for this
  benchmark.

## Limits

- **Synthetic and author-built.** The corpus was written by swordfish's
  author, who knows its rules. The mitigations are formats taken from
  provider documentation, out-of-scope providers reported in their own table,
  and decoys picked for being realistic rather than for what either tool
  handles. The corpus still measures behaviour on these cases. It is not
  real-world prevalence, and the mix of scenarios and contexts is a choice.
- **One labeler.** Some decoys are debatable. A Stripe publishable key is
  public by design. A UUID can be a real API key for some providers (Heroku,
  for example). They are labeled as not secret here.
- **No real-world data yet.** The natural next step is an external labeled
  dataset such as [Samsung CredData](https://github.com/Samsung/CredData).
  It is a multi-gigabyte download of real repositories with line-level
  labels.
