# swordfish

**Secrets you deleted still haunt your history.**

You commit an AWS key. A week later you notice, delete the file and push a
"remove secrets" commit. The key is still there: in every clone, in every tag
cut before the fix, and on every branch that forked before it.

Scanners like gitleaks and trufflehog tell you *that* a secret exists.
swordfish tells you **the story of each leak**:

- **when it appeared:** the commit, author, date, file and line
- **when it was "removed":** the commit that deleted it from the tree
- **how long it was exposed:** in days
- **who can still reach it:** the branches and tags that contain it today
- **its status:** `live_in_head`, `live_on_other_ref` (gone from HEAD but
  still on another branch), or `removed_but_in_history` ("rotate this key")

swordfish is **read-only** (it never writes to the repo it scans) and makes
**no network calls**.

## Install

```sh
cargo install --git https://github.com/itsF4LCON/swordfish swordfish-git
# or from a checkout
cargo install --path .
```

The crate is `swordfish-git` (the `swordfish` name on crates.io is taken), and
the binary is `swordfish`.

## Usage

```sh
swordfish scan [PATH] [--format pretty|json] [--rules FILE] [--max-blob-size N] [--show-secrets]
```

| option | meaning |
|---|---|
| `PATH` | any directory inside the repository (default `.`) |
| `--format` | `pretty` (default, colour on a TTY, honours `NO_COLOR`) or `json` (schema v1) |
| `--rules FILE` | extra rules in a gitleaks-compatible TOML subset, added to the built-in rules |
| `--max-blob-size N` | skip blobs larger than N bytes (default 1048576) |
| `--show-secrets` | print secrets in full instead of `AKIA****` (prints a warning) |

Exit codes: **0** no findings, **1** findings, **2** error. Drop it straight
into CI.

### Example

Try it on the demo repository (fake secrets):

```sh
cargo run --example demo -- /tmp/swordfish-demo
swordfish scan /tmp/swordfish-demo
```

```text
swordfish /tmp/swordfish-demo  (HEAD → refs/heads/main)
scanned 4 commits across 2 refs · 3 unique blobs (3 scanned, 0 binary, 0 too large, 0 allowlisted, 0 missing) · 1 ms

● [1/2] aws-access-key-id  AKIA****  fp 2407cc460656
  status      REMOVED, BUT STILL IN HISTORY (rotate this key)
  introduced  2025-03-05 09:00 UTC  e71a2363db  Alice <alice@example.com>
              .env:2
  removed     2025-03-26 09:00 UTC  e3b60ba34e  Alice <alice@example.com>  from .env
  exposed     21.00 days
  timeline    ███░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
  reachable   refs/heads/main, refs/tags/v1.0.0
  seen at     .env:2 (8ec4b3f3)

● [2/2] github-token  ghp_****  fp dc379ff48c75
  status      LIVE IN HEAD
  introduced  2025-03-12 09:00 UTC  3df24ec9b0  Bob <bob@example.com>
              scripts/deploy.sh:2
  removed     never
  exposed     574.48 days and counting
  timeline    ░███████████████████████████████████████
  reachable   refs/heads/main
  seen at     scripts/deploy.sh:2 (7f345bf9)

2 secrets found: 1 live in HEAD, 0 live on another ref, 1 removed but still in history

See you, space cowboy...
```

The `.env` file was deleted three weeks after it was committed, but the
`v1.0.0` tag still ships it.

JSON output (`--format json`, abridged):

```json
{
  "schema_version": 1,
  "head": "refs/heads/main",
  "stats": { "commits": 4, "unique_blobs": 3, "scanned_blobs": 3, "skipped_binary": 0, "findings": 2 },
  "findings": [
    {
      "fingerprint": "2407cc4606565445d89501b158bca8416593175db1275d2f2a5ac47bcdf55b2d",
      "rule_id": "aws-access-key-id",
      "secret": "AKIA****",
      "redacted": true,
      "status": "removed_but_in_history",
      "introduced": { "commit": "e71a2363…", "author": { "name": "Alice", "email": "alice@example.com" },
                      "date": "2025-03-05T09:00:00Z", "path": ".env", "line": 2 },
      "removed":    { "commit": "e3b60ba3…", "author": { "name": "Alice", "email": "alice@example.com" },
                      "date": "2025-03-26T09:00:00Z", "path": ".env" },
      "exposure_days": 21.0,
      "refs": ["refs/heads/main", "refs/tags/v1.0.0"],
      "locations": [{ "path": ".env", "blob": "8ec4b3f3…", "line": 2 }]
    }
  ]
}
```

The full schema and the exact timeline definitions are in
[ROADMAP.md](ROADMAP.md#4-json-schema-v1).

## Built-in rules

AWS access key IDs and secret keys, GitHub classic and fine-grained tokens,
Slack tokens and webhooks, Stripe secret keys, Google API keys, private key
blocks, JWTs, and a generic high-entropy assignment rule. Published example
values such as `AKIAIOSFODNN7EXAMPLE` are allowlisted.

### Custom rules

```toml
[allowlist]                       # global
paths = ['''^fixtures/''']

[[rules]]
id = "internal-token"
description = "Internal service token"
regex = '''\b(itk_[a-z0-9]{24})\b'''
keywords = ["itk_"]
entropy = 3.0                     # optional
[rules.allowlist]                 # optional
stopwords = ["dummy"]
```

A rule with the same `id` as a built-in one replaces it.

## How it's fast

- **Every unique blob is scanned once.** History is walked in topological order
  and each commit's tree is diffed against its first parent, skipping identical
  subtrees. Only new blob IDs are collected. The deduplicated set is then
  scanned in parallel with rayon.
- **Detection runs in two stages.** One Aho-Corasick automaton over all rule
  keywords prefilters each blob, and only rules whose keyword hit run their
  regex. Entropy is checked only on regex candidates.
- **Cheap skips.** Size comes from the object header, so oversized blobs are
  never inflated. Binary blobs are detected by a NUL byte in the first 8 KiB.

On `rust-lang/cargo` (35k commits, 9.7k refs, 71k unique blobs) a full scan
takes about 1 s on 20 cores and about 5 s on 2 threads. `bench/compare.sh`
runs a hyperfine comparison against gitleaks; see [bench/README.md](bench/README.md).

## Roadmap

v0.1 (this release) walks every commit reachable from any ref. Next:
- v0.2: deleted branches via the reflog, and dangling objects
- v0.3: self-contained HTML timeline report
- v0.4: GitHub PR refs and fork networks
- v1.0: a GitHub Action that says "rotate this key"

Details in [ROADMAP.md](ROADMAP.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.

---

built by F4LCON under solliia
