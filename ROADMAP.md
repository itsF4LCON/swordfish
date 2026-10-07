# swordfish roadmap

> Secrets you deleted still haunt your history.

swordfish finds secrets in git history and tells the story of each leak: when
it appeared, when it was "removed", how long it was exposed, and which refs can
still reach it. Other tools find secrets. swordfish focuses on the exposure
timeline and on places people forget to look: deleted branches, the reflog,
dangling objects, PR refs, and forks.

This document is the source of truth for the architecture, the data model and
the JSON output schema. Changes to the CLI or the JSON schema need explicit
sign-off from the maintainer.

---

## 1. Principles

1. **Read-only.** swordfish never writes to the repository it scans. It opens
   repos with gix in isolated mode, so it ignores global and system git config
   and never runs hooks, filters or fsmonitor.
2. **No network** in v0.1–v0.3. The first network access comes in v0.4 (the
   GitHub API), and only when the user explicitly passes a flag.
3. **Never print full secrets by default.** Output shows a redacted form and
   a fingerprint. `--show-secrets` is opt-in and prints a warning to stderr.
4. **Scan each unique blob exactly once.** Performance comes from
   deduplication, not micro-optimisation.
5. **CI friendly.** The output is stable JSON, and the exit codes are
   `0` = clean, `1` = findings, `2` = error.
6. **Live-secret verification is out of scope until later.** That means
   calling a provider API to check whether a key still works. When it arrives,
   it will be opt-in and fail-closed. It will only run against repos listed in
   an explicit scope file of repos the operator owns or is authorised to test.
   Anything not in scope, or a missing or unparsable scope file, means no
   verification at all. It is not built in v0.1.

---

## 2. Architecture (v0.1)

```
             ┌────────────┐   tips (refs + HEAD)
 PATH ──────▶│  history   │── commit graph (oid, parents, tree, time, author)
             │  walk      │── topo order (Kahn, ties broken by commit time)
             └─────┬──────┘
                   │ per-commit tree diff vs first parent (parallel, rayon)
                   ▼
             ┌────────────┐
             │  changes   │  (commit, path, Option<blob>)   paths & blobs interned
             └─────┬──────┘
                   │ unique blob set (dedupe)
                   ▼
             ┌────────────┐   stage 1: Aho-Corasick over all rule keywords
             │  detector  │   stage 2: regex only for rules whose keyword hit
             │ (parallel) │   stage 3: entropy + allowlists on regex candidates
             └─────┬──────┘
                   │ blob -> [hit(secret, rule, line)]
                   ▼
             ┌────────────┐   propagate secret-bearing (path, blob) sets along
             │  timeline  │   the topo order, derive add/remove events,
             │            │   reachability from refs, status
             └─────┬──────┘
                   ▼
             ┌────────────┐
             │  report    │── pretty (terminal) | json (schema v1)
             └────────────┘
```

### Modules

| module | responsibility |
|---|---|
| `rules` | gitleaks-compatible TOML subset, built-in rules (`rules/default.toml` embedded with `include_str!`), allowlists |
| `detect` | blob → hits. Binary sniffing, two-stage matching, span de-duplication |
| `entropy` | Shannon entropy in bits per byte |
| `redact` | redacted form, SHA-256 fingerprint |
| `history` | ref enumeration, commit graph load, topo sort, recursive tree diff |
| `timeline` | presence propagation, add/remove events, status, refs, exposure |
| `report` | serde types for the JSON schema and the pretty renderer |
| `main.rs` | clap CLI and exit codes |

### Why the design is fast

* **Blob dedupe.** Walking history only collects blob OIDs that are *new
  relative to the first parent*. Every blob in every reachable tree shows up
  that way at least once (proof: induction over the first-parent chain, with
  root commits diffed against the empty tree). The unique set is scanned once,
  in parallel.
* **Subtree pruning.** The tree diff is our own recursive merge-walk in git's
  canonical entry order. It never descends into subtrees whose OIDs match, so a
  commit that touches one file costs O(depth), not O(tree size).
* **Two-stage detection.** One case-insensitive Aho-Corasick automaton built
  from every rule keyword runs over each blob. Only rules with a keyword hit run
  their regex. Rules without keywords always run. Entropy is computed only for
  regex candidates.
* **Cheap skips.** Blob size comes from the object header (`find_header`), so
  oversized blobs are never inflated. Binary blobs are detected by a NUL byte in
  the first 8 KiB. Blobs seen only at globally allowlisted paths are never read.
  Every skip is counted in `stats`.
* **Timeline propagation shares memory.** Each commit carries only its
  *secret-bearing* `(path, blob)` entries, and that set is `Arc`-shared with
  the first parent whenever the diff doesn't touch it. On a clean history this
  is a no-op per commit.

---

## 3. Data model

```text
CommitNode   { id, parents: [idx], tree, time (committer, unix secs),
               author_name, author_email }
Change       { path_id, blob: Option<blob_idx> }        // vs first parent
BlobHit      { secret_id, rule_idx, line }               // per unique blob
Secret       { fingerprint = sha256(value), value, rule_idx }
Presence(c)  = sorted [(path_id, blob_idx)] whose blob has an allowed hit
Secrets(c)   = sorted unique secret ids present anywhere in tree(c)
```

**Path-dependent filters.** The global path allowlist, per-rule path
allowlists and a rule's `path` restriction can't be applied while scanning
deduplicated blobs, because one blob can live at many paths. They are applied
when a hit is attached to a `(path, blob)` entry. The single exception is the
skip optimisation above: a blob that only ever appears at globally allowlisted
paths is not read at all.

### Timeline semantics (definitions)

All ordering uses **committer time**, with ties broken by topological
position. Dates in the output are committer dates in UTC, RFC 3339, because the
committer date is when the content actually landed in this history (the author
date survives rebases and cherry-picks). The author name and email are reported
next to it.

For each secret `s`:

* **Present in commit `c`**: some `(path, blob)` in `tree(c)` contains `s`, and
  `path` is allowed for the hit's rule.
* **Add event at `c`**: `s` is present in `c` and in **none** of `c`'s parents.
  A merge that brings in a branch's secret is therefore *not* an add event. The
  branch commit that introduced it is.
* **Remove event at `c`**: `s` is present in some parent of `c` but not in `c`.
* **introduced**: the earliest add event. Its `path` and `line` are the
  location of `s` in that commit.
* **live_in_head**: `s` is present in the tree of the commit `HEAD` resolves to.
* **removed**:
  * `null` if `live_in_head`.
  * Otherwise, the earliest remove event in a descendant of the introducing
    commit. Remove events that are ancestors of `HEAD` are preferred, which is
    what "the same line of history" means.
  * `null` if there is no such event, for example when the secret still lives at
    the tip of a branch other than `HEAD`.
  * `removed.path` is where the parent still had it.
  * Removal means "gone from the whole tree". Renaming a file that holds a secret
    is not a removal.
* **exposure_days**: `(removed.date or now) − introduced.date`, in days,
  rounded to 2 decimals and never negative.
* **refs**: every ref, plus `HEAD` when detached, that can reach *any* commit
  containing `s`. Every containing commit has an add-event ancestor, so this
  equals the refs whose tip is a descendant of any add-event commit. It's
  computed with a breadth-first search over child edges.
* **status** (v0.1): `live_in_head` or `removed_but_in_history`.
  * v0.2 adds `unreachable_only`.

Refs scanned in v0.1 are every ref under `refs/` (branches, tags, remotes,
notes, stash, …) with tags peeled to commits, plus `HEAD`. Commits that only a
deleted branch can reach are *not* scanned until v0.2.

---

## 4. JSON schema (v1)

Stable from v0.1 onward. Fields may be added in minor versions. Renaming or
removing a field, or changing its meaning, bumps `schema_version`.

```jsonc
{
  "schema_version": 1,
  "tool": { "name": "swordfish", "version": "0.1.0" },
  "repository": "/abs/path/to/repo",          // git dir's worktree (or git dir if bare)
  "head": "refs/heads/main",                   // symbolic HEAD target (even if unborn), "HEAD" if detached
  "generated_at": "2026-10-07T20:00:00Z",
  "stats": {
    "refs": 3,                 // distinct ref names scanned (excluding HEAD)
    "commits": 120,
    "unique_blobs": 800,
    "scanned_blobs": 785,
    "skipped_binary": 7,
    "skipped_too_large": 3,
    "skipped_allowlisted": 4,  // blobs only seen at globally allowlisted paths
    "skipped_missing": 1,      // objects absent from the odb (shallow/partial clones)
    "findings": 2,
    "elapsed_ms": 412
  },
  "findings": [
    {
      "fingerprint": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "rule_id": "aws-access-key-id",
      "description": "AWS access key ID",
      "secret": "AKIA****",              // full value only with --show-secrets
      "redacted": true,
      "status": "removed_but_in_history", // live_in_head | removed_but_in_history
      "introduced": {
        "commit": "<40-hex>",
        "author": { "name": "Alice", "email": "alice@example.com" },
        "date": "2024-01-02T10:00:00Z",
        "path": "config/.env",
        "line": 3
      },
      "removed": {                        // or null
        "commit": "<40-hex>",
        "author": { "name": "Bob", "email": "bob@example.com" },
        "date": "2024-02-01T10:00:00Z",
        "path": "config/.env"
      },
      "exposure_days": 30.0,
      "refs": ["refs/heads/main", "refs/tags/v1.0"],
      "locations": [                      // every distinct place it was seen
        { "path": "config/.env", "blob": "<40-hex>", "line": 3 }
      ]
    }
  ]
}
```

Findings are sorted by `introduced.date`, then `fingerprint`. Redaction keeps
the first 4 characters and appends `****`. Secrets shorter than 8 characters
are shown as `****` only.

---

## 5. Rule format

swordfish supports a gitleaks-compatible TOML subset. The built-in rules use
the same format, and `--rules FILE` *extends* them.

```toml
[[rules]]
id = "my-token"                  # required, unique
description = "Internal token"   # optional
regex = '''\b(myco_[a-z0-9]{32})\b'''   # required (Rust regex syntax ≈ RE2)
secretGroup = 1                  # optional; default: group 1 if present, else whole match
entropy = 3.5                    # optional; candidate must have entropy > this
keywords = ["myco_"]             # optional; case-insensitive prefilter
path = '''\.env$'''              # optional; rule only applies to matching paths

[rules.allowlist]                # optional (gitleaks <8.21 form)
regexes = ['''EXAMPLE''']        # matched against regexTarget
regexTarget = "secret"           # secret (default) | match | line
paths = ['''^test/''']
stopwords = ["dummy"]            # secret containing any → ignored (case-insensitive)

[[rules.allowlists]]             # also accepted (gitleaks ≥8.21 form), any number

[allowlist]                      # global allowlist: paths, regexes, stopwords
paths = ['''(^|/)vendor/''']
```

Other gitleaks keys: `tags` and unknown keys are ignored silently.
`commits`, a `condition` other than OR, and `[extend]` are ignored with a
warning. A rule without a `regex` (gitleaks path-only rules) is
skipped with a warning.

---

## 6. Phased plan

### v0.1: history walk, detection, timeline (this release)

Tasks:
- [x] Crate scaffold, dual licence, CI (fmt, clippy `-D warnings`, test).
- [x] `history`: enumerate refs and HEAD, peel tags, load the commit graph
  (tolerating missing parents in shallow clones), Kahn topo sort, recursive
  first-parent tree diff run in parallel, path and blob interning.
- [x] `rules`: TOML subset loader and built-in rules (AWS access key and
  secret, GitHub classic and fine-grained tokens, Slack token and webhook,
  Stripe, Google API key, private key blocks, JWT, generic high-entropy
  assignment), allowlists.
- [x] `detect`: Aho-Corasick prefilter, regex stage, entropy, allowlists,
  overlapping-span dedupe, binary and size skips.
- [x] `timeline`: presence propagation, events, introduced/removed, refs,
  status, exposure, locations.
- [x] `report`: JSON schema v1 and a pretty terminal view (colour only on a
  TTY, honours `NO_COLOR`).
- [x] CLI: `swordfish scan [PATH] [--format pretty|json] [--rules FILE]
  [--max-blob-size N] [--show-secrets]`, exit codes 0/1/2.
- [x] Tests: unit tests (entropy, rules, redaction, detector) and integration
  tests on fixture repos built with gix at test time.
- [x] Benchmark script comparing against gitleaks with hyperfine.

Acceptance criteria:
- A fixture with a secret committed on day 1 and deleted on day 31 reports
  `introduced`/`removed` commits, dates, path and line exactly, plus
  `exposure_days == 30.0` and `status == removed_but_in_history`.
- A secret still in HEAD reports `removed == null` and `status == live_in_head`.
- A secret that only exists on a deleted, unmerged branch is **not** reported
  (documented gap, closed by v0.2).
- A secret merged in from a branch is `introduced` at the branch commit, not
  at the merge.
- A binary file is counted in `skipped_binary` and produces no findings.
- JSON output never contains a full secret unless `--show-secrets` is passed.
- The exit code is `0` with no findings, `1` with findings, and `2` on errors
  (including a non-repo path).
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
  `cargo test` pass in CI.

### v0.2: deleted branches, reflog, dangling objects

Tasks:
- Add every reflog entry (including `HEAD`'s) as an extra tip. The commits
  they reach join the graph with an `origin: reflog` marker.
- Enumerate all objects in the odb (loose and packed). Commits nobody
  references become extra tips. Blobs no tree references at all are scanned as
  "orphan blobs", with no path and no commit.
- Optionally scan stash entries explicitly, beyond `refs/stash`.
- Status classification:
  - `live_in_head`
  - `removed_but_in_history` (reachable from a ref)
  - `unreachable_only`: only reachable from the reflog or dangling objects,
    so it disappears on `git gc --prune` but still sits in local clones and
    possibly on the server.
- Add a `reachable_via` field (`refs` | `reflog` | `dangling`), a minor
  schema addition.

Acceptance criteria:
- A secret on a branch that was created and then deleted is reported as
  `unreachable_only`, with the reflog as evidence.
- A blob that was `git add`-ed and never committed (dangling) is reported with
  `introduced == null` and a `blob` location.
- Running v0.2 on a repo with no dangling objects produces exactly the v0.1
  findings set.

### v0.3: HTML report

Tasks:
- `--format html` writes a single self-contained file: inline CSS and JS, no
  CDN, no network.
- One horizontal timeline bar per secret, from introduced to removed or now,
  on a shared time axis.
- Bars are coloured by exposure: local only, pushed (reachable from a
  `refs/remotes/*` ref), or public (a remote URL known to be public, decided
  offline from config only).
- Secrets are redacted unless `--show-secrets` is passed, with a visible
  banner when they are shown.

Acceptance criteria:
- The report opens offline and validates as HTML5.
- A file `grep` finds no secret values when `--show-secrets` is absent.
- The report renders 1,000 findings without visible lag.

### v0.4: GitHub integration (first network feature, opt-in)

Tasks:
- `swordfish github OWNER/REPO` scans `refs/pull/*/head` and `refs/pull/*/merge`.
- Fork network enumeration through the API, including cross-fork object
  access: commits reachable through the network even after deletion in the
  origin.
- Token from the environment only, never logged. Rate-limit aware, with
  resumable state.

Acceptance criteria:
- A PR whose head commit introduced a secret is reported, with the PR number
  in `refs`.
- With no token, it degrades to public endpoints and makes no other network
  calls.

### v1.0: GitHub Action and stability

Tasks:
- A GitHub Action that runs on `push` and diffs findings against the previous
  run. It warns when a secret was deleted but still lives in history
  ("rotate this key") and annotates the commit that removed it.
- Freeze the rule format (`rules` v1), publish the docs, and add a rule-writing
  guide.
- Release binaries for Linux, macOS and Windows, publish to crates.io under
  the package name chosen in §8, and sign artifacts.
- Opt-in live-secret verification, under the constraints in §1.6.

Acceptance criteria:
- The Action runs on a sample repo in under 60s for 10k commits.
- Semver commitment on the CLI flags, the JSON schema and the rule format.

---

## 7. Benchmark

`bench/compare.sh` clones a large public repository (`BENCH_REPO`, default
`https://github.com/rails/rails`) once into a cache directory. It then runs
`hyperfine` comparing `swordfish scan --format json` with
`gitleaks git --no-banner --report-format json --report-path /dev/null`.
See `bench/README.md`.

## 8. Naming

The `swordfish` crate name on crates.io is taken by an unrelated project, a
data-oriented simulation library (v0.1.9). The package is published as
**`swordfish-git`**, and the binary is still called **`swordfish`**. Other
names that were free when checked (2026-10-07): `git-swordfish`, `leakline`,
`histleak`, `secret-timeline`.
