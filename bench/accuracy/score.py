#!/usr/bin/env python3
"""Score swordfish and gitleaks findings against the corpus ground truth.

    python3 -I bench/accuracy/score.py LABELS SWORDFISH_JSON GITLEAKS_JSON \
        [--meta KEY=VALUE ...] [--details]

Prints the results as Markdown. `--details` adds every false positive
(redacted) to stderr for manual review.

Scoring unit: one unique secret value per tool. gitleaks reports one row per
commit that adds a secret, swordfish one row per secret, so both are reduced
to unique values first. A finding matches a label when one contains the other
after removing whitespace and literal `\\n` (private keys are reported as
blocks and may be escaped in JSON or indented in YAML). A finding that is a
shorter piece of a labeled secret (at least 8 characters) is a *partial*
match: it still points at the leak, but does not capture all of it.
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict

FAMILIES = [
    "aws-access-key-id", "aws-secret-access-key", "github-token", "github-fine-grained-pat", "slack-token",
    "slack-webhook-url", "stripe-secret-key", "google-api-key", "private-key", "jwt", "generic-password",
]
HEADLINE_SCENARIOS = ["live_in_head", "deleted_later", "side_branch_only", "tag_only", "merge_commit_only", "two_files"]
EDGE_SCENARIOS = ["binary_blob", "blob_over_1mib", "unreachable_commit"]

GITLEAKS_FAMILY = [
    (r"^aws-access-token$", "aws-access-key-id"),
    (r"^aws-secret", "aws-secret-access-key"),
    (r"^github-(pat|oauth|app-token|refresh-token)$", "github-token"),
    (r"^github-fine-grained-pat$", "github-fine-grained-pat"),
    (r"^slack-webhook-url$", "slack-webhook-url"),
    (r"^slack-", "slack-token"),
    (r"^stripe-", "stripe-secret-key"),
    (r"^gcp-api-key$", "google-api-key"),
    (r"^private-key$", "private-key"),
    (r"^jwt", "jwt"),
    (r"^generic-api-key$", "generic"),
]


def family_of(tool, rule):
    if tool == "swordfish":
        return "generic" if rule == "generic-api-key" else rule
    for pat, fam in GITLEAKS_FAMILY:
        if re.search(pat, rule):
            return fam
    return "other-provider"


def norm(s):
    return re.sub(r"\\n|\s", "", s)


def redact(s):
    s = s.strip()
    return (s[:4] + "****") if len(s) >= 8 else "****"


def load(tool, path):
    """Unique secret value -> {rules, paths}."""
    data = json.load(open(path))
    out = defaultdict(lambda: {"rules": set(), "paths": set()})
    if tool == "swordfish":
        for f in data["findings"]:
            assert not f.get("redacted"), "run swordfish with --show-secrets"
            e = out[f["secret"]]
            e["rules"].add(f["rule_id"])
            e["paths"].update(loc["path"] for loc in f["locations"])
    else:
        for f in data or []:
            e = out[f["Secret"]]
            e["rules"].add(f["RuleID"])
            e["paths"].add(f["File"])
    return out


def classify(value, items):
    """Return (matches, kind): matches is a list of (item, 'full'|'partial')."""
    v = norm(value)
    secrets, decoys = [], []
    for it in items:
        t = norm(it["value"])
        if not t:
            continue
        if it["kind"] == "secret":
            if t in v:
                secrets.append((it, "full"))
            elif len(v) >= 8 and v in t:
                secrets.append((it, "partial"))
        else:
            if v == t or (len(v) >= 4 and v in t) or (len(t) >= 12 and t in v):
                decoys.append((it, "full"))
    if secrets:
        return secrets, "tp"
    if decoys:
        return decoys, "fp-decoy"
    return [], "fp-unlabeled"


def pct(n, d):
    return f"{100 * n / d:.1f}%" if d else "n/a"


def f1(p, r):
    return 2 * p * r / (p + r) if p + r else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("labels")
    ap.add_argument("swordfish")
    ap.add_argument("gitleaks")
    ap.add_argument("--meta", action="append", default=[])
    ap.add_argument("--details", action="store_true")
    args = ap.parse_args()

    labels = json.load(open(args.labels))
    items = labels["items"]
    secrets = [i for i in items if i["kind"] == "secret"]
    decoys = [i for i in items if i["kind"] == "decoy"]
    tools = {"swordfish": load("swordfish", args.swordfish), "gitleaks": load("gitleaks", args.gitleaks)}

    found = {}       # tool -> item id -> best match ('full' beats 'partial')
    caught_by = {}   # tool -> item id -> set of rule ids
    flagged = {}     # tool -> decoy id -> True
    fstats = {}      # tool -> Counter of finding classes
    fam_tp_fp = {}   # tool -> family -> Counter(tp, fp)
    fps = {}         # tool -> list of false positives
    for tool, findings in tools.items():
        found[tool], caught_by[tool], flagged[tool] = {}, defaultdict(set), {}
        fstats[tool], fam_tp_fp[tool], fps[tool] = Counter(), defaultdict(Counter), []
        for value, meta in findings.items():
            matches, kind = classify(value, items)
            fstats[tool][kind] += 1
            for rule in meta["rules"]:
                fam_tp_fp[tool][family_of(tool, rule)]["tp" if kind == "tp" else "fp"] += 1
            if kind == "tp":
                for it, how in matches:
                    if found[tool].get(it["id"]) != "full":
                        found[tool][it["id"]] = how
                    caught_by[tool][it["id"]].update(meta["rules"])
            else:
                for it, _ in matches:
                    flagged[tool][it["id"]] = True
                fps[tool].append((kind, matches[0][0]["category"] if matches else "-", sorted(meta["rules"]),
                                  sorted(meta["paths"])[:1], redact(value)))

    T = list(tools)
    out = []
    w = out.append
    w("# Accuracy results\n")
    w("Generated by `bench/accuracy/run.sh`; methodology in [README.md](README.md).\n")
    for m in args.meta:
        key, _, value = m.partition("=")
        w(f"- {key}: `{value}`")
    w(f"- corpus: {len(secrets)} planted secrets, {len(decoys)} decoys\n")

    def recall_row(label, group):
        cells = [label, str(len(group))]
        for t in T:
            full = sum(1 for i in group if found[t].get(i["id"]) == "full")
            part = sum(1 for i in group if found[t].get(i["id"]) == "partial")
            cells.append(f"{full + part} ({pct(full + part, len(group))})" + (f", {part} partial" if part else ""))
        return "| " + " | ".join(cells) + " |"

    head = [i for i in secrets if i["in_scope"] and i["scenario"] in HEADLINE_SCENARIOS]
    oos = [i for i in secrets if not i["in_scope"]]
    edge = [i for i in secrets if i["scenario"] in EDGE_SCENARIOS]

    w("## Headline\n")
    w("| | " + " | ".join(T) + " |")
    w("|---|" + "---|" * len(T))
    rec = {t: sum(1 for i in head if i["id"] in found[t]) / len(head) for t in T}
    prec = {t: fstats[t]["tp"] / sum(fstats[t].values()) if fstats[t] else 0 for t in T}
    w("| Recall, in-scope families, reachable text blobs (n=%d) | " % len(head) + " | ".join(pct(rec[t] * len(head), len(head)) for t in T) + " |")
    nm = [i for i in head if i["scenario"] != "merge_commit_only"]
    w("| ... excluding secrets that exist only in a merge commit (n=%d) | " % len(nm) + " | ".join(pct(sum(1 for i in nm if i["id"] in found[t]), len(nm)) for t in T) + " |")
    w("| Recall, providers swordfish has no rule for (n=%d) | " % len(oos) + " | ".join(pct(sum(1 for i in oos if i["id"] in found[t]), len(oos)) for t in T) + " |")
    w("| Precision, all unique findings | " + " | ".join(f"{pct(fstats[t]['tp'], sum(fstats[t].values()))} ({fstats[t]['tp']}/{sum(fstats[t].values())})" for t in T) + " |")
    w("| F1 (in-scope recall, overall precision) | " + " | ".join(f"{f1(prec[t], rec[t]):.3f}" for t in T) + " |")
    w("| Decoys flagged (n=%d) | " % len(decoys) + " | ".join(str(len(flagged[t])) for t in T) + " |")
    w("| Unique findings (raw report rows) | " + " | ".join(f"{len(tools[t])} ({raw})" for t, raw in zip(T, raw_rows(args))) + " |")
    w("")

    w("## Recall by family (in-scope, reachable text blobs)\n")
    w("Planted category, not the rule that fired: a GitHub token caught only by a generic rule still counts.\n")
    w("| family | planted | " + " | ".join(T) + " |")
    w("|---|---:|" + "---|" * len(T))
    for fam in FAMILIES:
        w(recall_row(fam, [i for i in head if i["category"] == fam]))
    w("")

    w("## Precision by rule family\n")
    w("Each unique finding is attributed to the family of the rule(s) that reported it.\n")
    w("| rule family | " + " | ".join(f"{t} TP / FP" for t in T) + " |")
    w("|---|" + "---|" * len(T))
    fams = sorted({f for t in T for f in fam_tp_fp[t]}, key=lambda f: (FAMILIES + ["generic", "other-provider"]).index(f) if f in FAMILIES + ["generic", "other-provider"] else 99)
    for fam in fams:
        w(f"| {fam} | " + " | ".join(f"{fam_tp_fp[t][fam]['tp']} / {fam_tp_fp[t][fam]['fp']}" for t in T) + " |")
    w("")

    w("## Providers swordfish has no rule for\n")
    w("| provider | planted | " + " | ".join(T) + " | swordfish rule that caught it |")
    w("|---|---:|" + "---|" * len(T) + "---|")
    for cat in sorted({i["category"] for i in oos}):
        group = [i for i in oos if i["category"] == cat]
        rules = sorted({r for i in group for r in caught_by["swordfish"].get(i["id"], ())}) or ["-"]
        w(recall_row(cat, group)[:-2] + f" | {', '.join(rules)} |")
    w("")

    w("## Recall by history scenario (in-scope)\n")
    w("| scenario | planted | " + " | ".join(T) + " |")
    w("|---|---:|" + "---|" * len(T))
    for sc in HEADLINE_SCENARIOS + EDGE_SCENARIOS:
        w(recall_row(sc, [i for i in secrets if i["in_scope"] and i["scenario"] == sc]))
    w("")

    w("## Decoys (not secrets)\n")
    w("| decoy category | planted | " + " | ".join(f"flagged by {t}" for t in T) + " |")
    w("|---|---:|" + "---:|" * len(T))
    for cat in sorted({d["category"] for d in decoys}):
        group = [d for d in decoys if d["category"] == cat]
        w(f"| {cat} | {len(group)} | " + " | ".join(str(sum(1 for d in group if d["id"] in flagged[t])) for t in T) + " |")
    w("")
    w("False positives that match no label (filler code, lockfiles, or a mis-captured span): "
      + ", ".join(f"{t} {fstats[t]['fp-unlabeled']}" for t in T) + ".\n")

    w("## Agreement on all planted secrets (n=%d)\n" % len(secrets))
    both = sum(1 for i in secrets if all(i["id"] in found[t] for t in T))
    only = {t: sum(1 for i in secrets if i["id"] in found[t] and not any(i["id"] in found[u] for u in T if u != t)) for t in T}
    neither = sum(1 for i in secrets if not any(i["id"] in found[t] for t in T))
    w("| both | " + " | ".join(f"only {t}" for t in T) + " | neither |")
    w("|---:|" + "---:|" * len(T) + "---:|")
    w(f"| {both} | " + " | ".join(str(only[t]) for t in T) + f" | {neither} |")
    w("")

    print("\n".join(out))
    if args.details:
        for t in T:
            for fp in fps[t]:
                print(t, *fp, file=sys.stderr)
        for t in T:
            for i in secrets:
                if i["id"] not in found[t] and i["scenario"] in HEADLINE_SCENARIOS:
                    print(f"MISS {t} {i['id']} {i['category']} {i['scenario']} {i['paths'][:1]} ctx={i.get('context')!r}", file=sys.stderr)


def raw_rows(args):
    sf = json.load(open(args.swordfish))["findings"]
    gl = json.load(open(args.gitleaks)) or []
    return [len(sf), len(gl)]


if __name__ == "__main__":
    main()
