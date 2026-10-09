#!/usr/bin/env python3
"""Build the labeled accuracy corpus: a git repository full of fake secrets.

    python3 -I bench/accuracy/gen_corpus.py <empty-dir> [--seed N]

Writes the repository to <empty-dir>/repo and the ground truth to
<empty-dir>/labels.json. Output is deterministic for a given seed (fixed
dates, identities and RNG), so commit IDs are reproducible.

Every "secret" is random data shaped like the provider's *published* token
format. None of them is a real credential, and none is written down in this
file: they are generated at run time so this repository never contains them.
Formats come from provider documentation, not from swordfish's or gitleaks'
rule regexes, so neither tool is graded against its own patterns.
"""

import argparse
import base64
import json
import os
import random
import string
import subprocess
import sys
import zlib
from pathlib import Path

UPPER = string.ascii_uppercase
LOWER = string.ascii_lowercase
DIGITS = string.digits
ALNUM = DIGITS + UPPER + LOWER
HEX = "0123456789abcdef"
B32 = UPPER + "234567"
B64 = UPPER + LOWER + DIGITS + "+/"
B64URL = UPPER + LOWER + DIGITS + "-_"

# 2024-01-08T09:00:00Z; one corpus "day" per commit keeps dates readable.
T0 = 1_704_704_400
DAY = 86_400

rng = random.Random()


def rs(n, alphabet=ALNUM):
    return "".join(rng.choice(alphabet) for _ in range(n))


def b62(n):
    out = ""
    while n:
        n, r = divmod(n, 62)
        out = (DIGITS + UPPER + LOWER)[r] + out
    return out or "0"


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# ---------------------------------------------------------------------------
# Token formats (provider documentation / public format write-ups)
# ---------------------------------------------------------------------------


def github_classic(prefix):
    # 30 random base62 chars + 6-char base62 CRC32 checksum (GitHub, 2021).
    body = rs(30)
    return f"{prefix}_{body}{b62(zlib.crc32(body.encode())).rjust(6, '0')}"


def private_key():
    kind = rng.choice(["RSA", "EC", "OPENSSH", "PKCS8"])
    if kind == "RSA":
        label, lead, size = "RSA PRIVATE KEY", b"\x30\x82\x04\xa4\x02\x01\x00\x02\x82\x01\x01\x00", 1180
    elif kind == "EC":
        label, lead, size = "EC PRIVATE KEY", b"\x30\x77\x02\x01\x01\x04\x20", 112
    elif kind == "OPENSSH":
        label, lead, size = "OPENSSH PRIVATE KEY", b"openssh-key-v1\x00", 380
    else:
        label, lead, size = "PRIVATE KEY", b"\x30\x82\x04\xbe\x02\x01\x00\x30\x0d", 1200
    body = base64.b64encode(lead + rng.randbytes(size)).decode()
    width = 70 if kind == "OPENSSH" else 64
    lines = [body[i : i + width] for i in range(0, len(body), width)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----"


def jwt():
    header = b64url(json.dumps({"alg": rng.choice(["HS256", "RS256"]), "typ": "JWT"}, separators=(",", ":")).encode())
    claims = {"sub": rs(12, HEX), "iss": rng.choice(["auth.internal", "api.corp", "accounts"]),
              "iat": 1_700_000_000 + rng.randrange(10**7)}
    payload = b64url(json.dumps(claims, separators=(",", ":")).encode())
    return f"{header}.{payload}.{b64url(rng.randbytes(32))}"


def password():
    shape = rng.choice(["alnum", "symbols", "b64"])
    if shape == "alnum":
        return rs(rng.randint(16, 24))
    if shape == "symbols":
        return rs(rng.randint(14, 20), ALNUM + "!@#%^&*()-_=+")
    return base64.b64encode(rng.randbytes(rng.choice([24, 32]))).decode()


# family -> (generator, variable-name stem, whether it needs a keyword context)
IN_SCOPE = {
    "aws-access-key-id": lambda: rng.choice(["AKIA", "ASIA"]) + rs(16, B32),
    "aws-secret-access-key": lambda: rs(40, B64),
    "github-token": lambda: github_classic(rng.choice(["ghp", "ghp", "gho", "ghs", "ghu"])),
    "github-fine-grained-pat": lambda: f"github_pat_{rs(22)}_{rs(59)}",
    "slack-token": lambda: rng.choice([
        f"xoxb-{rs(12, DIGITS)}-{rs(13, DIGITS)}-{rs(24)}",
        f"xoxp-{rs(12, DIGITS)}-{rs(12, DIGITS)}-{rs(13, DIGITS)}-{rs(32, HEX)}",
    ]),
    "slack-webhook-url": lambda: f"https://hooks.slack.com/services/T{rs(10, UPPER + DIGITS)}/B{rs(10, UPPER + DIGITS)}/{rs(24)}",
    "stripe-secret-key": lambda: f"{rng.choice(['sk_live', 'rk_live', 'sk_live'])}_{rs(rng.choice([24, 99]))}",
    "google-api-key": lambda: "AIza" + rs(35, ALNUM + "-_"),
    "private-key": private_key,
    "jwt": jwt,
    "generic-password": password,
}

OUT_OF_SCOPE = {
    "openai-api-key": lambda: f"sk-proj-{rs(74, ALNUM + '-_')}T3BlbkFJ{rs(74, ALNUM + '-_')}",
    "anthropic-api-key": lambda: f"sk-ant-api03-{rs(93, ALNUM + '-_')}AA",
    "gitlab-pat": lambda: f"glpat-{rs(20, ALNUM + '-_')}",
    "sendgrid-api-key": lambda: f"SG.{rs(22, ALNUM + '-_')}.{rs(43, ALNUM + '-_')}",
    "twilio-api-key": lambda: f"SK{rs(32, HEX)}",
    "npm-token": lambda: f"npm_{rs(36)}",
    "pypi-token": lambda: f"pypi-AgEIcHlwaS5vcmc{rs(70, ALNUM + '-_')}",
    "shopify-token": lambda: f"shpat_{rs(32, HEX)}",
    "digitalocean-token": lambda: f"dop_v1_{rs(64, HEX)}",
    "databricks-token": lambda: f"dapi{rs(32, HEX)}",
}

NAMES = {
    "aws-access-key-id": ["AWS_ACCESS_KEY_ID", "aws_access_key_id", "accessKeyId"],
    "aws-secret-access-key": ["AWS_SECRET_ACCESS_KEY", "aws_secret_access_key", "secretAccessKey"],
    "github-token": ["GITHUB_TOKEN", "GH_TOKEN", "github_token"],
    "github-fine-grained-pat": ["GITHUB_PAT", "GH_TOKEN", "gh_pat"],
    "slack-token": ["SLACK_BOT_TOKEN", "slack_token", "SLACK_API_TOKEN"],
    "slack-webhook-url": ["SLACK_WEBHOOK_URL", "slack_webhook", "webhookUrl"],
    "stripe-secret-key": ["STRIPE_SECRET_KEY", "stripe_api_key", "stripeSecret"],
    "google-api-key": ["GOOGLE_API_KEY", "MAPS_API_KEY", "googleApiKey"],
    "jwt": ["SERVICE_TOKEN", "auth_token", "accessToken"],
    "generic-password": ["DB_PASSWORD", "db_password", "REDIS_PASSWORD", "client_secret",
                         "API_SECRET", "smtpPassword", "SECRET_KEY", "api_key", "AUTH_TOKEN",
                         "admin_pass", "MYSQL_ROOT_PASSWORD", "encryptionKey"],
    "openai-api-key": ["OPENAI_API_KEY", "openai_key", "llm_api_key"],
    "anthropic-api-key": ["ANTHROPIC_API_KEY", "claude_key"],
    "gitlab-pat": ["GITLAB_TOKEN", "CI_TOKEN", "gitlab_pat"],
    "sendgrid-api-key": ["SENDGRID_API_KEY", "MAIL_KEY"],
    "twilio-api-key": ["TWILIO_API_KEY", "twilio_sid"],
    "npm-token": ["NPM_TOKEN", "_authToken"],
    "pypi-token": ["PYPI_TOKEN", "TWINE_PASSWORD"],
    "shopify-token": ["SHOPIFY_ACCESS_TOKEN", "shopify_token"],
    "digitalocean-token": ["DIGITALOCEAN_TOKEN", "DO_TOKEN"],
    "databricks-token": ["DATABRICKS_TOKEN", "dbx_token"],
}


def camel(name):
    parts = name.lower().split("_")
    return parts[0] + "".join(p.title() for p in parts[1:]) if len(parts) > 1 else name


# ---------------------------------------------------------------------------
# Contexts: how a value lands in a file. Each returns (path suffix, text).
# ---------------------------------------------------------------------------


def ctx_env(name, v):
    return ".env", f"{name.upper()}={v}"


def ctx_env_quoted(name, v):
    return ".env", f'{name.upper()}="{v}"'


def ctx_shell(name, v):
    return ".sh", f"#!/bin/sh\nset -e\nexport {name.upper()}='{v}'\n./bin/release --env prod"


def ctx_yaml(name, v):
    return ".yaml", f"service:\n  name: billing\n  replicas: 2\n  {name.lower()}: {v}\n  timeout: 30s"


def ctx_json(name, v):
    return ".json", json.dumps({"service": "billing", camel(name): v, "region": "eu-west-1"}, indent=2)


def ctx_python(name, v):
    return ".py", f'import os\n\n{name.upper()} = "{v}"\n\n\ndef client():\n    return Client(token={name.upper()})'


def ctx_js(name, v):
    return ".js", f"const {camel(name)} = '{v}';\n\nmodule.exports = {{ {camel(name)} }};"


def ctx_tf(name, v):
    return ".tf", f'provider "service" {{\n  region = "eu-west-1"\n  {name.lower()} = "{v}"\n}}'


def ctx_ini(name, v):
    return ".ini", f"[default]\nregion = eu-west-1\n{name.lower()} = {v}"


def ctx_docker(name, v):
    return "Dockerfile", f"FROM python:3.12-slim\nENV {name.upper()}={v}\nCMD [\"python\", \"app.py\"]"


def ctx_xml(name, v):
    return ".config", f'<configuration>\n  <appSettings>\n    <add key="{camel(name)}" value="{v}" />\n  </appSettings>\n</configuration>'


def ctx_curl(name, v):
    return ".md", f"## Calling the API\n\n```sh\ncurl -H \"Authorization: Bearer {v}\" https://api.internal/v1/jobs\n```"


def ctx_url(name, v):
    # Credential inside a connection string: no `password=` assignment at all.
    return ".env", f"DATABASE_URL=postgres://app:{v}@db.internal:5432/app"


def ctx_bare(name, v):
    # Pasted in a comment with no variable name.
    return ".py", f"# temporary, remove before merge: {v}\nRETRIES = 3"


CONTEXTS = [ctx_env, ctx_env_quoted, ctx_shell, ctx_yaml, ctx_json, ctx_python, ctx_js, ctx_tf, ctx_ini,
            ctx_docker, ctx_xml]


def ctx_pem_file(name, v):
    return rng.choice([".pem", ".key", "id_rsa"]), v


def ctx_pem_embedded(name, v):
    body = v.replace("\n", "\\n")
    return ".json", json.dumps({"type": "service_account", "client_email": "svc@corp.iam", "private_key": "@@"}, indent=2).replace("@@", body)


def contexts_for(family):
    if family == "private-key":
        return [ctx_pem_file, ctx_pem_file, ctx_pem_embedded, ctx_yaml_block]
    extra = []
    if family in ("jwt", "github-token", "openai-api-key", "anthropic-api-key", "gitlab-pat"):
        extra.append(ctx_curl)
    if family == "generic-password":
        extra += [ctx_url, ctx_url]
    if family not in ("generic-password",):
        extra.append(ctx_bare)
    return CONTEXTS + extra


def ctx_yaml_block(name, v):
    body = "\n".join("    " + line for line in v.splitlines())
    return ".yaml", f"tls:\n  enabled: true\n  key: |\n{body}"


# ---------------------------------------------------------------------------
# Decoys: things that look like secrets but are not.
# ---------------------------------------------------------------------------


def decoys():
    """(category, file suffix, text, value a tool would capture)."""
    out = []
    aws_id = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    aws_secret = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
    out.append(("published-example", ".ini", f"[default]\naws_access_key_id = {aws_id}\naws_secret_access_key = {aws_secret}", aws_id))
    out.append(("published-example", ".md", f"Set `AWS_SECRET_ACCESS_KEY={aws_secret}` as in the AWS docs.", aws_secret))
    jwt_io = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
              "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
              "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    out.append(("published-example", ".md", f"Example token from jwt.io:\n\n    {jwt_io}", jwt_io))
    for v in ["your_api_key_here", "changeme", "<YOUR_TOKEN>", "xxxxxxxxxxxxxxxxxxxxxxxx", "REPLACE_ME_WITH_REAL_KEY",
              "********", "TODO-set-in-vault"]:
        out.append(("placeholder", ".env.example", f"API_KEY={v}\nDB_PASSWORD={v}", v))
    for v in ["${STRIPE_SECRET_KEY}", "process.env.GITHUB_TOKEN", 'os.environ["DB_PASSWORD"]',
              "{{ .Values.apiKey }}", "$(cat /run/secrets/token)", "${{ secrets.NPM_TOKEN }}",
              "secrets.SLACK_WEBHOOK_URL"]:
        out.append(("variable-reference", ".yaml", f"env:\n  api_key: {v}\n  auth_token: {v}", v))
    for _ in range(4):
        h = rs(40, HEX)
        out.append(("git-sha", ".yaml", f"steps:\n  - uses: actions/checkout@{h}\n  - name: cache\n    with:\n      key: deps-{h}", h))
    for _ in range(4):
        h = rs(64, HEX)
        out.append(("content-hash", ".yaml", f"artifact:\n  url: https://cdn.internal/app.tar.gz\n  cache_key: {h}\n  sha256: {h}", h))
    for _ in range(4):
        u = f"{rs(8, HEX)}-{rs(4, HEX)}-4{rs(3, HEX)}-a{rs(3, HEX)}-{rs(12, HEX)}"
        out.append(("uuid-identifier", ".json", json.dumps({"idempotencyKey": u, "requestId": u}, indent=2), u))
    for _ in range(4):
        pub = base64.b64encode(rng.randbytes(32)).decode()
        out.append(("public-key", ".json", json.dumps({"kid": "k1", "publicKey": pub}, indent=2), pub))
    for _ in range(2):
        ssh = "AAAAC3NzaC1lZDI1NTE5AAAAI" + base64.b64encode(rng.randbytes(32)).decode()[:43]
        out.append(("public-key", ".pub", f"ssh-ed25519 {ssh} deploy@ci", ssh))
    for _ in range(2):
        body = base64.b64encode(rng.randbytes(294)).decode()
        pem = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64)) + "\n-----END PUBLIC KEY-----"
        out.append(("public-key", ".pem", pem, pem))
    for _ in range(3):
        pk = f"pk_live_{rs(24)}"
        out.append(("publishable-key", ".env", f"STRIPE_PUBLISHABLE_KEY={pk}", pk))
    for _ in range(2):
        cid = f"{rs(12, DIGITS)}-{rs(32, DIGITS + LOWER)}.apps.googleusercontent.com"
        out.append(("oauth-client-id", ".env", f"GOOGLE_CLIENT_ID={cid}", cid))
    for v in ["ghp_" + "a" * 36, "AKIA" + "X" * 16, "sk_live_" + "0" * 24, "xoxb-" + "0" * 30]:
        out.append(("low-entropy-fixture", ".py", f'FAKE = "{v}"  # used by tests', v))
    for code in ['password = getpass.getpass("Password: ")', 'api_key = request.headers.get("X-Api-Key")',
                 "token = jwt.encode(payload, signing_key, algorithm=\"HS256\")",
                 "secret_key = settings.SECRET_KEY", 'self.auth_token = kwargs.pop("auth_token", None)']:
        val = code.split("=", 1)[1].strip()
        out.append(("code-expression", ".py", code, val))
    for label in [("password", "Password"), ("forgot_password", "Forgot your password?"),
                  ("token_expired", "Your session token has expired"), ("api_key_help", "Find your API key in Settings")]:
        out.append(("ui-string", ".json", json.dumps({label[0]: label[1]}, indent=2), label[1]))
    img = base64.b64encode(rng.randbytes(120)).decode()
    out.append(("data-uri", ".css", f".icon-key {{ background: url(data:image/png;base64,{img}); }}", img))
    sri = "sha384-" + base64.b64encode(rng.randbytes(48)).decode()
    out.append(("sri-hash", ".html", f'<script src="https://cdn.example.net/api-client.min.js" integrity="{sri}" crossorigin="anonymous"></script>', sri))
    return out


def lockfiles():
    """Lockfiles full of hashes. Not labeled individually: any finding is an FP."""
    pkgs = {}
    for i in range(40):
        name = f"pkg-{rs(6, LOWER)}"
        pkgs[f"node_modules/{name}"] = {
            "version": f"1.{i}.0",
            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-1.{i}.0.tgz",
            "integrity": "sha512-" + base64.b64encode(rng.randbytes(64)).decode(),
        }
    lock = json.dumps({"name": "web", "lockfileVersion": 3, "packages": pkgs}, indent=2)
    cargo = "\n".join(
        f'[[package]]\nname = "crate-{rs(5, LOWER)}"\nversion = "0.{i}.1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "{rs(64, HEX)}"\n'
        for i in range(40))
    gosum = "\n".join(f"github.com/corp/mod{i} v1.{i}.0 h1:{base64.b64encode(rng.randbytes(32)).decode()}" for i in range(40))
    return {"web/package-lock.json": lock, "Cargo.lock": cargo, "go.sum": gosum}


# ---------------------------------------------------------------------------
# Filler: ordinary code and config, with the keywords scanners key on.
# ---------------------------------------------------------------------------

FILLER_LINES = [
    "PORT=8080", "LOG_LEVEL=info", "FEATURE_FLAGS=search,billing", "timeout: 30s", "retries: 3",
    "rows.sort(key=lambda r: r.created_at)", "tokens = tokenizer.tokenize(text)",
    "id = Column(Integer, primary_key=True)", 'api_version = "2023-10-16"', "max_tokens: 4096",
    'cache_key = f"user:{user_id}:profile"', "token_type: Bearer", 'password_min_length: 12',
    "auth_mode: oidc", 'secret_name = "prod/db/credentials"', "key_rotation_days: 90",
    'credentials_path = "/etc/app/credentials.json"', "api_base: https://api.internal/v2",
    'access_log = "/var/log/app/access.log"', "keyboard_layout: us", "monkey_patch = True",
]


def filler_file(i):
    kind = rng.choice(["py", "yaml", "env", "js"])
    lines = rng.sample(FILLER_LINES, 8)
    if kind == "py":
        body = [f"def handler_{i}(event):"] + [f"    {l}" for l in lines] + ["    return event"]
    elif kind == "js":
        body = [f"export function handler{i}(event) {{"] + [f"  // {l}" for l in lines] + ["  return event;", "}"]
    else:
        body = lines
    return f"src/mod{i:02d}/handler.{kind}", "\n".join(body) + "\n"


# ---------------------------------------------------------------------------
# Repository construction
# ---------------------------------------------------------------------------


class Repo:
    def __init__(self, path):
        self.path = path
        self.day = 0
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "HOME": str(path)})
        self.env = env
        path.mkdir(parents=True)
        self.git("init", "-q", "--template=", "-b", "main")

    def git(self, *args, author="Dev"):
        t = f"{T0 + self.day * DAY} +0000"
        env = dict(self.env, GIT_AUTHOR_NAME=author, GIT_AUTHOR_EMAIL=f"{author.lower()}@corp.test",
                   GIT_COMMITTER_NAME=author, GIT_COMMITTER_EMAIL=f"{author.lower()}@corp.test",
                   GIT_AUTHOR_DATE=t, GIT_COMMITTER_DATE=t)
        return subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
                              cwd=self.path, env=env, check=True, capture_output=True, text=True).stdout.strip()

    def write(self, rel, content):
        p = self.path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            content = content.encode() if content.endswith("\n") else (content + "\n").encode()
        p.write_bytes(content)

    def remove(self, rel):
        (self.path / rel).unlink()

    def commit(self, msg, author="Dev"):
        self.day += 1
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", msg, author=author)
        return self.git("rev-parse", "HEAD")


SCENARIOS = [  # (scenario, share of in-scope positives)
    ("live_in_head", 0.50), ("deleted_later", 0.25), ("side_branch_only", 0.10),
    ("tag_only", 0.05), ("merge_commit_only", 0.05), ("two_files", 0.05),
]
EDGE_SCENARIOS = ["binary_blob", "blob_over_1mib", "unreachable_commit"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=Path)
    ap.add_argument("--seed", type=int, default=20261009)
    ap.add_argument("--per-family", type=int, default=16)
    ap.add_argument("--out-of-scope-per-family", type=int, default=5)
    args = ap.parse_args()
    if args.out.exists() and any(args.out.iterdir()):
        sys.exit(f"{args.out} is not empty")
    rng.seed(args.seed)

    items = []  # ground truth

    def new_item(kind, category, value, in_scope, scenario):
        item = {"id": f"{kind[0]}{len(items):04d}", "kind": kind, "category": category, "value": value,
                "in_scope": in_scope, "scenario": scenario, "paths": []}
        items.append(item)
        return item

    def placement(item, family):
        name = rng.choice(NAMES.get(family, ["KEY"]))
        suffix, text = rng.choice(contexts_for(family))(name, item["value"])
        stem = rng.choice(["config", "deploy", "settings", "secrets", "app", "local", "ci", "prod"])
        rel = f"{rng.choice(['services/api', 'services/worker', 'infra', 'scripts', 'web', 'ops'])}/{stem}-{item['id']}{suffix if suffix.startswith('.') else '-' + suffix}"
        item["context"] = text.split(item["value"])[0][-40:].strip() or "(file start)"
        return rel, text

    # Positives -----------------------------------------------------------
    scen_names = [s for s, _ in SCENARIOS]
    weights = [w for _, w in SCENARIOS]
    for family, gen in IN_SCOPE.items():
        for i in range(args.per_family):
            # Spread scenarios evenly per family rather than leaving it to chance.
            scenario = scen_names[i % len(scen_names)] if i < len(scen_names) else rng.choices(scen_names, weights)[0]
            new_item("secret", family, gen(), True, scenario)
    for family, gen in OUT_OF_SCOPE.items():
        for _ in range(args.out_of_scope_per_family):
            new_item("secret", family, gen(), False, "live_in_head")
    edge_families = ["aws-access-key-id", "github-token", "slack-token", "stripe-secret-key"]
    for scenario in EDGE_SCENARIOS:
        for fam in edge_families:
            new_item("secret", fam, IN_SCOPE[fam](), True, scenario)

    placed = {}
    for item in items:
        placed[item["id"]] = placement(item, item["category"])

    # Decoys ---------------------------------------------------------------
    decoy_files = []
    for cat, suffix, text, value in decoys():
        item = new_item("decoy", cat, value, None, "live_in_head")
        rel = f"{rng.choice(['docs', 'examples', 'tests/fixtures', 'web', 'config'])}/{cat}-{item['id']}{suffix}"
        decoy_files.append((item, rel, text))

    # Build history ------------------------------------------------------
    repo = Repo(args.out / "repo")
    repo.write("README.md", "# billing platform\n\nInternal services.\n")
    for i in range(30):
        repo.write(*filler_file(i))
    for rel, text in lockfiles().items():
        repo.write(rel, text)
    repo.commit("initial import", author="Alice")

    for item, rel, text in decoy_files:
        repo.write(rel, text)
        item["paths"].append(rel)
    repo.commit("docs, examples and fixtures", author="Bob")

    def by(scenario):
        return [it for it in items if it["kind"] == "secret" and it["scenario"] == scenario]

    authors = ["Alice", "Bob", "Carol", "Dan"]
    # live_in_head, deleted_later, two_files: committed on main in small batches.
    mainline = by("live_in_head") + by("deleted_later") + by("two_files")
    rng.shuffle(mainline)
    for b in range(0, len(mainline), 8):
        for item in mainline[b:b + 8]:
            rel, text = placed[item["id"]]
            repo.write(rel, text)
            item["paths"].append(rel)
            if item["scenario"] == "two_files":
                copy = rel.replace("/", "/backup/", 1)
                repo.write(copy, text)
                item["paths"].append(copy)
        repo.commit(f"config batch {b // 8 + 1}", author=rng.choice(authors))

    for item in by("deleted_later"):
        repo.remove(placed[item["id"]][0])
    repo.commit("remove secrets from config", author="Alice")

    # tag_only: committed on a throwaway branch, tagged, branch deleted.
    repo.git("checkout", "-q", "-b", "release-candidate")
    for item in by("tag_only"):
        rel, text = placed[item["id"]]
        repo.write(rel, text)
        item["paths"].append(rel)
    repo.commit("rc config", author="Carol")
    repo.git("tag", "v0.9.0-rc1")
    repo.git("checkout", "-q", "main")
    repo.git("branch", "-q", "-D", "release-candidate")

    # side_branch_only: on an unmerged feature branch.
    repo.git("checkout", "-q", "-b", "feature/payments")
    for item in by("side_branch_only"):
        rel, text = placed[item["id"]]
        repo.write(rel, text)
        item["paths"].append(rel)
    repo.commit("wip payments", author="Dan")
    repo.git("checkout", "-q", "main")

    # merge_commit_only: content that appears only in a merge commit's tree
    # (an "evil merge": neither parent has it).
    repo.git("checkout", "-q", "-b", "feature/search")
    repo.write("src/search/README.md", "search service\n")
    repo.commit("search scaffold", author="Bob")
    repo.git("checkout", "-q", "main")
    repo.write("CHANGELOG.md", "## unreleased\n- search\n")
    repo.commit("changelog", author="Alice")
    repo.git("merge", "-q", "--no-ff", "--no-commit", "feature/search")
    for item in by("merge_commit_only"):
        rel, text = placed[item["id"]]
        repo.write(rel, text)
        item["paths"].append(rel)
    repo.day += 1
    repo.git("add", "-A")
    repo.git("commit", "-q", "-m", "Merge branch 'feature/search'", author="Bob")
    repo.git("branch", "-q", "-D", "feature/search")

    # Edge cases ------------------------------------------------------------
    for item in by("binary_blob"):
        rel = f"assets/blob-{item['id']}.bin"
        repo.write(rel, b"\x00\x01\x02SQLite format 3\x00" + rng.randbytes(64) + item["value"].encode() + b"\x00" * 16)
        item["paths"].append(rel)
    for item in by("blob_over_1mib"):
        rel = f"data/export-{item['id']}.csv"
        rows = [f"{i},{rs(12)},{rs(20, LOWER)}" for i in range(40_000)]
        rows.insert(20_000, f"20000,{item['value']},token")
        text = "id,ref,name\n" + "\n".join(rows) + "\n"
        assert len(text) > 1_100_000
        repo.write(rel, text)
        item["paths"].append(rel)
    repo.commit("add data exports and assets", author="Carol")

    # unreachable_commit: committed, then reset away. Only the reflog has it.
    for item in by("unreachable_commit"):
        rel, text = placed[item["id"]]
        repo.write(rel, text)
        item["paths"].append(rel)
    repo.commit("oops", author="Dan")
    repo.git("reset", "-q", "--hard", "HEAD~1")

    repo.write("README.md", "# billing platform\n\nInternal services. See docs/.\n")
    repo.commit("docs", author="Alice")

    head = repo.git("rev-parse", "HEAD")
    labels = {"seed": args.seed, "head": head, "generator": "bench/accuracy/gen_corpus.py", "items": items}
    (args.out / "labels.json").write_text(json.dumps(labels, indent=1))
    n_sec = sum(1 for i in items if i["kind"] == "secret")
    print(f"corpus: {args.out / 'repo'} (HEAD {head[:12]}), {n_sec} secrets, {len(items) - n_sec} decoys")


if __name__ == "__main__":
    main()
