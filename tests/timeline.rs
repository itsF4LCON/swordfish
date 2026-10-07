//! Exact timeline assertions on fixture repositories built with gix.

mod common;

use common::*;
use serde_json::json;
use swordfish_git::redact::fingerprint;
use swordfish_git::rules::RuleSet;
use swordfish_git::DEFAULT_MAX_BLOB_SIZE;

const NOW: i64 = T0 + 100 * DAY;

#[test]
fn secret_lifecycle_tags_binary_and_deleted_branch() {
    let fx = Fixture::new();
    let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    png.extend_from_slice(stripe_key().as_bytes()); // must stay invisible: binary
    let env = format!("# prod\nDEBUG=false\nAWS_ACCESS_KEY_ID={}\n", aws_key());
    let app = format!("import os\nTOKEN = \"{}\"\n", github_token());

    let readme: (&str, &[u8]) = ("README.md", b"hello\n");
    let logo: (&str, &[u8]) = ("assets/logo.png", &png);
    let c1 = fx.commit("HEAD", &[], &[readme, logo], T0, "Alice");
    let c2 = fx.commit(
        "HEAD",
        &[c1],
        &[readme, logo, ("config/.env", env.as_bytes())],
        T0 + DAY,
        "Alice",
    );
    fx.tag("v0.1", c2);
    let c3 = fx.commit(
        "HEAD",
        &[c2],
        &[
            readme,
            logo,
            ("config/.env", env.as_bytes()),
            ("app.py", app.as_bytes()),
        ],
        T0 + 2 * DAY,
        "Alice",
    );

    // A branch holding a secret, created and then deleted without merging.
    let pay = format!("const key = '{}';\n", stripe_key());
    fx.commit(
        "refs/heads/feature",
        &[c3],
        &[
            readme,
            logo,
            ("config/.env", env.as_bytes()),
            ("app.py", app.as_bytes()),
            ("pay.js", pay.as_bytes()),
        ],
        T0 + 5 * DAY,
        "Carol",
    );
    fx.delete_ref("refs/heads/feature");

    let c4 = fx.commit(
        "HEAD",
        &[c3],
        &[readme, logo, ("app.py", app.as_bytes())],
        T0 + 31 * DAY,
        "Bob",
    );

    let report = fx.json(NOW);
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["head"], "refs/heads/main");
    assert_eq!(report["stats"]["commits"], 4);
    assert_eq!(report["stats"]["refs"], 2);
    assert_eq!(report["stats"]["skipped_binary"], 1);
    assert_eq!(report["stats"]["findings"], 2);

    let aws = finding(&report, "aws-access-key-id");
    assert_eq!(aws["fingerprint"], fingerprint(aws_key().as_bytes()));
    assert_eq!(aws["secret"], "AKIA****");
    assert_eq!(aws["redacted"], true);
    assert_eq!(aws["status"], "removed_but_in_history");
    assert_eq!(
        aws["introduced"],
        json!({
            "commit": c2.to_string(),
            "author": {"name": "Alice", "email": "alice@example.com"},
            "date": "2024-01-03T10:00:00Z",
            "path": "config/.env",
            "line": 3
        })
    );
    assert_eq!(
        aws["removed"],
        json!({
            "commit": c4.to_string(),
            "author": {"name": "Bob", "email": "bob@example.com"},
            "date": "2024-02-02T10:00:00Z",
            "path": "config/.env"
        })
    );
    assert_eq!(aws["exposure_days"], 30.0);
    assert_eq!(aws["refs"], json!(["refs/heads/main", "refs/tags/v0.1"]));
    assert_eq!(aws["locations"].as_array().unwrap().len(), 1);
    assert_eq!(aws["locations"][0]["path"], "config/.env");
    assert_eq!(aws["locations"][0]["line"], 3);

    let gh = finding(&report, "github-token");
    assert_eq!(gh["status"], "live_in_head");
    assert_eq!(gh["introduced"]["commit"], c3.to_string());
    assert_eq!(gh["introduced"]["path"], "app.py");
    assert_eq!(gh["introduced"]["line"], 2);
    assert_eq!(gh["removed"], serde_json::Value::Null);
    assert_eq!(gh["exposure_days"], 98.0);
    assert_eq!(gh["refs"], json!(["refs/heads/main"]));

    // v0.1 only walks refs: the deleted branch's secret is not reported (v0.2 gap).
    assert!(report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|f| f["rule_id"] != "stripe-secret-key"));

    // Findings are ordered by introduction date.
    assert_eq!(report["findings"][0]["rule_id"], "aws-access-key-id");

    let text = report.to_string();
    assert!(!text.contains(&aws_key()), "full secret leaked into JSON");
    assert!(
        !text.contains(&github_token()),
        "full secret leaked into JSON"
    );
}

#[test]
fn merged_secret_is_introduced_on_its_branch_not_at_the_merge() {
    let fx = Fixture::new();
    let readme: (&str, &[u8]) = ("README.md", b"hi\n");
    let notes: (&str, &[u8]) = ("notes.md", b"notes\n");
    let creds = format!("stripe:\n  key: {}\n", stripe_key());
    let creds: (&str, &[u8]) = ("deploy/creds.yml", creds.as_bytes());

    let m1 = fx.commit("HEAD", &[], &[readme], T0, "Alice");
    let f1 = fx.commit(
        "refs/heads/feature",
        &[m1],
        &[readme, creds],
        T0 + DAY,
        "Dana",
    );
    let m2 = fx.commit("HEAD", &[m1], &[readme, notes], T0 + 2 * DAY, "Alice");
    let merge = fx.commit(
        "HEAD",
        &[m2, f1],
        &[readme, notes, creds],
        T0 + 3 * DAY,
        "Alice",
    );

    let report = fx.json(NOW);
    assert_eq!(report["stats"]["commits"], 4);
    let f = finding(&report, "stripe-secret-key");
    assert_eq!(f["introduced"]["commit"], f1.to_string());
    assert_ne!(f["introduced"]["commit"], merge.to_string());
    assert_eq!(f["introduced"]["author"]["name"], "Dana");
    assert_eq!(f["introduced"]["line"], 2);
    assert_eq!(f["status"], "live_in_head");
    assert_eq!(f["exposure_days"], 99.0);
    assert_eq!(f["refs"], json!(["refs/heads/feature", "refs/heads/main"]));
}

#[test]
fn rename_is_not_a_removal() {
    let fx = Fixture::new();
    let body = format!("key = {}\n", aws_key());
    let c1 = fx.commit(
        "HEAD",
        &[],
        &[("a/creds.txt", body.as_bytes())],
        T0,
        "Alice",
    );
    let c2 = fx.commit(
        "HEAD",
        &[c1],
        &[("b/creds.txt", body.as_bytes())],
        T0 + 10 * DAY,
        "Alice",
    );
    let c3 = fx.commit(
        "HEAD",
        &[c2],
        &[("README.md", b"clean\n")],
        T0 + 20 * DAY,
        "Bob",
    );

    let report = fx.json(NOW);
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    let f = finding(&report, "aws-access-key-id");
    assert_eq!(f["introduced"]["commit"], c1.to_string());
    assert_eq!(f["introduced"]["path"], "a/creds.txt");
    assert_eq!(f["removed"]["commit"], c3.to_string());
    assert_eq!(f["removed"]["path"], "b/creds.txt");
    assert_eq!(f["exposure_days"], 20.0);
    let paths: Vec<&str> = f["locations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, vec!["a/creds.txt", "b/creds.txt"]);
    // Same content at both paths: one blob, scanned once.
    assert_eq!(f["locations"][0]["blob"], f["locations"][1]["blob"]);
}

#[test]
fn secret_only_on_unmerged_branch_tip() {
    let fx = Fixture::new();
    let readme: (&str, &[u8]) = ("README.md", b"hi\n");
    let m1 = fx.commit("HEAD", &[], &[readme], T0, "Alice");
    let token = format!("GH_TOKEN={}\n", github_token());
    fx.commit(
        "refs/heads/wip",
        &[m1],
        &[readme, (".env", token.as_bytes())],
        T0 + 7 * DAY,
        "Eve",
    );

    let report = fx.json(NOW);
    let f = finding(&report, "github-token");
    assert_eq!(f["status"], "removed_but_in_history");
    assert_eq!(f["removed"], serde_json::Value::Null);
    assert_eq!(f["exposure_days"], 93.0);
    assert_eq!(f["refs"], json!(["refs/heads/wip"]));
}

#[test]
fn reintroduced_secret_keeps_first_introduction() {
    let fx = Fixture::new();
    let env = format!("AWS_ACCESS_KEY_ID={}\n", aws_key());
    let c1 = fx.commit("HEAD", &[], &[(".env", env.as_bytes())], T0, "Alice");
    let c2 = fx.commit(
        "HEAD",
        &[c1],
        &[("README.md", b"x\n")],
        T0 + 3 * DAY,
        "Alice",
    );
    let c3 = fx.commit(
        "HEAD",
        &[c2],
        &[(".env", env.as_bytes())],
        T0 + 6 * DAY,
        "Alice",
    );
    fx.commit("HEAD", &[c3], &[("README.md", b"y\n")], T0 + 9 * DAY, "Bob");

    let report = fx.json(NOW);
    let f = finding(&report, "aws-access-key-id");
    assert_eq!(f["introduced"]["commit"], c1.to_string());
    // First removal after the introduction on HEAD's line of history.
    assert_eq!(f["removed"]["commit"], c2.to_string());
    assert_eq!(f["exposure_days"], 3.0);
}

#[test]
fn custom_rules_and_global_path_allowlist() {
    let fx = Fixture::new();
    let sample = format!("AWS_ACCESS_KEY_ID={}\n", aws_key());
    let token = format!("{}{}", "itk_", "q7w8e9r0t1y2u3i4o5p6a7s8");
    let src = format!("const T = \"{token}\";\n");
    fx.commit(
        "HEAD",
        &[],
        &[
            ("fixtures/sample.env", sample.as_bytes()),
            ("src/client.ts", src.as_bytes()),
        ],
        T0,
        "Alice",
    );
    let rules_dir = tempfile::tempdir().unwrap();
    let rules_file = rules_dir.path().join("rules.toml");
    let rules_toml = r#"
        [allowlist]
        paths = ['''^fixtures/''']

        [[rules]]
        id = "internal-token"
        description = "Internal service token"
        regex = '''\b(itk_[a-z0-9]{24})\b'''
        keywords = ["itk_"]
    "#;
    std::fs::write(&rules_file, rules_toml).unwrap();
    let rules = RuleSet::builtin_with_file(&rules_file).unwrap();

    let result = fx.scan_with(rules, DEFAULT_MAX_BLOB_SIZE, NOW);
    let report = json_of(&result, NOW);
    assert_eq!(
        report["findings"].as_array().unwrap().len(),
        1,
        "{report:#}"
    );
    let f = finding(&report, "internal-token");
    assert_eq!(f["description"], "Internal service token");
    assert_eq!(f["secret"], "itk_****");
    assert_eq!(report["stats"]["skipped_allowlisted"], 1);
}

#[test]
fn oversized_blobs_are_skipped_and_counted() {
    let fx = Fixture::new();
    let mut big = format!("AWS_ACCESS_KEY_ID={}\n", aws_key()).into_bytes();
    big.resize(4096, b'#');
    fx.commit("HEAD", &[], &[("dump.sql", &big)], T0, "Alice");

    let report = json_of(&fx.scan_with(RuleSet::builtin(), 1024, NOW), NOW);
    assert_eq!(report["stats"]["skipped_too_large"], 1);
    assert_eq!(report["stats"]["scanned_blobs"], 0);
    assert!(report["findings"].as_array().unwrap().is_empty());

    let report = json_of(&fx.scan_with(RuleSet::builtin(), 8192, NOW), NOW);
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
}

#[test]
fn empty_repository_has_no_findings() {
    let fx = Fixture::new();
    let report = fx.json(NOW);
    assert_eq!(report["head"], "refs/heads/main");
    assert_eq!(report["stats"]["commits"], 0);
    assert!(report["findings"].as_array().unwrap().is_empty());
}
