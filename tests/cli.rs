//! End-to-end CLI behaviour: exit codes, redaction, formats.

mod common;

use assert_cmd::Command;
use common::*;

fn swordfish() -> Command {
    Command::cargo_bin("swordfish").expect("binary built")
}

fn leaky_repo() -> Fixture {
    let fx = Fixture::new();
    let env = format!("AWS_ACCESS_KEY_ID={}\n", aws_key());
    let c1 = fx.commit("HEAD", &[], &[(".env", env.as_bytes())], T0, "Alice");
    fx.commit("HEAD", &[c1], &[("README.md", b"gone\n")], T0 + DAY, "Bob");
    fx
}

#[test]
fn findings_exit_1_with_redacted_json() {
    let fx = leaky_repo();
    let out = swordfish()
        .args(["scan", "--format", "json"])
        .arg(fx.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(!stdout.contains(&aws_key()));
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["findings"][0]["secret"], "AKIA****");
    assert_eq!(report["findings"][0]["status"], "removed_but_in_history");
    assert_eq!(report["findings"][0]["exposure_days"], 1.0);
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn show_secrets_prints_full_value_and_warns_on_stderr() {
    let fx = leaky_repo();
    let out = swordfish()
        .args(["scan", "--format", "json", "--show-secrets"])
        .arg(fx.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["findings"][0]["secret"], aws_key());
    assert_eq!(report["findings"][0]["redacted"], false);
    assert!(String::from_utf8_lossy(&out.stderr).contains("--show-secrets"));
}

#[test]
fn pretty_output_is_redacted_and_uncoloured_when_piped() {
    let fx = leaky_repo();
    let out = swordfish().arg("scan").arg(fx.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("aws-access-key-id"));
    assert!(stdout.contains("AKIA****"));
    assert!(stdout.contains("REMOVED, BUT STILL IN HISTORY"));
    assert!(stdout.contains(".env:1"));
    assert!(stdout.trim_end().ends_with("See you, space cowboy..."));
    assert!(!stdout.contains(&aws_key()));
    assert!(!stdout.contains('\x1b'), "no ANSI escapes when not a TTY");
}

#[test]
fn clean_repo_exits_0() {
    let fx = Fixture::new();
    fx.commit(
        "HEAD",
        &[],
        &[("README.md", b"nothing to see\n")],
        T0,
        "Alice",
    );
    let out = swordfish().arg("scan").arg(fx.path()).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("No secrets found."));

    let json = swordfish()
        .args(["scan", "--format", "json"])
        .arg(fx.path())
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&json.stdout).contains("space cowboy"));
}

#[test]
fn scanning_from_a_subdirectory_discovers_the_repo() {
    let fx = leaky_repo();
    let sub = fx.path().join("some/dir");
    std::fs::create_dir_all(&sub).unwrap();
    let out = swordfish()
        .args(["scan", "--format", "json"])
        .arg(&sub)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn errors_exit_2() {
    let not_repo = tempfile::tempdir().unwrap();
    let out = swordfish()
        .arg("scan")
        .arg(not_repo.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not inside a git repository"));

    let fx = leaky_repo();
    let bad_rules = fx.path().join("bad.toml");
    std::fs::write(
        &bad_rules,
        "[[rules]]\nid = \"x\"\nregex = '''(unclosed'''\n",
    )
    .unwrap();
    let out = swordfish()
        .arg("scan")
        .arg(fx.path())
        .arg("--rules")
        .arg(&bad_rules)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));

    let out = swordfish()
        .args(["scan", "--format", "xml"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "usage errors are errors too");
}

#[test]
fn scan_does_not_modify_the_repository() {
    let fx = leaky_repo();
    let before = snapshot(fx.path());
    swordfish().arg("scan").arg(fx.path()).output().unwrap();
    assert_eq!(before, snapshot(fx.path()));
}

/// (relative path, length, mtime) of every file under `root`.
fn snapshot(root: &std::path::Path) -> Vec<(String, u64, std::time::SystemTime)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let meta = entry.metadata().unwrap();
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                out.push((
                    entry
                        .path()
                        .strip_prefix(root)
                        .unwrap()
                        .display()
                        .to_string(),
                    meta.len(),
                    meta.modified().unwrap(),
                ));
            }
        }
    }
    out.sort();
    out
}
