//! Fixture repositories built at test time with gix (no `git` binary needed).
#![allow(dead_code)] // each test crate uses a different subset

use std::path::Path;

use gix::objs::tree::EntryKind;
use gix::refs::transaction::{Change, PreviousValue, RefEdit, RefLog};
use gix::ObjectId;
use swordfish_git::report::Report;
use swordfish_git::rules::RuleSet;
use swordfish_git::{ScanOptions, ScanResult, DEFAULT_MAX_BLOB_SIZE};

pub const DAY: i64 = 86_400;
/// 2024-01-02T10:00:00Z
pub const T0: i64 = 1_704_189_600;

// Secrets are assembled at runtime so this repository never contains them
// verbatim (keeps swordfish, gitleaks and push protection quiet on ourselves).
pub fn aws_key() -> String {
    format!("{}{}", "AKIA", "Z7Q3VXN2LMP4RT6Y")
}
pub fn github_token() -> String {
    format!("{}{}", "ghp_", "Xk9mP2qR7sT4vW8yZ1bC3dF6gH0jK5nL2pQ4")
}
pub fn stripe_key() -> String {
    format!("{}{}", "sk_live_", "4eC39HqLyjWDarjtT1zdp7dc")
}

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub repo: gix::Repository,
}

impl Fixture {
    /// A fresh repository whose HEAD points at `refs/heads/main`.
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let repo = gix::init(dir.path()).expect("init");
        Fixture { dir, repo }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Commit a full snapshot of `files` to `reference` (created or advanced).
    pub fn commit(
        &self,
        reference: &str,
        parents: &[ObjectId],
        files: &[(&str, &[u8])],
        time: i64,
        author: &str,
    ) -> ObjectId {
        let mut editor = self
            .repo
            .edit_tree(ObjectId::empty_tree(gix::hash::Kind::Sha1))
            .expect("tree editor");
        for (path, content) in files {
            let blob = self.repo.write_blob(content).expect("write blob").detach();
            editor.upsert(*path, EntryKind::Blob, blob).expect("upsert");
        }
        let tree = editor.write().expect("write tree").detach();
        let email = format!("{}@example.com", author.to_lowercase());
        let time = format!("{time} +0000");
        let sig = gix::actor::SignatureRef {
            name: author.into(),
            email: email.as_str().into(),
            time: &time,
        };
        self.repo
            .commit_as(
                sig,
                sig,
                reference,
                format!("commit by {author}"),
                tree,
                parents.iter().copied(),
            )
            .expect("commit")
            .detach()
    }

    pub fn tag(&self, name: &str, target: ObjectId) {
        self.repo
            .tag_reference(name, target, PreviousValue::MustNotExist)
            .expect("tag");
    }

    pub fn delete_ref(&self, name: &str) {
        self.repo
            .edit_reference(RefEdit {
                change: Change::Delete {
                    expected: PreviousValue::MustExist,
                    log: RefLog::AndReference,
                },
                name: name.try_into().expect("ref name"),
                deref: false,
            })
            .expect("delete ref");
    }

    pub fn scan_with(&self, rules: RuleSet, max_blob_size: u64, now: i64) -> ScanResult {
        swordfish_git::scan(ScanOptions {
            path: self.path().to_path_buf(),
            rules,
            max_blob_size,
            now,
        })
        .expect("scan")
    }

    pub fn scan(&self, now: i64) -> ScanResult {
        self.scan_with(RuleSet::builtin(), DEFAULT_MAX_BLOB_SIZE, now)
    }

    /// JSON report (schema v1) as a value, secrets redacted.
    pub fn json(&self, now: i64) -> serde_json::Value {
        json_of(&self.scan(now), now)
    }
}

pub fn json_of(result: &ScanResult, now: i64) -> serde_json::Value {
    serde_json::from_str(&Report::new(result, false, now).to_json()).expect("valid json")
}

pub fn finding<'a>(report: &'a serde_json::Value, rule_id: &str) -> &'a serde_json::Value {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule_id"] == rule_id)
        .unwrap_or_else(|| panic!("no {rule_id} finding in {report:#}"))
}
