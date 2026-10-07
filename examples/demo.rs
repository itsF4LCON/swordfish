//! Builds a small demo repository with a realistic leak story:
//!
//! ```text
//! cargo run --example demo -- /tmp/swordfish-demo
//! swordfish scan /tmp/swordfish-demo
//! ```
//!
//! All secrets are fake and assembled at runtime.

use anyhow::{bail, Result};
use gix::objs::tree::EntryKind;
use gix::refs::transaction::PreviousValue;
use gix::ObjectId;

const DAY: i64 = 86_400;
/// 2025-03-03T09:00:00Z
const T0: i64 = 1_740_992_400;

fn main() -> Result<()> {
    let Some(dir) = std::env::args().nth(1) else {
        bail!("usage: demo <empty-directory>");
    };
    if std::path::Path::new(&dir).join(".git").exists() {
        bail!("{dir} already contains a repository");
    }
    gix::init(&dir)?;
    // Pin the branch name regardless of the system's init.defaultBranch.
    std::fs::write(
        std::path::Path::new(&dir).join(".git/HEAD"),
        "ref: refs/heads/main\n",
    )?;
    let repo = gix::open(&dir)?;

    let aws = format!("{}{}", "AKIA", "Z7Q3VXN2LMP4RT6Y");
    let gh = format!("{}{}", "ghp_", "Xk9mP2qR7sT4vW8yZ1bC3dF6gH0jK5nL2pQ4");
    let env = format!("DATABASE_URL=postgres://localhost/app\nAWS_ACCESS_KEY_ID={aws}\n");
    let deploy = format!("#!/bin/sh\nexport GITHUB_TOKEN={gh}\n./release.sh\n");

    let readme: (&str, &[u8]) = ("README.md", b"# demo app\n");
    let c1 = commit(&repo, &[], &[readme], T0, "Alice")?;
    let c2 = commit(
        &repo,
        &[c1],
        &[readme, (".env", env.as_bytes())],
        T0 + 2 * DAY,
        "Alice",
    )?;
    repo.tag_reference("v1.0.0", c2, PreviousValue::MustNotExist)?;
    let c3 = commit(
        &repo,
        &[c2],
        &[
            readme,
            (".env", env.as_bytes()),
            ("scripts/deploy.sh", deploy.as_bytes()),
        ],
        T0 + 9 * DAY,
        "Bob",
    )?;
    // "Oops" - remove .env, but the tag and history still hold it.
    commit(
        &repo,
        &[c3],
        &[readme, ("scripts/deploy.sh", deploy.as_bytes())],
        T0 + 23 * DAY,
        "Alice",
    )?;
    println!("demo repository written to {dir}");
    Ok(())
}

fn commit(
    repo: &gix::Repository,
    parents: &[ObjectId],
    files: &[(&str, &[u8])],
    time: i64,
    author: &str,
) -> Result<ObjectId> {
    let mut editor = repo.edit_tree(ObjectId::empty_tree(gix::hash::Kind::Sha1))?;
    for (path, content) in files {
        let blob = repo.write_blob(content)?.detach();
        editor.upsert(*path, EntryKind::Blob, blob)?;
    }
    let tree = editor.write()?.detach();
    let email = format!("{}@example.com", author.to_lowercase());
    let time = format!("{time} +0000");
    let sig = gix::actor::SignatureRef {
        name: author.into(),
        email: email.as_str().into(),
        time: &time,
    };
    Ok(repo
        .commit_as(sig, sig, "HEAD", "update", tree, parents.iter().copied())?
        .detach())
}
