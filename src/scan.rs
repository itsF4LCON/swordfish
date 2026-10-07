//! The scan pipeline: walk → diff → dedupe → detect (parallel) → timeline.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{Context, Result};
use gix::bstr::BString;
use gix::ObjectId;
use rayon::prelude::*;

use crate::detect::{BlobScan, Detector};
use crate::history::{self, Graph, TreeDiffer};
use crate::rules::RuleSet;
use crate::timeline::{self, Finding, Hit, Interned, SecretDef};

/// Default `--max-blob-size`: 1 MiB.
pub const DEFAULT_MAX_BLOB_SIZE: u64 = 1024 * 1024;

/// Commits diffed per parallel batch before interning (bounds peak memory).
const DIFF_BATCH: usize = 2048;
/// Per-thread object cache; trees are re-read across neighbouring commits.
const OBJECT_CACHE_BYTES: usize = 32 * 1024 * 1024;

pub struct ScanOptions {
    pub path: PathBuf,
    pub rules: RuleSet,
    pub max_blob_size: u64,
    /// "Now" for exposure of secrets that were never removed (Unix seconds).
    /// Injected so results are reproducible in tests.
    pub now: i64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stats {
    pub refs: usize,
    pub commits: usize,
    pub unique_blobs: usize,
    pub scanned_blobs: usize,
    pub skipped_binary: usize,
    pub skipped_too_large: usize,
    pub skipped_allowlisted: usize,
    pub skipped_missing: usize,
    pub elapsed_ms: u128,
}

pub struct ScanResult {
    pub repository: PathBuf,
    pub head: Option<String>,
    /// Earliest committer time in the scanned history.
    pub history_start: Option<i64>,
    pub stats: Stats,
    pub findings: Vec<Finding>,
    pub rules: RuleSet,
    pub warnings: Vec<String>,
}

enum BlobOutcome {
    NotNeeded,
    Binary,
    TooLarge,
    Missing,
    Hits(Vec<crate::detect::RawHit>),
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

pub fn scan(opts: ScanOptions) -> Result<ScanResult> {
    let started = Instant::now();
    let repo = open_repo(&opts.path)?;
    let repository = repo
        .workdir()
        .unwrap_or_else(|| repo.git_dir())
        .to_path_buf();
    let repository = repository.canonicalize().unwrap_or(repository);

    let graph = history::load_graph(&repo)?;
    let shared = repo.into_sync();
    let missing = AtomicUsize::new(0);

    let interned = diff_all(&shared, &graph, &missing)?;

    // Blobs only ever seen at globally allowlisted paths are never read.
    let path_ok: Vec<bool> = interned
        .paths
        .iter()
        .map(|p| !opts.rules.path_globally_allowlisted(p))
        .collect();
    let mut needed = vec![false; interned.blobs.len()];
    for changes in &interned.changes {
        for &(path, blob) in changes {
            if let Some(b) = blob {
                needed[b as usize] |= path_ok[path as usize];
            }
        }
    }

    let detector = Detector::new(opts.rules);
    let max = opts.max_blob_size;
    let outcomes: Vec<BlobOutcome> = interned
        .blobs
        .par_iter()
        .zip(needed.par_iter())
        .map_init(
            || thread_repo(&shared),
            |repo, (&id, &needed)| {
                if !needed {
                    return BlobOutcome::NotNeeded;
                }
                scan_blob(repo, &detector, id, max)
            },
        )
        .collect();

    let mut stats = Stats {
        refs: graph.ref_count(),
        commits: graph.commits.len(),
        unique_blobs: interned.blobs.len(),
        ..Stats::default()
    };
    let mut secret_index: HashMap<Vec<u8>, u32> = HashMap::new();
    let mut secrets: Vec<SecretDef> = Vec::new();
    let mut blob_hits: Vec<Vec<Hit>> = Vec::with_capacity(outcomes.len());
    for outcome in outcomes {
        let mut hits = Vec::new();
        match outcome {
            BlobOutcome::NotNeeded => stats.skipped_allowlisted += 1,
            BlobOutcome::Binary => stats.skipped_binary += 1,
            BlobOutcome::TooLarge => stats.skipped_too_large += 1,
            BlobOutcome::Missing => stats.skipped_missing += 1,
            BlobOutcome::Hits(raw) => {
                stats.scanned_blobs += 1;
                for h in raw {
                    let id = *secret_index.entry(h.secret.clone()).or_insert_with(|| {
                        secrets.push(SecretDef {
                            value: h.secret,
                            rule: h.rule,
                        });
                        (secrets.len() - 1) as u32
                    });
                    let def = &mut secrets[id as usize];
                    def.rule = def.rule.min(h.rule);
                    // One hit per secret per blob: the first line it appears on.
                    match hits.iter_mut().find(|x: &&mut Hit| x.secret == id) {
                        Some(existing) => existing.line = existing.line.min(h.line),
                        None => hits.push(Hit {
                            secret: id,
                            rule: h.rule,
                            line: h.line,
                        }),
                    }
                }
            }
        }
        blob_hits.push(hits);
    }
    stats.skipped_missing += missing.load(Ordering::Relaxed) + graph.missing_parents;

    let rules = detector.rules().clone();
    let mut findings = timeline::build(&graph, &interned, &blob_hits, &secrets, &rules, opts.now);
    findings.sort_by(|a, b| {
        a.introduced.time.cmp(&b.introduced.time).then_with(|| {
            crate::redact::fingerprint(&a.secret).cmp(&crate::redact::fingerprint(&b.secret))
        })
    });

    let mut warnings = rules.warnings.clone();
    warnings.extend(graph.warnings.iter().cloned());
    stats.elapsed_ms = started.elapsed().as_millis();
    Ok(ScanResult {
        repository,
        head: graph.head_name.clone(),
        history_start: graph.commits.iter().map(|c| c.time).min(),
        stats,
        findings,
        rules,
        warnings,
    })
}

/// Open read-only and isolated: no global/system config, no hooks, no env overrides.
fn open_repo(path: &Path) -> Result<gix::Repository> {
    gix::discover_opts(path, Default::default(), gix::open::Options::isolated())
        .with_context(|| format!("{} is not inside a git repository", path.display()))
}

fn thread_repo(shared: &gix::ThreadSafeRepository) -> gix::Repository {
    let mut repo = shared.to_thread_local();
    repo.object_cache_size_if_unset(OBJECT_CACHE_BYTES);
    repo
}

fn diff_all(
    shared: &gix::ThreadSafeRepository,
    graph: &Graph,
    missing: &AtomicUsize,
) -> Result<Interned> {
    let mut interned = Interned {
        changes: Vec::with_capacity(graph.commits.len()),
        ..Interned::default()
    };
    let mut path_ids: HashMap<BString, u32> = HashMap::new();
    let mut blob_ids: HashMap<ObjectId, u32> = HashMap::new();

    for batch in graph.commits.chunks(DIFF_BATCH) {
        let diffs: Vec<Vec<history::Change>> = batch
            .par_iter()
            .map_init(
                || thread_repo(shared),
                |repo, commit| {
                    let parent_tree = commit
                        .parents
                        .first()
                        .map(|&p| graph.commits[p as usize].tree);
                    TreeDiffer::new(repo, missing).diff(parent_tree, commit.tree)
                },
            )
            .collect::<Result<_>>()?;
        for diff in diffs {
            let mut changes: Vec<(u32, Option<u32>)> = diff
                .into_iter()
                .map(|ch| {
                    let next_path = path_ids.len() as u32;
                    let path = *path_ids.entry(ch.path).or_insert(next_path);
                    if path == next_path {
                        interned.paths.push(BString::default());
                    }
                    let blob = ch.blob.map(|oid| {
                        let next_blob = blob_ids.len() as u32;
                        *blob_ids.entry(oid).or_insert_with(|| {
                            interned.blobs.push(oid);
                            next_blob
                        })
                    });
                    (path, blob)
                })
                .collect();
            changes.sort_unstable_by_key(|c| c.0);
            interned.changes.push(changes);
        }
    }
    for (path, id) in path_ids {
        interned.paths[id as usize] = path;
    }
    Ok(interned)
}

fn scan_blob(repo: &gix::Repository, detector: &Detector, id: ObjectId, max: u64) -> BlobOutcome {
    match repo.find_header(id) {
        Ok(header) if header.size() > max => return BlobOutcome::TooLarge,
        Ok(_) => {}
        Err(_) => return BlobOutcome::Missing,
    }
    let object = match repo.find_object(id) {
        Ok(o) => o,
        Err(_) => return BlobOutcome::Missing,
    };
    match detector.scan(&object.data) {
        BlobScan::Binary => BlobOutcome::Binary,
        BlobScan::Hits(h) => BlobOutcome::Hits(h),
    }
}
