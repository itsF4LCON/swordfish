//! Turns per-blob hits into per-secret exposure timelines.
//!
//! See ROADMAP.md §3 for the exact definitions implemented here. The core idea:
//! walk commits in topological order and carry, per commit, the small set of
//! secret-bearing `(path, blob)` entries in its tree. That set is derived from
//! the first parent plus the first-parent diff and is `Arc`-shared when
//! unchanged, so clean history costs nothing.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Arc;

use gix::bstr::BString;
use gix::ObjectId;
use rayon::prelude::*;

use crate::history::Graph;
use crate::rules::RuleSet;

/// A secret hit inside one unique blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    pub secret: u32,
    pub rule: usize,
    pub line: u32,
}

/// Interned history: every path and blob gets a dense id.
#[derive(Debug, Default)]
pub struct Interned {
    pub paths: Vec<BString>,
    pub blobs: Vec<ObjectId>,
    /// Per commit (indexed like `Graph::commits`): first-parent changes,
    /// sorted by path id. `None` blob = path removed.
    pub changes: Vec<Vec<(u32, Option<u32>)>>,
}

/// A distinct secret value.
#[derive(Debug, Clone)]
pub struct SecretDef {
    pub value: Vec<u8>,
    /// Lowest (most specific) rule index that matched it.
    pub rule: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    LiveInHead,
    RemovedButInHistory,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub commit: ObjectId,
    pub author_name: String,
    pub author_email: String,
    pub time: i64,
    pub path: String,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Location {
    pub path: String,
    pub blob: ObjectId,
    pub line: u32,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub secret: Vec<u8>,
    pub rule: usize,
    pub status: Status,
    pub introduced: Event,
    pub removed: Option<Event>,
    pub exposure_days: f64,
    pub refs: Vec<String>,
    pub locations: Vec<Location>,
}

/// Commit-level timeline of one secret, before resolving ids to names.
struct Timeline {
    secret: usize,
    intro: u32,
    /// (removing commit, parent that still held the secret)
    removed: Option<(u32, u32)>,
    refs: Vec<String>,
    status: Status,
}

type Entries = Arc<Vec<(u32, u32)>>;
type Secrets = Arc<Vec<u32>>;

struct Ctx<'a> {
    interned: &'a Interned,
    blob_hits: &'a [Vec<Hit>],
    rules: &'a RuleSet,
    allowed: HashMap<(u32, usize), bool>,
}

impl Ctx<'_> {
    /// Whether a hit of `rule` may be reported at `path`.
    fn allowed(&mut self, path: u32, rule: usize) -> bool {
        let rules = self.rules;
        let paths = &self.interned.paths;
        *self.allowed.entry((path, rule)).or_insert_with(|| {
            let p = paths[path as usize].as_slice();
            rules.rules[rule].applies_to_path(p) && !rules.path_globally_allowlisted(p)
        })
    }

    /// Hits of `blob` that count at `path`.
    fn hits_at(&mut self, path: u32, blob: u32) -> Vec<Hit> {
        let hits = &self.blob_hits[blob as usize];
        let mut out = Vec::with_capacity(hits.len());
        for &h in hits {
            if self.allowed(path, h.rule) {
                out.push(h);
            }
        }
        out
    }
}

pub fn build(
    graph: &Graph,
    interned: &Interned,
    blob_hits: &[Vec<Hit>],
    secrets: &[SecretDef],
    rules: &RuleSet,
    now: i64,
) -> Vec<Finding> {
    if secrets.is_empty() || graph.commits.is_empty() {
        return Vec::new();
    }
    let n = graph.commits.len();
    let mut ctx = Ctx {
        interned,
        blob_hits,
        rules,
        allowed: HashMap::new(),
    };

    // 1. Propagate secret-bearing entries and present secrets along topo order.
    let empty_entries: Entries = Arc::new(Vec::new());
    let empty_secrets: Secrets = Arc::new(Vec::new());
    let mut entries: Vec<Entries> = vec![empty_entries.clone(); n];
    let mut present: Vec<Secrets> = vec![empty_secrets.clone(); n];
    let bearing = |blob: u32| !blob_hits[blob as usize].is_empty();

    for &c in &graph.topo {
        let c = c as usize;
        let fp = graph.commits[c].parents.first().map(|&p| p as usize);
        let (base_entries, base_secrets) = match fp {
            Some(p) => (entries[p].clone(), present[p].clone()),
            None => (empty_entries.clone(), empty_secrets.clone()),
        };
        let changes = &interned.changes[c];
        let touches_path = |path: u32| changes.binary_search_by_key(&path, |ch| ch.0).is_ok();
        let touched = base_entries.iter().any(|&(path, _)| touches_path(path));
        let has_new = changes.iter().any(|&(_, blob)| blob.is_some_and(bearing));
        if !touched && !has_new {
            entries[c] = base_entries;
            present[c] = base_secrets;
            continue;
        }
        let mut next: Vec<(u32, u32)> = base_entries
            .iter()
            .copied()
            .filter(|&(path, _)| !touches_path(path))
            .collect();
        next.extend(
            changes
                .iter()
                .filter_map(|&(path, blob)| blob.filter(|&b| bearing(b)).map(|b| (path, b))),
        );
        next.sort_unstable();
        let mut ids: Vec<u32> = Vec::new();
        for &(path, blob) in &next {
            ids.extend(ctx.hits_at(path, blob).iter().map(|h| h.secret));
        }
        ids.sort_unstable();
        ids.dedup();
        entries[c] = Arc::new(next);
        present[c] = if ids == *base_secrets {
            base_secrets
        } else {
            Arc::new(ids)
        };
    }

    // 2. Add/remove events and locations.
    let n_secrets = secrets.len();
    let mut adds: Vec<Vec<u32>> = vec![Vec::new(); n_secrets];
    let mut removes: Vec<Vec<(u32, u32)>> = vec![Vec::new(); n_secrets]; // (commit, parent)
    let mut locations: Vec<BTreeSet<(u32, u32, u32)>> = vec![BTreeSet::new(); n_secrets];
    for &c in &graph.topo {
        let ci = c as usize;
        let parents = &graph.commits[ci].parents;
        let fp = parents.first().map(|&p| p as usize);
        let entries_changed = fp.is_none_or(|p| !Arc::ptr_eq(&entries[ci], &entries[p]));
        if entries_changed {
            for &(path, blob) in entries[ci].iter() {
                for h in ctx.hits_at(path, blob) {
                    locations[h.secret as usize].insert((path, blob, h.line));
                }
            }
        }
        let single_unchanged =
            parents.len() == 1 && Arc::ptr_eq(&present[ci], &present[parents[0] as usize]);
        if single_unchanged {
            continue;
        }
        let here = &present[ci];
        for &s in here.iter() {
            let inherited = parents
                .iter()
                .any(|&p| present[p as usize].binary_search(&s).is_ok());
            if !inherited {
                adds[s as usize].push(c);
            }
        }
        for &p in parents {
            for &s in present[p as usize].iter() {
                if here.binary_search(&s).is_err()
                    && removes[s as usize].last().is_none_or(|&(rc, _)| rc != c)
                {
                    removes[s as usize].push((c, p));
                }
            }
        }
    }

    // 3. Reachability helpers shared by all secrets.
    let head_ancestors = graph.head.map(|h| ancestors(graph, h));
    let order_key = |c: u32| (graph.commits[c as usize].time, graph.topo_pos[c as usize]);

    // 4. Per-secret timelines (independent; parallel).
    let per_secret: Vec<Option<Timeline>> = (0..n_secrets)
        .into_par_iter()
        .map(|s| {
            let intro = *adds[s].iter().min_by_key(|&&c| order_key(c))?;
            let live = graph
                .head
                .is_some_and(|h| present[h as usize].binary_search(&(s as u32)).is_ok());
            let removed = if live {
                None
            } else {
                let after_intro = descendants(graph, &[intro]);
                let candidates: Vec<(u32, u32)> = removes[s]
                    .iter()
                    .copied()
                    .filter(|&(c, _)| after_intro[c as usize])
                    .collect();
                let on_head_line: Vec<(u32, u32)> = match &head_ancestors {
                    Some(anc) => candidates
                        .iter()
                        .copied()
                        .filter(|&(c, _)| anc[c as usize])
                        .collect(),
                    None => Vec::new(),
                };
                let pool = if on_head_line.is_empty() {
                    candidates
                } else {
                    on_head_line
                };
                pool.into_iter().min_by_key(|&(c, _)| order_key(c))
            };
            let reach = descendants(graph, &adds[s]);
            let refs = graph
                .tips
                .iter()
                .filter(|t| reach[t.commit as usize])
                .map(|t| t.name.clone())
                .collect();
            let status = if live {
                Status::LiveInHead
            } else {
                Status::RemovedButInHistory
            };
            Some(Timeline {
                secret: s,
                intro,
                removed,
                refs,
                status,
            })
        })
        .collect();

    // 5. Resolve commits, paths and lines into findings.
    let mut findings = Vec::new();
    for t in per_secret.into_iter().flatten() {
        let Timeline {
            secret: s,
            intro,
            removed,
            refs,
            status,
        } = t;
        let secret_id = s as u32;
        let changes = &interned.changes[intro as usize];
        let intro_entry = entries[intro as usize]
            .iter()
            .copied()
            .filter(|&(path, blob)| {
                ctx.hits_at(path, blob)
                    .iter()
                    .any(|h| h.secret == secret_id)
            })
            .min_by_key(|&(path, _)| {
                // Prefer a path the commit actually changed.
                (
                    changes.binary_search_by_key(&path, |ch| ch.0).is_err(),
                    path,
                )
            })
            .expect("an add event implies the secret is present");
        let intro_line = ctx
            .hits_at(intro_entry.0, intro_entry.1)
            .iter()
            .find(|h| h.secret == secret_id)
            .map(|h| h.line);
        let introduced = event(graph, interned, intro, intro_entry.0, intro_line);

        let removed = removed.map(|(c, parent)| {
            let path = entries[parent as usize]
                .iter()
                .copied()
                .find(|&(path, blob)| {
                    ctx.hits_at(path, blob)
                        .iter()
                        .any(|h| h.secret == secret_id)
                })
                .map(|(path, _)| path)
                .expect("a remove event implies the parent held the secret");
            event(graph, interned, c, path, None)
        });

        let end = removed.as_ref().map_or(now, |r| r.time);
        let exposure_days =
            ((end - introduced.time).max(0) as f64 / 86_400.0 * 100.0).round() / 100.0;

        let mut locs: Vec<Location> = locations[s]
            .iter()
            .map(|&(path, blob, line)| Location {
                path: path_string(interned, path),
                blob: interned.blobs[blob as usize],
                line,
            })
            .collect();
        locs.sort();

        findings.push(Finding {
            secret: secrets[s].value.clone(),
            rule: secrets[s].rule,
            status,
            introduced,
            removed,
            exposure_days,
            refs,
            locations: locs,
        });
    }
    findings
}

fn event(graph: &Graph, interned: &Interned, commit: u32, path: u32, line: Option<u32>) -> Event {
    let c = &graph.commits[commit as usize];
    Event {
        commit: c.id,
        author_name: c.author_name.clone(),
        author_email: c.author_email.clone(),
        time: c.time,
        path: path_string(interned, path),
        line,
    }
}

fn path_string(interned: &Interned, path: u32) -> String {
    String::from_utf8_lossy(&interned.paths[path as usize]).into_owned()
}

/// Commits reachable from `start` (inclusive) via child edges.
fn descendants(graph: &Graph, start: &[u32]) -> Vec<bool> {
    let mut seen = vec![false; graph.commits.len()];
    let mut queue: VecDeque<u32> = VecDeque::new();
    for &s in start {
        if !seen[s as usize] {
            seen[s as usize] = true;
            queue.push_back(s);
        }
    }
    while let Some(c) = queue.pop_front() {
        for &child in &graph.children[c as usize] {
            if !seen[child as usize] {
                seen[child as usize] = true;
                queue.push_back(child);
            }
        }
    }
    seen
}

/// Commits reachable from `start` (inclusive) via parent edges.
fn ancestors(graph: &Graph, start: u32) -> Vec<bool> {
    let mut seen = vec![false; graph.commits.len()];
    let mut stack = vec![start];
    seen[start as usize] = true;
    while let Some(c) = stack.pop() {
        for &p in &graph.commits[c as usize].parents {
            if !seen[p as usize] {
                seen[p as usize] = true;
                stack.push(p);
            }
        }
    }
    seen
}
