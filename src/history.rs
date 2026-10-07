//! Commit graph loading, topological ordering and first-parent tree diffs.
//!
//! Everything here is read-only: objects and refs are looked up, never written.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use gix::bstr::{BString, ByteSlice};
use gix::ObjectId;

/// A named starting point of the walk.
#[derive(Debug, Clone)]
pub struct Tip {
    pub name: String,
    pub commit: u32,
}

#[derive(Debug, Clone)]
pub struct CommitNode {
    pub id: ObjectId,
    pub tree: ObjectId,
    /// Parent indices into [`Graph::commits`]; parents missing from the odb
    /// (shallow clones) are dropped.
    pub parents: Vec<u32>,
    /// Committer time, seconds since the Unix epoch.
    pub time: i64,
    pub author_name: String,
    pub author_email: String,
}

#[derive(Debug, Default)]
pub struct Graph {
    pub commits: Vec<CommitNode>,
    /// Parents before children; ties broken by committer time, then load order.
    pub topo: Vec<u32>,
    /// `topo_pos[c]` is the position of commit `c` in [`Graph::topo`].
    pub topo_pos: Vec<u32>,
    pub children: Vec<Vec<u32>>,
    /// Every ref under `refs/` that peels to a commit, plus `HEAD` if detached.
    pub tips: Vec<Tip>,
    pub head: Option<u32>,
    /// Symbolic target of HEAD (`refs/heads/main`), `HEAD` if detached, `None` if unborn.
    pub head_name: Option<String>,
    pub missing_parents: usize,
    pub warnings: Vec<String>,
}

impl Graph {
    /// Number of distinct ref names, excluding a detached `HEAD` pseudo-tip.
    pub fn ref_count(&self) -> usize {
        self.tips.iter().filter(|t| t.name != "HEAD").count()
    }
}

/// Enumerate tips and load every commit reachable from them.
pub fn load_graph(repo: &gix::Repository) -> Result<Graph> {
    let mut graph = Graph::default();
    let mut tip_ids: Vec<(String, ObjectId)> = Vec::new();

    let platform = repo.references().context("cannot read references")?;
    for reference in platform.all().context("cannot iterate references")? {
        let mut reference = match reference {
            Ok(r) => r,
            Err(e) => {
                graph.warnings.push(format!("skipping unreadable ref: {e}"));
                continue;
            }
        };
        let name = reference.name().as_bstr().to_string();
        match reference.peel_to_commit() {
            Ok(commit) => tip_ids.push((name, commit.id)),
            // Tags of trees/blobs and dangling refs carry no history to walk.
            Err(e) => graph.warnings.push(format!(
                "skipping ref {name}: does not peel to a commit ({e})"
            )),
        }
    }

    let head = repo.head().context("cannot read HEAD")?;
    let head_ref_name = head.referent_name().map(|n| n.as_bstr().to_string());
    let head_id = match repo.head_id() {
        Ok(id) => Some(id.detach()),
        Err(_) => None, // unborn HEAD
    };
    graph.head_name = match (&head_ref_name, head_id) {
        (Some(name), _) => Some(name.clone()),
        (None, Some(_)) => Some("HEAD".to_string()),
        (None, None) => None,
    };
    if let (None, Some(id)) = (&head_ref_name, head_id) {
        tip_ids.push(("HEAD".to_string(), id));
    }
    if let (Some(name), Some(id)) = (&head_ref_name, head_id) {
        // A symbolic HEAD normally points at a ref we already have; cover odd setups.
        if !tip_ids.iter().any(|(n, _)| n == name) {
            tip_ids.push((name.clone(), id));
        }
    }

    // Breadth-first load of all reachable commits.
    let mut index: HashMap<ObjectId, u32> = HashMap::new();
    let mut parent_ids: Vec<Vec<ObjectId>> = Vec::new();
    let mut queue: Vec<ObjectId> = tip_ids.iter().map(|(_, id)| *id).collect();
    while let Some(id) = queue.pop() {
        if index.contains_key(&id) {
            continue;
        }
        let commit = match repo.find_commit(id) {
            Ok(c) => c,
            Err(_) => {
                graph.missing_parents += 1;
                continue;
            }
        };
        let decoded = commit
            .decode()
            .map_err(|e| anyhow::anyhow!("cannot decode commit {id}: {e}"))?;
        let committer = decoded
            .committer()
            .map_err(|e| anyhow::anyhow!("commit {id}: bad committer: {e}"))?;
        let author = decoded
            .author()
            .map_err(|e| anyhow::anyhow!("commit {id}: bad author: {e}"))?;
        let time = committer.seconds();
        let parents: Vec<ObjectId> = decoded.parents().collect();
        queue.extend(parents.iter().copied());
        index.insert(id, graph.commits.len() as u32);
        parent_ids.push(parents);
        graph.commits.push(CommitNode {
            id,
            tree: decoded.tree(),
            parents: Vec::new(),
            time,
            author_name: author.name.trim().to_str_lossy().into_owned(),
            author_email: author.email.trim().to_str_lossy().into_owned(),
        });
    }

    for (node, parents) in graph.commits.iter_mut().zip(parent_ids) {
        node.parents = parents
            .iter()
            .filter_map(|p| index.get(p).copied())
            .collect();
    }

    for (name, id) in tip_ids {
        if let Some(&commit) = index.get(&id) {
            graph.tips.push(Tip { name, commit });
        }
    }
    graph.tips.sort_by(|a, b| a.name.cmp(&b.name));
    graph.tips.dedup_by(|a, b| a.name == b.name);
    graph.head = head_id.and_then(|id| index.get(&id).copied());

    topo_sort(&mut graph);
    Ok(graph)
}

/// Kahn's algorithm, parents first, earliest committer time first among ready commits.
fn topo_sort(graph: &mut Graph) {
    let n = graph.commits.len();
    let mut children = vec![Vec::new(); n];
    let mut pending: Vec<usize> = vec![0; n];
    for (idx, c) in graph.commits.iter().enumerate() {
        // Duplicate parent entries (rare, but legal) count once.
        let mut ps = c.parents.clone();
        ps.sort_unstable();
        ps.dedup();
        pending[idx] = ps.len();
        for p in ps {
            children[p as usize].push(idx as u32);
        }
    }
    let mut ready: BinaryHeap<Reverse<(i64, u32)>> = graph
        .commits
        .iter()
        .enumerate()
        .filter(|(i, _)| pending[*i] == 0)
        .map(|(i, c)| Reverse((c.time, i as u32)))
        .collect();
    let mut topo = Vec::with_capacity(n);
    while let Some(Reverse((_, idx))) = ready.pop() {
        topo.push(idx);
        for &child in &children[idx as usize] {
            let p = &mut pending[child as usize];
            *p -= 1;
            if *p == 0 {
                ready.push(Reverse((graph.commits[child as usize].time, child)));
            }
        }
    }
    debug_assert_eq!(topo.len(), n, "commit graph must be acyclic");
    let mut topo_pos = vec![0u32; n];
    for (pos, &idx) in topo.iter().enumerate() {
        topo_pos[idx as usize] = pos as u32;
    }
    graph.topo = topo;
    graph.topo_pos = topo_pos;
    graph.children = children;
}

/// A file-level change of a commit relative to its first parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub path: BString,
    /// New blob at `path`, or `None` if the path no longer holds a regular file.
    pub blob: Option<ObjectId>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Tree,
    Blob,
    /// Symlinks and submodules (gitlinks): not scanned.
    Other,
}

struct Entry {
    name: BString,
    kind: Kind,
    oid: ObjectId,
}

/// Diffs trees of a single repository handle; counts objects missing from the odb.
pub struct TreeDiffer<'a> {
    repo: &'a gix::Repository,
    missing: &'a AtomicUsize,
}

impl<'a> TreeDiffer<'a> {
    pub fn new(repo: &'a gix::Repository, missing: &'a AtomicUsize) -> Self {
        TreeDiffer { repo, missing }
    }

    /// Changes from `old` (None = empty tree) to `new`.
    pub fn diff(&self, old: Option<ObjectId>, new: ObjectId) -> Result<Vec<Change>> {
        let mut out = Vec::new();
        let mut prefix = BString::default();
        self.diff_trees(old, Some(new), &mut prefix, &mut out)?;
        Ok(out)
    }

    fn entries(&self, id: Option<ObjectId>) -> Result<Vec<Entry>> {
        let Some(id) = id else {
            return Ok(Vec::new());
        };
        let tree = match self.repo.find_tree(id) {
            Ok(t) => t,
            Err(_) => {
                self.missing.fetch_add(1, Ordering::Relaxed);
                return Ok(Vec::new());
            }
        };
        let decoded = tree
            .decode()
            .map_err(|e| anyhow::anyhow!("cannot decode tree {id}: {e}"))?;
        Ok(decoded
            .entries
            .iter()
            .map(|e| Entry {
                name: e.filename.to_owned(),
                kind: if e.mode.is_tree() {
                    Kind::Tree
                } else if e.mode.is_blob() {
                    Kind::Blob
                } else {
                    Kind::Other
                },
                oid: e.oid.to_owned(),
            })
            .collect())
    }

    fn diff_trees(
        &self,
        old: Option<ObjectId>,
        new: Option<ObjectId>,
        prefix: &mut BString,
        out: &mut Vec<Change>,
    ) -> Result<()> {
        if old == new {
            return Ok(());
        }
        let old_entries = self.entries(old)?;
        let new_entries = self.entries(new)?;
        let (mut i, mut j) = (0, 0);
        while i < old_entries.len() || j < new_entries.len() {
            let order = match (old_entries.get(i), new_entries.get(j)) {
                (Some(a), Some(b)) => gix::objs::tree::name_order(
                    &a.name,
                    a.kind == Kind::Tree,
                    &b.name,
                    b.kind == Kind::Tree,
                ),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, _) => std::cmp::Ordering::Greater,
            };
            match order {
                std::cmp::Ordering::Less => {
                    self.side(&old_entries[i], false, prefix, out)?;
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    self.side(&new_entries[j], true, prefix, out)?;
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    let (a, b) = (&old_entries[i], &new_entries[j]);
                    if a.oid != b.oid || a.kind != b.kind {
                        match (a.kind, b.kind) {
                            (Kind::Tree, Kind::Tree) => {
                                self.recurse(&a.name, Some(a.oid), Some(b.oid), prefix, out)?
                            }
                            (_, Kind::Blob) => out.push(change(prefix, &b.name, Some(b.oid))),
                            (Kind::Blob, _) => out.push(change(prefix, &a.name, None)),
                            _ => {}
                        }
                    }
                    i += 1;
                    j += 1;
                }
            }
        }
        Ok(())
    }

    /// An entry present on only one side.
    fn side(
        &self,
        e: &Entry,
        added: bool,
        prefix: &mut BString,
        out: &mut Vec<Change>,
    ) -> Result<()> {
        match e.kind {
            Kind::Tree if added => self.recurse(&e.name, None, Some(e.oid), prefix, out),
            Kind::Tree => self.recurse(&e.name, Some(e.oid), None, prefix, out),
            Kind::Blob => {
                out.push(change(prefix, &e.name, added.then_some(e.oid)));
                Ok(())
            }
            Kind::Other => Ok(()),
        }
    }

    fn recurse(
        &self,
        name: &[u8],
        old: Option<ObjectId>,
        new: Option<ObjectId>,
        prefix: &mut BString,
        out: &mut Vec<Change>,
    ) -> Result<()> {
        let len = prefix.len();
        prefix.extend_from_slice(name);
        prefix.push(b'/');
        let result = self.diff_trees(old, new, prefix, out);
        prefix.truncate(len);
        result
    }
}

fn change(prefix: &BString, name: &[u8], blob: Option<ObjectId>) -> Change {
    let mut path = prefix.clone();
    path.extend_from_slice(name);
    Change { path, blob }
}
