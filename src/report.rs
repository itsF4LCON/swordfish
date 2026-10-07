//! Output: JSON schema v1 (see ROADMAP.md §4) and the pretty terminal view.

use std::fmt::Write as _;

use serde::Serialize;

use crate::redact::{fingerprint, redact};
use crate::scan::ScanResult;
use crate::timeline::{Event, Finding, Status};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub tool: Tool,
    pub repository: String,
    pub head: Option<String>,
    pub generated_at: String,
    pub stats: StatsJson,
    pub findings: Vec<FindingJson>,
}

#[derive(Debug, Serialize)]
pub struct Tool {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct StatsJson {
    pub refs: usize,
    pub commits: usize,
    pub unique_blobs: usize,
    pub scanned_blobs: usize,
    pub skipped_binary: usize,
    pub skipped_too_large: usize,
    pub skipped_allowlisted: usize,
    pub skipped_missing: usize,
    pub findings: usize,
    pub elapsed_ms: u128,
}

#[derive(Debug, Serialize)]
pub struct FindingJson {
    pub fingerprint: String,
    pub rule_id: String,
    pub description: String,
    pub secret: String,
    pub redacted: bool,
    pub status: &'static str,
    pub introduced: IntroducedJson,
    pub removed: Option<RemovedJson>,
    pub exposure_days: f64,
    pub refs: Vec<String>,
    pub locations: Vec<LocationJson>,
}

#[derive(Debug, Serialize)]
pub struct Author {
    pub name: String,
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct IntroducedJson {
    pub commit: String,
    pub author: Author,
    pub date: String,
    pub path: String,
    pub line: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct RemovedJson {
    pub commit: String,
    pub author: Author,
    pub date: String,
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct LocationJson {
    pub path: String,
    pub blob: String,
    pub line: u32,
}

pub fn status_str(status: Status) -> &'static str {
    match status {
        Status::LiveInHead => "live_in_head",
        Status::LiveOnOtherRef => "live_on_other_ref",
        Status::RemovedButInHistory => "removed_but_in_history",
    }
}

fn author(e: &Event) -> Author {
    Author {
        name: e.author_name.clone(),
        email: e.author_email.clone(),
    }
}

impl Report {
    pub fn new(result: &ScanResult, show_secrets: bool, now: i64) -> Self {
        let findings = result
            .findings
            .iter()
            .map(|f| {
                let rule = &result.rules.rules[f.rule];
                FindingJson {
                    fingerprint: fingerprint(&f.secret),
                    rule_id: rule.id.clone(),
                    description: rule.description.clone(),
                    secret: display_secret(f, show_secrets),
                    redacted: !show_secrets,
                    status: status_str(f.status),
                    introduced: IntroducedJson {
                        commit: f.introduced.commit.to_string(),
                        author: author(&f.introduced),
                        date: rfc3339(f.introduced.time),
                        path: f.introduced.path.clone(),
                        line: f.introduced.line,
                    },
                    removed: f.removed.as_ref().map(|r| RemovedJson {
                        commit: r.commit.to_string(),
                        author: author(r),
                        date: rfc3339(r.time),
                        path: r.path.clone(),
                    }),
                    exposure_days: f.exposure_days,
                    refs: f.refs.clone(),
                    locations: f
                        .locations
                        .iter()
                        .map(|l| LocationJson {
                            path: l.path.clone(),
                            blob: l.blob.to_string(),
                            line: l.line,
                        })
                        .collect(),
                }
            })
            .collect::<Vec<_>>();
        let s = &result.stats;
        Report {
            schema_version: SCHEMA_VERSION,
            tool: Tool {
                name: "swordfish",
                version: env!("CARGO_PKG_VERSION"),
            },
            repository: result.repository.display().to_string(),
            head: result.head.clone(),
            generated_at: rfc3339(now),
            stats: StatsJson {
                refs: s.refs,
                commits: s.commits,
                unique_blobs: s.unique_blobs,
                scanned_blobs: s.scanned_blobs,
                skipped_binary: s.skipped_binary,
                skipped_too_large: s.skipped_too_large,
                skipped_allowlisted: s.skipped_allowlisted,
                skipped_missing: s.skipped_missing,
                findings: findings.len(),
                elapsed_ms: s.elapsed_ms,
            },
            findings,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("report serializes")
    }
}

fn display_secret(f: &Finding, show: bool) -> String {
    if show {
        String::from_utf8_lossy(&f.secret).into_owned()
    } else {
        redact(&f.secret)
    }
}

/// Unix seconds -> `YYYY-MM-DDTHH:MM:SSZ` (UTC).
pub fn rfc3339(secs: i64) -> String {
    let (date, time) = split_utc(secs);
    format!("{date}T{time}Z")
}

fn split_utc(secs: i64) -> (String, String) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    (
        format!("{y:04}-{m:02}-{d:02}"),
        format!("{:02}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60),
    )
}

/// Howard Hinnant's days-to-civil algorithm (proleptic Gregorian).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// ANSI styling that collapses to nothing when colour is off.
struct Style {
    on: bool,
}

impl Style {
    fn paint(&self, code: &str, text: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
    fn bold(&self, t: &str) -> String {
        self.paint("1", t)
    }
    fn dim(&self, t: &str) -> String {
        self.paint("2", t)
    }
    fn red(&self, t: &str) -> String {
        self.paint("1;31", t)
    }
    fn yellow(&self, t: &str) -> String {
        self.paint("1;33", t)
    }
    fn green(&self, t: &str) -> String {
        self.paint("1;32", t)
    }
    fn cyan(&self, t: &str) -> String {
        self.paint("36", t)
    }
}

const BAR_WIDTH: usize = 40;
/// Refs/locations listed per finding in the pretty view; JSON always has all.
const MAX_LISTED: usize = 5;

/// `a, b, c … and 12 more`
fn summarize(items: &[String], max: usize, st: &Style) -> String {
    if items.len() <= max {
        return items.join(", ");
    }
    format!(
        "{} {}",
        items[..max].join(", "),
        st.dim(&format!(
            "… and {} more (see --format json)",
            items.len() - max
        ))
    )
}

/// Human-readable terminal view of a report.
pub fn render_pretty(report: &Report, history_start: Option<i64>, now: i64, color: bool) -> String {
    let st = Style { on: color };
    let mut out = String::new();
    let s = &report.stats;
    let head = report.head.as_deref().unwrap_or("unborn");
    let _ = writeln!(
        out,
        "{} {}  {}",
        st.bold("swordfish"),
        report.repository,
        st.dim(&format!("(HEAD → {head})"))
    );
    let _ = writeln!(
        out,
        "{}",
        st.dim(&format!(
            "scanned {} commits across {} refs · {} unique blobs ({} scanned, {} binary, {} too large, {} allowlisted, {} missing) · {} ms",
            s.commits,
            s.refs,
            s.unique_blobs,
            s.scanned_blobs,
            s.skipped_binary,
            s.skipped_too_large,
            s.skipped_allowlisted,
            s.skipped_missing,
            s.elapsed_ms
        ))
    );
    out.push('\n');

    if report.findings.is_empty() {
        let _ = writeln!(out, "{}", st.green("No secrets found."));
        return out;
    }

    let total = report.findings.len();
    for (i, f) in report.findings.iter().enumerate() {
        let in_head = f.status == status_str(Status::LiveInHead);
        let other_ref = f.status == status_str(Status::LiveOnOtherRef);
        let live = in_head || other_ref;
        let marker = if live {
            st.red("●")
        } else {
            st.yellow("●")
        };
        let _ = writeln!(
            out,
            "{marker} {} {}  {}  {}",
            st.dim(&format!("[{}/{total}]", i + 1)),
            st.bold(&f.rule_id),
            st.cyan(&f.secret),
            st.dim(&format!("fp {}", &f.fingerprint[..12]))
        );
        let status = if in_head {
            st.red("LIVE IN HEAD")
        } else if other_ref {
            st.red("LIVE ON ANOTHER REF (not in HEAD)")
        } else {
            st.yellow("REMOVED, BUT STILL IN HISTORY (rotate this key)")
        };
        let _ = writeln!(out, "  {}  {status}", label("status"));
        let intro = &f.introduced;
        let _ = writeln!(
            out,
            "  {}  {}  {}  {} <{}>",
            label("introduced"),
            human_date(&intro.date),
            st.bold(&intro.commit[..10]),
            intro.author.name,
            intro.author.email
        );
        let at = match intro.line {
            Some(line) => format!("{}:{line}", intro.path),
            None => intro.path.clone(),
        };
        let _ = writeln!(out, "  {}  {at}", label(""));
        match &f.removed {
            Some(r) => {
                let _ = writeln!(
                    out,
                    "  {}  {}  {}  {} <{}>  {}",
                    label("removed"),
                    human_date(&r.date),
                    st.bold(&r.commit[..10]),
                    r.author.name,
                    r.author.email,
                    st.dim(&format!("from {}", r.path))
                );
            }
            None => {
                let _ = writeln!(out, "  {}  {}", label("removed"), st.dim("never"));
            }
        }
        let _ = writeln!(
            out,
            "  {}  {:.2} days{}",
            label("exposed"),
            f.exposure_days,
            if live || f.removed.is_none() {
                " and counting"
            } else {
                ""
            }
        );
        if let Some(start) = history_start {
            let bar = exposure_bar(start, now, f, live);
            let painted = if live { st.red(&bar) } else { st.yellow(&bar) };
            let _ = writeln!(out, "  {}  {painted}", label("timeline"));
        }
        let refs = if f.refs.is_empty() {
            st.dim("none")
        } else {
            summarize(&f.refs, MAX_LISTED, &st)
        };
        let _ = writeln!(out, "  {}  {refs}", label("reachable"));
        let seen: Vec<String> = f
            .locations
            .iter()
            .map(|l| {
                format!(
                    "{}:{} {}",
                    l.path,
                    l.line,
                    st.dim(&format!("({})", &l.blob[..8]))
                )
            })
            .collect();
        let _ = writeln!(
            out,
            "  {}  {}",
            label("seen at"),
            summarize(&seen, MAX_LISTED, &st)
        );
        out.push('\n');
    }

    let count = |status: Status| {
        report
            .findings
            .iter()
            .filter(|f| f.status == status_str(status))
            .count()
    };
    let _ = writeln!(
        out,
        "{} {}, {}, {}",
        st.bold(&format!(
            "{total} secret{} found:",
            if total == 1 { "" } else { "s" }
        )),
        st.red(&format!("{} live in HEAD", count(Status::LiveInHead))),
        st.red(&format!(
            "{} live on another ref",
            count(Status::LiveOnOtherRef)
        )),
        st.yellow(&format!(
            "{} removed but still in history",
            count(Status::RemovedButInHistory)
        ))
    );
    out
}

fn label(name: &str) -> String {
    format!("{name:<10}")
}

/// `2024-01-02T10:00:00Z` -> `2024-01-02 10:00 UTC`
fn human_date(rfc: &str) -> String {
    format!("{} {} UTC", &rfc[..10], &rfc[11..16])
}

/// `░░░░████████░░░░` over [first commit, now]; filled = exposure window.
fn exposure_bar(history_start: i64, now: i64, f: &FindingJson, live: bool) -> String {
    let span = (now - history_start).max(1) as f64;
    let pos = |t: i64| -> usize {
        let frac = ((t - history_start) as f64 / span).clamp(0.0, 1.0);
        (frac * (BAR_WIDTH as f64 - 1.0)).round() as usize
    };
    let start = pos(parse_rfc3339(&f.introduced.date));
    let end = match (&f.removed, live) {
        (Some(r), false) => pos(parse_rfc3339(&r.date)),
        _ => BAR_WIDTH - 1,
    };
    (0..BAR_WIDTH)
        .map(|i| if i >= start && i <= end { '█' } else { '░' })
        .collect()
}

/// Inverse of [`rfc3339`] for the exact format it produces.
fn parse_rfc3339(s: &str) -> i64 {
    let num = |r: std::ops::Range<usize>| s[r].parse::<i64>().unwrap_or(0);
    let (y, m, d) = (num(0..4), num(5..7), num(8..10));
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + num(11..13) * 3600 + num(14..16) * 60 + num(17..19)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc_dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_704_189_600), "2024-01-02T10:00:00Z");
        assert_eq!(rfc3339(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn long_lists_are_summarized() {
        let st = Style { on: false };
        let items: Vec<String> = (0..8).map(|i| format!("r{i}")).collect();
        assert_eq!(summarize(&items[..3], 5, &st), "r0, r1, r2");
        assert_eq!(
            summarize(&items, 5, &st),
            "r0, r1, r2, r3, r4 … and 3 more (see --format json)"
        );
    }

    #[test]
    fn rfc3339_roundtrips() {
        for t in [0, 951_782_400, 1_704_189_600, 1_791_053_149, 4_102_444_799] {
            assert_eq!(parse_rfc3339(&rfc3339(t)), t);
        }
    }
}
