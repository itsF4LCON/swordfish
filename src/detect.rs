//! Two-stage secret detection over a single blob.
//!
//! Stage 1 runs one case-insensitive Aho-Corasick automaton built from every
//! rule keyword. Stage 2 runs the regex only for rules whose keywords hit (and
//! for keyword-less rules). Entropy and content allowlists are evaluated only
//! on regex candidates. Path-dependent filters are applied later by the
//! timeline, because a deduplicated blob has no single path.

use std::ops::Range;

use aho_corasick::AhoCorasick;

use crate::entropy::shannon;
use crate::rules::RuleSet;

/// Bytes inspected for a NUL when deciding whether a blob is binary.
pub const BINARY_SNIFF_LEN: usize = 8000;

/// One secret found in a blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHit {
    /// Index into [`RuleSet::rules`].
    pub rule: usize,
    pub secret: Vec<u8>,
    /// 1-based line of the first byte of the secret.
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobScan {
    Binary,
    Hits(Vec<RawHit>),
}

pub struct Detector {
    rules: RuleSet,
    automaton: Option<AhoCorasick>,
    /// Automaton pattern index -> rules using that keyword.
    keyword_rules: Vec<Vec<usize>>,
    /// Rules without keywords; their regex always runs.
    unconditional: Vec<usize>,
}

impl Detector {
    pub fn new(rules: RuleSet) -> Self {
        let mut keywords: Vec<String> = Vec::new();
        let mut keyword_rules: Vec<Vec<usize>> = Vec::new();
        let mut unconditional = Vec::new();
        for (idx, rule) in rules.rules.iter().enumerate() {
            if rule.keywords.is_empty() {
                unconditional.push(idx);
                continue;
            }
            for kw in &rule.keywords {
                match keywords.iter().position(|k| k == kw) {
                    Some(p) => keyword_rules[p].push(idx),
                    None => {
                        keywords.push(kw.clone());
                        keyword_rules.push(vec![idx]);
                    }
                }
            }
        }
        let automaton = (!keywords.is_empty()).then(|| {
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&keywords)
                .expect("keyword automaton from plain literals")
        });
        Detector {
            rules,
            automaton,
            keyword_rules,
            unconditional,
        }
    }

    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    pub fn scan(&self, data: &[u8]) -> BlobScan {
        if is_binary(data) {
            return BlobScan::Binary;
        }
        let n_rules = self.rules.rules.len();
        let mut candidate = vec![false; n_rules];
        for &idx in &self.unconditional {
            candidate[idx] = true;
        }
        if let Some(ac) = &self.automaton {
            let keyword_rule_count = n_rules - self.unconditional.len();
            let mut marked = 0;
            for m in ac.find_overlapping_iter(data) {
                for &idx in &self.keyword_rules[m.pattern().as_usize()] {
                    if !candidate[idx] {
                        candidate[idx] = true;
                        marked += 1;
                    }
                }
                if marked == keyword_rule_count {
                    break;
                }
            }
        }

        let mut hits = Vec::new();
        let mut taken: Vec<Range<usize>> = Vec::new();
        for (idx, rule) in self.rules.rules.iter().enumerate() {
            if !candidate[idx] {
                continue;
            }
            for caps in rule.regex.captures_iter(data) {
                let whole = caps.get(0).expect("group 0 always matches");
                let secret = match rule.secret_group {
                    Some(g) => caps.get(g),
                    None => caps.get(1).or(Some(whole)),
                };
                let Some(secret) = secret else { continue };
                if secret.is_empty() {
                    continue;
                }
                let span = secret.range();
                if taken
                    .iter()
                    .any(|t| t.start < span.end && span.start < t.end)
                {
                    continue;
                }
                let value = secret.as_bytes();
                if let Some(min) = rule.entropy {
                    if shannon(value) <= min {
                        continue;
                    }
                }
                let line = line_around(data, whole.start(), whole.end());
                let allowlisted = rule
                    .allowlists
                    .iter()
                    .chain(&self.rules.global)
                    .any(|a| a.allows_content(value, whole.as_bytes(), line));
                if allowlisted {
                    continue;
                }
                hits.push(RawHit {
                    rule: idx,
                    secret: value.to_vec(),
                    line: line_number(data, span.start),
                });
                taken.push(span);
            }
        }
        BlobScan::Hits(hits)
    }
}

pub fn is_binary(data: &[u8]) -> bool {
    data[..data.len().min(BINARY_SNIFF_LEN)].contains(&0)
}

fn line_number(data: &[u8], offset: usize) -> u32 {
    let newlines = data[..offset].iter().filter(|&&b| b == b'\n').count();
    u32::try_from(newlines + 1).unwrap_or(u32::MAX)
}

/// The full line(s) spanned by `start..end`, without the trailing newline.
fn line_around(data: &[u8], start: usize, end: usize) -> &[u8] {
    let line_start = data[..start]
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |p| p + 1);
    let line_end = data[end..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(data.len(), |p| end + p);
    &data[line_start..line_end]
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test tokens are assembled at runtime so this source file does not itself
    // trip secret scanners (including swordfish run on its own repo).
    fn aws_key() -> String {
        format!("{}{}", "AKIA", "Z7Q3VXN2LMP4RT6Y")
    }

    fn hits(d: &Detector, text: &str) -> Vec<(String, String, u32)> {
        match d.scan(text.as_bytes()) {
            BlobScan::Hits(h) => h
                .into_iter()
                .map(|h| {
                    (
                        d.rules().rules[h.rule].id.clone(),
                        String::from_utf8(h.secret).unwrap(),
                        h.line,
                    )
                })
                .collect(),
            BlobScan::Binary => panic!("unexpected binary"),
        }
    }

    #[test]
    fn finds_builtin_secrets_with_line_numbers() {
        let d = Detector::new(RuleSet::builtin());
        let gh = format!("{}{}", "ghp_", "Xk9mP2qR7sT4vW8yZ1bC3dF6gH0jK5nL2pQ4");
        let stripe = format!("{}{}", "sk_live_", "4eC39HqLyjWDarjtT1zdp7dc");
        let google = format!("{}{}", "AIza", "SyD3x8Qk2Lm9Np4Rs7Tv1Wx6Yz0Ab5Cd8Ef");
        let text = format!(
            "# config\nAWS_ACCESS_KEY_ID={}\ntoken: {gh}\nstripe = \"{stripe}\"\nmaps={google}\n",
            aws_key()
        );
        let found = hits(&d, &text);
        assert!(
            found.contains(&("aws-access-key-id".into(), aws_key(), 2)),
            "{found:?}"
        );
        assert!(found.contains(&("github-token".into(), gh, 3)), "{found:?}");
        assert!(
            found.contains(&("stripe-secret-key".into(), stripe, 4)),
            "{found:?}"
        );
        assert!(
            found.contains(&("google-api-key".into(), google, 5)),
            "{found:?}"
        );
        assert_eq!(
            found.len(),
            4,
            "generic rule must not double-report: {found:?}"
        );
    }

    #[test]
    fn private_key_block_is_one_secret() {
        let d = Detector::new(RuleSet::builtin());
        let body = "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB\naNY8nMnFTnJCZPnzrGT3JOMZTqLlhEAcSv9zHgIYOgdvbTn4bOTTHnSBmTyqh8Y\n";
        let text = format!(
            "x\n-----BEGIN RSA {k}-----\n{body}-----END RSA {k}-----\n",
            k = "PRIVATE KEY"
        );
        let found = hits(&d, &text);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].0, "private-key");
        assert_eq!(found[0].2, 2);
    }

    #[test]
    fn keyword_prefilter_is_case_insensitive_and_required() {
        let rules = RuleSet::from_toml_str(
            "[[rules]]\nid = \"t\"\nregex = '''(?i)(zz_[a-z0-9]{6})'''\nkeywords = [\"ZZ_\"]",
            "t",
        )
        .unwrap();
        let d = Detector::new(rules);
        assert_eq!(hits(&d, "a zz_abc123 b").len(), 1);
        assert_eq!(hits(&d, "a ZZ_ABC123 b").len(), 1);
        assert!(hits(&d, "nothing here").is_empty());
    }

    #[test]
    fn entropy_threshold_rejects_low_randomness() {
        let d = Detector::new(RuleSet::builtin());
        assert!(hits(&d, "password = \"aaaaaaaaaaaaaaaa\"\n").is_empty());
        let found = hits(&d, "db_password = \"q8Zr4Lp2Vx9Nm3Kt\"\n");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].0, "generic-api-key");
        assert_eq!(found[0].1, "q8Zr4Lp2Vx9Nm3Kt");
    }

    #[test]
    fn allowlisted_values_are_ignored() {
        let d = Detector::new(RuleSet::builtin());
        assert!(hits(&d, &format!("key={}{}\n", "AKIAIOSFODNN7", "EXAMPLE")).is_empty());
        assert!(hits(&d, "api_key = \"your_api_key_goes_here_123\"\n").is_empty());
        assert!(hits(&d, "token = process.env.SECRET_TOKEN_42\n").is_empty());
    }

    #[test]
    fn generic_rule_ignores_identifiers_and_paths() {
        let d = Detector::new(RuleSet::builtin());
        for line in [
            "key = LIBSSH2_KNOWNHOST_KEY_ECDSA_521\n",
            "key: CARGO_TARGET_X86_64_UNKNOWN_LINUX_musl_LINKER\n",
            "auth = workspace.lints.rust.rust-2018-idioms.unused\n",
            "credential = cargo-credential-1password\n",
            "key_path = /home/username/.ssh/id_rsa\n",
            "api_doc = docs/BINDINGS.md\n",
        ] {
            assert!(hits(&d, line).is_empty(), "false positive on {line:?}");
        }
        // A long random segment still counts, even inside a dotted value.
        let paseto = format!("token = k3.secret.{}\n", "fNYVuMvBgOlljt9TDohnaYLblghqaHoQ");
        assert_eq!(hits(&d, &paseto).len(), 1);
    }

    #[test]
    fn binary_blobs_are_skipped() {
        let d = Detector::new(RuleSet::builtin());
        let mut data = b"\x89PNG\r\n\x1a\n\0\0".to_vec();
        data.extend_from_slice(aws_key().as_bytes());
        assert_eq!(d.scan(&data), BlobScan::Binary);
        assert!(is_binary(b"a\0b"));
        assert!(!is_binary(b"plain text"));
    }

    #[test]
    fn keywordless_rules_always_run() {
        let rules = RuleSet::from_toml_str(
            "[[rules]]\nid = \"n\"\nregex = '''\\b(n0kw[0-9]{4})\\b'''",
            "t",
        )
        .unwrap();
        let d = Detector::new(rules);
        assert_eq!(
            hits(&d, "x n0kw1234 y"),
            vec![("n".into(), "n0kw1234".into(), 1)]
        );
    }
}
