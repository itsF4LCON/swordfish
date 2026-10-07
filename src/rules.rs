//! Detection rules: a gitleaks-compatible TOML subset plus the built-in set.
//!
//! See ROADMAP.md §5 for the supported keys. Path filters are kept separate from
//! content filters because blobs are scanned once, independent of their path.

use std::path::Path;

use regex::bytes::Regex;
use serde::Deserialize;

const BUILTIN_RULES: &str = include_str!("rules/default.toml");

#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("cannot read rules file {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid rules TOML in {origin}: {source}")]
    Toml {
        origin: String,
        source: toml::de::Error,
    },
    #[error("rule `{id}`: invalid {field} regex: {source}")]
    Regex {
        id: String,
        field: &'static str,
        source: Box<regex::Error>,
    },
    #[error("rule `{id}`: {message}")]
    Invalid { id: String, message: String },
}

/// Which text an allowlist regex is matched against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegexTarget {
    /// The extracted secret (gitleaks default).
    Secret,
    /// The full regex match.
    Match,
    /// The whole line containing the match.
    Line,
}

#[derive(Debug, Clone)]
pub struct Allowlist {
    pub regexes: Vec<Regex>,
    pub regex_target: RegexTarget,
    pub paths: Vec<Regex>,
    /// Lower-cased; a secret containing any stopword is ignored.
    pub stopwords: Vec<String>,
}

impl Allowlist {
    /// Content-side check (regexes and stopwords); paths are checked separately.
    pub fn allows_content(&self, secret: &[u8], full_match: &[u8], line: &[u8]) -> bool {
        let target = match self.regex_target {
            RegexTarget::Secret => secret,
            RegexTarget::Match => full_match,
            RegexTarget::Line => line,
        };
        if self.regexes.iter().any(|re| re.is_match(target)) {
            return true;
        }
        if !self.stopwords.is_empty() {
            let lower = secret.to_ascii_lowercase();
            return self
                .stopwords
                .iter()
                .any(|w| contains(&lower, w.as_bytes()));
        }
        false
    }

    pub fn allows_path(&self, path: &[u8]) -> bool {
        self.paths.iter().any(|re| re.is_match(path))
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub description: String,
    pub regex: Regex,
    pub secret_group: Option<usize>,
    pub entropy: Option<f64>,
    /// Lower-cased prefilter keywords. Empty means the regex always runs.
    pub keywords: Vec<String>,
    /// If set, the rule only applies to paths matching this regex.
    pub path: Option<Regex>,
    pub allowlists: Vec<Allowlist>,
}

impl Rule {
    /// Whether a hit of this rule may be reported at `path`.
    pub fn applies_to_path(&self, path: &[u8]) -> bool {
        if let Some(re) = &self.path {
            if !re.is_match(path) {
                return false;
            }
        }
        !self.allowlists.iter().any(|a| a.allows_path(path))
    }
}

#[derive(Debug, Clone)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
    pub global: Vec<Allowlist>,
    /// Non-fatal notes about unsupported keys, surfaced on stderr by the CLI.
    pub warnings: Vec<String>,
}

impl RuleSet {
    /// The rules embedded in the binary.
    pub fn builtin() -> Self {
        Self::from_toml_str(BUILTIN_RULES, "built-in rules")
            .expect("built-in rules must always parse")
    }

    /// Built-in rules extended with the rules in `path`. A loaded rule with the
    /// same `id` as a built-in one replaces it in place.
    pub fn builtin_with_file(path: &Path) -> Result<Self, RuleError> {
        let text = std::fs::read_to_string(path).map_err(|source| RuleError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let extra = Self::from_toml_str(&text, &path.display().to_string())?;
        let mut set = Self::builtin();
        set.extend(extra);
        Ok(set)
    }

    pub fn extend(&mut self, other: RuleSet) {
        for rule in other.rules {
            match self.rules.iter_mut().find(|r| r.id == rule.id) {
                Some(existing) => *existing = rule,
                None => self.rules.push(rule),
            }
        }
        self.global.extend(other.global);
        self.warnings.extend(other.warnings);
    }

    pub fn from_toml_str(text: &str, origin: &str) -> Result<Self, RuleError> {
        let raw: RawConfig = toml::from_str(text).map_err(|source| RuleError::Toml {
            origin: origin.to_string(),
            source,
        })?;
        let mut warnings = Vec::new();
        if raw.extend.is_some() {
            warnings.push(format!(
                "{origin}: [extend] is ignored; --rules always extends the built-in rules"
            ));
        }

        let mut global = Vec::new();
        for (i, a) in raw.allowlist.into_iter().chain(raw.allowlists).enumerate() {
            let ctx = format!("global allowlist #{}", i + 1);
            global.push(a.compile(&ctx, origin, &mut warnings)?);
        }

        let mut rules: Vec<Rule> = Vec::with_capacity(raw.rules.len());
        for r in raw.rules {
            if r.id.trim().is_empty() {
                return Err(RuleError::Invalid {
                    id: "<empty>".into(),
                    message: format!("{origin}: every rule needs a non-empty `id`"),
                });
            }
            if rules.iter().any(|x| x.id == r.id) {
                return Err(RuleError::Invalid {
                    id: r.id,
                    message: format!("{origin}: duplicate rule id"),
                });
            }
            let Some(pattern) = r.regex else {
                warnings.push(format!(
                    "{origin}: rule `{}` has no `regex` (path-only rules are not supported); skipped",
                    r.id
                ));
                continue;
            };
            let regex = compile(&pattern, &r.id, "content")?;
            if let Some(g) = r.secret_group {
                if g >= regex.captures_len() {
                    return Err(RuleError::Invalid {
                        id: r.id,
                        message: format!(
                            "secretGroup {g} exceeds the {} capture group(s) in the regex",
                            regex.captures_len() - 1
                        ),
                    });
                }
            }
            let path = r
                .path
                .as_deref()
                .map(|p| compile(p, &r.id, "path"))
                .transpose()?;
            let mut allowlists = Vec::new();
            for a in r.allowlist.into_iter().chain(r.allowlists) {
                allowlists.push(a.compile(&r.id, origin, &mut warnings)?);
            }
            rules.push(Rule {
                description: r.description.unwrap_or_else(|| r.id.clone()),
                id: r.id,
                regex,
                secret_group: r.secret_group,
                entropy: r.entropy.filter(|e| *e > 0.0),
                keywords: r
                    .keywords
                    .into_iter()
                    .map(|k| k.to_ascii_lowercase())
                    .filter(|k| !k.is_empty())
                    .collect(),
                path,
                allowlists,
            });
        }

        Ok(RuleSet {
            rules,
            global,
            warnings,
        })
    }

    /// Whether `path` is excluded by a global path allowlist.
    pub fn path_globally_allowlisted(&self, path: &[u8]) -> bool {
        self.global.iter().any(|a| a.allows_path(path))
    }
}

fn compile(pattern: &str, id: &str, field: &'static str) -> Result<Regex, RuleError> {
    Regex::new(pattern).map_err(|source| RuleError::Regex {
        id: id.to_string(),
        field,
        source: Box::new(source),
    })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|w| w == needle)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawConfig {
    #[serde(default)]
    rules: Vec<RawRule>,
    allowlist: Option<RawAllowlist>,
    #[serde(default)]
    allowlists: Vec<RawAllowlist>,
    extend: Option<toml::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRule {
    id: String,
    description: Option<String>,
    regex: Option<String>,
    secret_group: Option<usize>,
    entropy: Option<f64>,
    #[serde(default)]
    keywords: Vec<String>,
    path: Option<String>,
    allowlist: Option<RawAllowlist>,
    #[serde(default)]
    allowlists: Vec<RawAllowlist>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawAllowlist {
    #[serde(default)]
    regexes: Vec<String>,
    regex_target: Option<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    stopwords: Vec<String>,
    #[serde(default)]
    commits: Vec<String>,
    condition: Option<String>,
}

impl RawAllowlist {
    fn compile(
        self,
        ctx: &str,
        origin: &str,
        warnings: &mut Vec<String>,
    ) -> Result<Allowlist, RuleError> {
        if !self.commits.is_empty() {
            warnings.push(format!(
                "{origin}: {ctx}: allowlist `commits` is not supported yet; ignored"
            ));
        }
        if self
            .condition
            .is_some_and(|c| !c.eq_ignore_ascii_case("or"))
        {
            warnings.push(format!(
                "{origin}: {ctx}: allowlist `condition` other than OR is not supported; using OR"
            ));
        }
        let regex_target = match self.regex_target.as_deref() {
            None | Some("secret") => RegexTarget::Secret,
            Some("match") => RegexTarget::Match,
            Some("line") => RegexTarget::Line,
            Some(other) => {
                return Err(RuleError::Invalid {
                    id: ctx.to_string(),
                    message: format!("unknown allowlist regexTarget `{other}`"),
                })
            }
        };
        Ok(Allowlist {
            regexes: self
                .regexes
                .iter()
                .map(|p| compile(p, ctx, "allowlist"))
                .collect::<Result<_, _>>()?,
            regex_target,
            paths: self
                .paths
                .iter()
                .map(|p| compile(p, ctx, "allowlist path"))
                .collect::<Result<_, _>>()?,
            stopwords: self
                .stopwords
                .into_iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_parse_without_warnings() {
        let set = RuleSet::builtin();
        assert!(set.rules.len() >= 10);
        assert!(set.warnings.is_empty(), "{:?}", set.warnings);
        let ids: Vec<_> = set.rules.iter().map(|r| r.id.as_str()).collect();
        for expected in [
            "aws-access-key-id",
            "github-token",
            "slack-token",
            "stripe-secret-key",
            "google-api-key",
            "private-key",
            "jwt",
            "generic-api-key",
        ] {
            assert!(ids.contains(&expected), "missing {expected}");
        }
        assert_eq!(
            ids.last(),
            Some(&"generic-api-key"),
            "generic rule must be last"
        );
    }

    #[test]
    fn loads_gitleaks_subset() {
        let toml = r#"
            [allowlist]
            paths = ['''^vendor/''']

            [[rules]]
            id = "myco-token"
            description = "MyCo token"
            regex = '''\b(myco_[a-z0-9]{8})(?:x)?'''
            secretGroup = 1
            entropy = 2.5
            keywords = ["MYCO_"]
            tags = ["internal"]
            path = '''\.env$'''

            [rules.allowlist]
            regexes = ['''^myco_00000000$''']
            stopwords = ["Dummy"]
            regexTarget = "secret"

            [[rules.allowlists]]
            paths = ['''^test/''']
            commits = ["abc"]
        "#;
        let set = RuleSet::from_toml_str(toml, "test").unwrap();
        assert_eq!(set.rules.len(), 1);
        let r = &set.rules[0];
        assert_eq!(r.id, "myco-token");
        assert_eq!(r.secret_group, Some(1));
        assert_eq!(r.entropy, Some(2.5));
        assert_eq!(r.keywords, vec!["myco_"]);
        assert_eq!(r.allowlists.len(), 2);
        assert_eq!(r.allowlists[0].stopwords, vec!["dummy"]);
        assert!(r.applies_to_path(b"app/.env"));
        assert!(!r.applies_to_path(b"app/main.rs"), "path restriction");
        assert!(!r.applies_to_path(b"test/.env"), "per-rule path allowlist");
        assert!(set.path_globally_allowlisted(b"vendor/x.env"));
        assert_eq!(set.warnings.len(), 1, "commits allowlist warns");
    }

    #[test]
    fn extra_rules_extend_and_override_builtin() {
        let mut set = RuleSet::builtin();
        let n = set.rules.len();
        let extra = RuleSet::from_toml_str(
            r#"
            [[rules]]
            id = "jwt"
            regex = '''never-matches-anything-xyz'''
            [[rules]]
            id = "new-rule"
            regex = '''foo_[0-9]+'''
            "#,
            "extra",
        )
        .unwrap();
        set.extend(extra);
        assert_eq!(set.rules.len(), n + 1);
        let jwt = set.rules.iter().find(|r| r.id == "jwt").unwrap();
        assert_eq!(jwt.regex.as_str(), "never-matches-anything-xyz");
    }

    #[test]
    fn rejects_bad_rules() {
        let bad_regex =
            RuleSet::from_toml_str("[[rules]]\nid = \"x\"\nregex = '''(unclosed'''", "t");
        assert!(matches!(bad_regex, Err(RuleError::Regex { .. })));

        let bad_group = RuleSet::from_toml_str(
            "[[rules]]\nid = \"x\"\nregex = '''a(b)'''\nsecretGroup = 2",
            "t",
        );
        assert!(matches!(bad_group, Err(RuleError::Invalid { .. })));

        let dup = RuleSet::from_toml_str(
            "[[rules]]\nid = \"x\"\nregex = 'a'\n[[rules]]\nid = \"x\"\nregex = 'b'",
            "t",
        );
        assert!(matches!(dup, Err(RuleError::Invalid { .. })));

        let bad_toml = RuleSet::from_toml_str("[[rules]\nid=", "t");
        assert!(matches!(bad_toml, Err(RuleError::Toml { .. })));
    }

    #[test]
    fn path_only_rule_is_skipped_with_warning() {
        let set = RuleSet::from_toml_str("[[rules]]\nid = \"pem-file\"\npath = '''\\.pem$'''", "t")
            .unwrap();
        assert!(set.rules.is_empty());
        assert_eq!(set.warnings.len(), 1);
    }

    #[test]
    fn allowlist_targets_and_stopwords() {
        let a = Allowlist {
            regexes: vec![Regex::new("^LINE").unwrap()],
            regex_target: RegexTarget::Line,
            paths: vec![],
            stopwords: vec!["example".into()],
        };
        assert!(a.allows_content(b"s", b"m", b"LINE x"));
        assert!(!a.allows_content(b"s", b"LINE", b"other"));
        assert!(a.allows_content(b"my-EXAMPLE-key", b"m", b"l"));
    }
}
