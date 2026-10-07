use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use swordfish_git::report::{render_pretty, Report};
use swordfish_git::rules::RuleSet;
use swordfish_git::scan::now_unix;
use swordfish_git::{scan, ScanOptions, DEFAULT_MAX_BLOB_SIZE};

/// Exit codes: 0 = no findings, 1 = findings, 2 = error.
const EXIT_FINDINGS: u8 = 1;
const EXIT_ERROR: u8 = 2;

#[derive(Parser)]
#[command(
    name = "swordfish",
    version,
    about = "Hunt secrets in git history and tell the story of each leak",
    after_help = "Exit codes: 0 = no findings, 1 = findings, 2 = error.\nswordfish is read-only and makes no network calls."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan every commit reachable from any ref and report a timeline per secret
    Scan(ScanArgs),
}

#[derive(clap::Args)]
struct ScanArgs {
    /// Path inside the repository to scan
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Output format
    #[arg(long, value_enum, default_value_t = Format::Pretty)]
    format: Format,

    /// Extra rules (gitleaks-compatible TOML subset) added to the built-in set
    #[arg(long, value_name = "FILE")]
    rules: Option<PathBuf>,

    /// Skip blobs larger than N bytes
    #[arg(long, value_name = "N", default_value_t = DEFAULT_MAX_BLOB_SIZE)]
    max_blob_size: u64,

    /// Print secrets in full instead of redacted (prints a warning)
    #[arg(long)]
    show_secrets: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Pretty,
    Json,
}

fn main() -> ExitCode {
    let Command::Scan(args) = Cli::parse().command;
    match run(args) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("swordfish: error: {e:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run(args: ScanArgs) -> anyhow::Result<u8> {
    let rules = match &args.rules {
        Some(path) => RuleSet::builtin_with_file(path)?,
        None => RuleSet::builtin(),
    };
    if args.show_secrets {
        eprintln!(
            "swordfish: warning: --show-secrets prints secrets in full; do not share this output"
        );
    }
    let now = now_unix();
    let result = scan(ScanOptions {
        path: args.path,
        rules,
        max_blob_size: args.max_blob_size,
        now,
    })?;
    for w in &result.warnings {
        eprintln!("swordfish: warning: {w}");
    }

    let report = Report::new(&result, args.show_secrets, now);
    let rendered = match args.format {
        Format::Json => report.to_json() + "\n",
        Format::Pretty => {
            let color = std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none();
            render_pretty(&report, result.history_start, now, color)
        }
    };
    let mut stdout = std::io::stdout().lock();
    if let Err(e) = stdout
        .write_all(rendered.as_bytes())
        .and_then(|()| stdout.flush())
    {
        if e.kind() != std::io::ErrorKind::BrokenPipe {
            return Err(e.into());
        }
    }
    Ok(if report.findings.is_empty() {
        0
    } else {
        EXIT_FINDINGS
    })
}
