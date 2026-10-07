//! swordfish: hunts secrets in git history and reconstructs each leak's timeline.
//!
//! The pipeline lives in [`scan::scan`]; [`report`] renders its result.

pub mod detect;
pub mod entropy;
pub mod history;
pub mod redact;
pub mod report;
pub mod rules;
pub mod scan;
pub mod timeline;

pub use scan::{scan, ScanOptions, ScanResult, Stats, DEFAULT_MAX_BLOB_SIZE};
