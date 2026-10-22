//! Parsers for the logs APT keeps about package changes, to provide insight into the update history
//! of a system.
//!
//! APT records each transaction, i.e. each of its runs that changes packages, in its history log,
//! see [`HistoryParser`], and the terminal output of the transaction in its terminal log, see
//! [`TermLogParser`]. logrotate rotates and compresses both logs monthly by default, see
//! [`rotated_log_files`] and [`open_log_file`] for reading all of them.
//!
//! The parsers only need a minimal set of dependencies. They are not available on `wasm32`, where
//! only the types are, for use in web UIs.

use std::io;
use std::path::PathBuf;

#[cfg(not(target_arch = "wasm32"))]
mod files;
#[cfg(not(target_arch = "wasm32"))]
pub use files::{open_log_file, rotated_log_files};

#[cfg(not(target_arch = "wasm32"))]
mod history;
#[cfg(not(target_arch = "wasm32"))]
pub use history::HistoryParser;

#[cfg(not(target_arch = "wasm32"))]
mod term_log;
#[cfg(not(target_arch = "wasm32"))]
pub use term_log::{TermLogParser, TermLogSection};

#[cfg(not(target_arch = "wasm32"))]
mod terminal;
#[cfg(not(target_arch = "wasm32"))]
pub use terminal::clean_terminal_output;

#[cfg(not(target_arch = "wasm32"))]
mod time;

mod types;
pub use types::{HistoryEntry, PackageAction, PackageChange};

/// Directory in which APT keeps its logs by default.
pub const APT_LOG_DIR: &str = "/var/log/apt";

/// File name of the APT history log.
pub const HISTORY_LOG_NAME: &str = "history.log";

/// File name of the APT terminal log.
pub const TERM_LOG_NAME: &str = "term.log";

/// Errors from reading or parsing APT logs.
///
/// The messages include their causes, which are therefore not exposed as error sources too, as
/// printing an error together with its sources would show them twice.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Reading the log failed.
    #[error("failed to read log - {0}")]
    Io(io::Error),

    /// Accessing or reading a log file or its directory failed.
    #[error("failed to read {path:?} - {error}")]
    File { path: PathBuf, error: io::Error },

    /// The entry starting at `line` could not be parsed.
    #[error("invalid entry at line {line} - {message}")]
    Parse { line: usize, message: String },
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
