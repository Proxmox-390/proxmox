use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::{Path, PathBuf};

use flate2::read::MultiGzDecoder;

use crate::Error;

/// Lists the files of a log named `name` in `dir`, newest first, including the ones rotated by
/// logrotate, like `name.1` and `name.2.gz`, or `name-20261001.gz` with its `dateext` option.
///
/// Returns an empty list if `dir` does not exist. If a rotated file exists both uncompressed and
/// compressed, which happens while logrotate compresses it, only the uncompressed one is listed.
pub fn rotated_log_files(dir: &Path, name: &str) -> Result<Vec<PathBuf>, Error> {
    let file_error = |error| Error::File {
        path: dir.to_owned(),
        error,
    };

    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(file_error(err)),
    };

    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(file_error)?;
        let file_name = entry.file_name();
        let Some(suffix) = file_name.to_str().and_then(|n| n.strip_prefix(name)) else {
            continue;
        };

        let (suffix, compressed) = match suffix.strip_suffix(".gz") {
            Some(suffix) => (suffix, true),
            None => (suffix, false),
        };

        let order = if suffix.is_empty() && !compressed {
            (0, 0)
        } else if let Some(index) = suffix.strip_prefix('.').and_then(digits) {
            if index == 0 {
                continue;
            }
            (1, index)
        } else if let Some(date) = suffix.strip_prefix('-').and_then(digits) {
            // the most recent date first
            (2, u64::MAX - date)
        } else {
            continue;
        };

        files.push((order, compressed, entry.path()));
    }

    files.sort_unstable();
    files.dedup_by_key(|(order, _, _)| *order);

    Ok(files.into_iter().map(|(_, _, path)| path).collect())
}

/// Parses a non-empty string of decimal digits.
fn digits(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

/// Opens a log file for reading, decompressing it if its name ends with `.gz`.
pub fn open_log_file(path: &Path) -> Result<Box<dyn BufRead + Send>, Error> {
    let file = File::open(path).map_err(|error| Error::File {
        path: path.to_owned(),
        error,
    })?;

    if path.extension() == Some(OsStr::new("gz")) {
        Ok(Box::new(BufReader::new(MultiGzDecoder::new(file))))
    } else {
        Ok(Box::new(BufReader::new(file)))
    }
}

/// Reads a log line by line, tracking the line number.
///
/// Lines are converted to UTF-8 lossily, as APT logs command lines and dpkg output verbatim.
pub(crate) struct LineReader<R> {
    reader: R,
    buf: Vec<u8>,
    line: usize,
}

impl<R: BufRead> LineReader<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            line: 0,
        }
    }

    /// Number of the line returned last, starting at 1.
    pub(crate) fn line(&self) -> usize {
        self.line
    }

    /// Returns the next line including its line ending, or `None` at the end of the log.
    pub(crate) fn next_line(&mut self) -> io::Result<Option<String>> {
        self.buf.clear();
        if self.reader.read_until(b'\n', &mut self.buf)? == 0 {
            return Ok(None);
        }
        self.line += 1;
        Ok(Some(String::from_utf8_lossy(&self.buf).into_owned()))
    }
}
