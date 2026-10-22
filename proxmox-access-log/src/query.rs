use std::cell::Cell;
use std::collections::VecDeque;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use anyhow::{Error, bail, format_err};

use crate::reader::{Line, LineReader, MAX_LINE_LENGTH, parse_line};
use crate::{
    AccessLogEntry, AccessLogFilter, DEFAULT_LIMIT, Gap, GapReason, LogFormat, MAX_CURSOR_LENGTH,
    MAX_LIMIT, Prefix, QueryResult,
};

/// The amount of data [`query`] reads at most, counting both the compressed and the decompressed
/// data of compressed copies. Identifying the files adds to this, reading up to their first lines,
/// as does finding where the newest line ends, reading at most one line from the end of a file.
pub const MAX_READ_BYTES: u64 = 512 * 1024 * 1024;

/// The amount of lines [`query`] parses completely at most. A line whose first fields already
/// show that it does not match, like one outside the time range or of another user, only counts
/// towards [`MAX_READ_BYTES`].
pub const MAX_PARSE_BYTES: u64 = 64 * 1024 * 1024;

/// The amount of lines of a compressed copy kept to parse, which are the ones that can match
/// before the position a page continues at. A page that does not find enough matches among these
/// continues before the oldest of them, which takes decompressing the copy again.
const MAX_BUFFERED_BYTES: usize = 16 * 1024 * 1024;

/// The approximate size of the entries a page returns at most, unless its first entry is larger.
const MAX_ENTRY_BYTES: usize = 16 * 1024 * 1024;

/// The amount of a plain log file read at once, from its end towards its start.
const WINDOW_SIZE: usize = 1024 * 1024;

/// The number of first lines that identify a log file in a cursor.
const FINGERPRINT_LINES: usize = 16;

/// The amount of plain or decoded data read per file to identify it, independent of the line limit.
const FINGERPRINT_BYTES: u64 = 16 * 1024 * 1024;

/// The largest window zstd may need for decompressing, 8 MiB, which bounds its memory use.
const ZSTD_WINDOW_LOG_MAX: u32 = 23;

struct Limits {
    read: u64,
    parse: u64,
    buffered: usize,
    entries: usize,
    window: usize,
}

// These bounds let a fresh page consume or skip a line and advance its cursor.
const _: () = assert!(MAX_READ_BYTES > (MAX_LINE_LENGTH + 2 * (WINDOW_SIZE + 1)) as u64);
const _: () = assert!(MAX_PARSE_BYTES >= MAX_LINE_LENGTH as u64);

const LIMITS: Limits = Limits {
    read: MAX_READ_BYTES,
    parse: MAX_PARSE_BYTES,
    buffered: MAX_BUFFERED_BYTES,
    entries: MAX_ENTRY_BYTES,
    window: WINDOW_SIZE,
};

/// The error of a query that cannot be answered as asked, as a parameter is out of range or the
/// cursor is invalid or points into a file that got rotated away, unlike a failure to read the log.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct InvalidRequest(String);

fn invalid(message: impl Into<String>) -> Error {
    InvalidRequest(message.into()).into()
}

/// Lists a log file and its rotated copies, newest first.
///
/// Rotated copies have an increasing number appended to the name of the log, like `access.log.1`,
/// and can be compressed with gzip, as logrotate does, or zstd, as proxmox-sys does.
pub fn log_files(path: &Path) -> Result<Vec<PathBuf>, Error> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format_err!("invalid log file path {path:?}"))?;

    let dir_entries = match std::fs::read_dir(dir) {
        Ok(dir_entries) => dir_entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => bail!("unable to list log directory {dir:?} - {err}"),
    };

    let mut files = Vec::new();
    for dir_entry in dir_entries {
        let dir_entry =
            dir_entry.map_err(|err| format_err!("unable to list log directory {dir:?} - {err}"))?;
        let file_name = dir_entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };

        if file_name == name {
            files.push(((0, false), dir_entry.path()));
            continue;
        }

        let Some(suffix) = file_name
            .strip_prefix(name)
            .and_then(|suffix| suffix.strip_prefix('.'))
        else {
            continue;
        };
        let (number, compressed) = match suffix
            .strip_suffix(".gz")
            .or_else(|| suffix.strip_suffix(".zst"))
        {
            Some(number) => (number, true),
            None => (suffix, false),
        };
        // rotation starts at 1 and does not pad numbers, so `.0` or `.01` are something else
        if number.starts_with('0') {
            continue;
        }
        if let Some(number) = crate::parse_decimal::<u64>(number) {
            files.push(((number, compressed), dir_entry.path()));
        }
    }

    // While a rotated copy gets compressed both versions exist, of which only the uncompressed
    // one is complete.
    files.sort_by_key(|(key, _)| *key);
    files.dedup_by_key(|((number, _), _)| *number);

    Ok(files.into_iter().map(|(_, path)| path).collect())
}

fn is_compressed(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("gz" | "zst")
    )
}

fn decompress<R: Read + 'static>(reader: R, path: &Path) -> Result<Box<dyn Read>, io::Error> {
    Ok(
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("gz") => Box::new(flate2::read::MultiGzDecoder::new(reader)),
            Some("zst") => {
                let mut decoder = zstd::Decoder::new(reader)?;
                decoder.window_log_max(ZSTD_WINDOW_LOG_MAX)?;
                Box::new(decoder)
            }
            _ => Box::new(reader),
        },
    )
}

/// Reads one page of the entries of a log and its rotated copies that match a filter.
///
/// Pages go from the end of the log towards its start, then through the rotated copies from the
/// newest on, each from its end towards its start. A page holds the matches in that order, up to
/// `limit` or [`DEFAULT_LIMIT`], and a cursor for the next page, which continues right before the
/// last line the page looked at. So paging returns each matching line once, as long as the files
/// are only appended to and rotated. Lines are not reordered by their timestamps, as servers write
/// lines late at times and rotated copies can overlap, and a time range only filters.
///
/// Each page reads at most [`MAX_READ_BYTES`], fully parses at most [`MAX_PARSE_BYTES`] of lines,
/// and returns about 16 MiB of entries at most, or a single larger one. A page can thus end before
/// reaching the limit, also without any match, and still carry a cursor. Plain files are read in
/// windows of 1 MiB. Compressed copies can only be read from their start, so a page decompresses a
/// copy from its start up to where it continues. If that is more than a page may read, the page
/// skips the rest of the copy and reports it as gap, as it does for a damaged copy.
/// [`QueryResult::complete`] tells whether no page so far had a gap and no older lines are left.
///
/// A cursor identifies a file by its first lines, so it survives rotation and compression of the
/// file. It fails once the file got rotated away, or if it does not point at the start of a line.
/// The cursor of a page whose files had a gap remembers that, for later pages to report.
///
/// An unterminated last line of a file is ignored, as it is still being written or got cut off,
/// and so are lines that got appended to a file after a page went past them.
///
/// Fails with [`InvalidRequest`] if the limit or the cursor are invalid, and otherwise if rotation
/// keeps changing the files while opening them, or on errors reading them. Listing the files while
/// a rotation compresses a copy can make pages return entries twice, as the compressed copy appears
/// before the plain one gets removed, and makes continuing in these files fail.
pub fn query(
    path: &Path,
    format: LogFormat,
    filter: &AccessLogFilter,
    limit: Option<u64>,
    cursor: Option<&str>,
) -> Result<QueryResult, Error> {
    query_with_limits(
        path,
        format,
        filter,
        limit,
        Direction::Older(cursor),
        &LIMITS,
    )
}

/// Reads the entries of a log that match a filter and got logged after the position of a head
/// cursor, as [`QueryResult::head_cursor`] returns, newest first.
///
/// The page holds up to `limit` or [`DEFAULT_LIMIT`] of these, with a new head cursor for the next
/// call, and tells by [`QueryResult::complete`] whether it holds all of them. It reads at most as
/// much as a page of [`query`] does, so with more entries logged since, it holds the newest ones.
/// Fails like [`query`], also if the head cursor's file got rotated away.
pub fn query_newer(
    path: &Path,
    format: LogFormat,
    filter: &AccessLogFilter,
    limit: Option<u64>,
    head: &str,
) -> Result<QueryResult, Error> {
    query_with_limits(path, format, filter, limit, Direction::Newer(head), &LIMITS)
}

/// Where a page goes: towards older entries, from the end or a cursor on, or towards the end of the
/// log, from a head cursor on.
#[derive(Clone, Copy)]
enum Direction<'a> {
    Older(Option<&'a str>),
    Newer(&'a str),
}

fn query_with_limits(
    path: &Path,
    format: LogFormat,
    filter: &AccessLogFilter,
    limit: Option<u64>,
    direction: Direction,
    limits: &Limits,
) -> Result<QueryResult, Error> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(invalid(format!(
            "access log query limit must be between 1 and {MAX_LIMIT}"
        )));
    }
    let (cursor, head) = match direction {
        Direction::Older(cursor) => (cursor.map(Cursor::parse).transpose()?, None),
        Direction::Newer(head) => (None, Some(Cursor::parse(head)?)),
    };

    let files = open_log_files(path)?;
    let mut page = Page {
        filter,
        format,
        limit: limit as usize,
        limits,
        read: 0,
        parsed: 0,
        entries: Vec::new(),
        entry_bytes: 0,
        searched_back_to: None,
        invalid_lines: 0,
        gaps: Vec::new(),
    };

    // the end of the log at the start of the page, as it can grow while reading it
    let head_cursor = match cursor {
        None => page.head(&files)?,
        Some(_) => None,
    };
    if let Some(head) = head {
        return page.newer(&files, &head, head_cursor);
    }

    let (first, mut start) = match &cursor {
        Some(cursor) => (page.locate(&files, cursor)?, cursor.position),
        None => (0, Position::End),
    };

    let mut stop = None;
    for (index, file) in files.iter().enumerate().skip(first) {
        let outcome = match file.compressed {
            true => page.scan_compressed(file, start, 0)?,
            false => page.scan_plain(file, start, 0)?,
        };
        start = Position::End;
        match outcome {
            Outcome::Done => {}
            Outcome::Stopped(position) => {
                stop = Some((index, position));
                break;
            }
            Outcome::NotStarted => {
                stop = Some((index, Position::End));
                break;
            }
        }
    }

    let next_cursor = match stop {
        Some((index, position)) => page.cursor_at(&files, index, position)?,
        None => None,
    };
    let gap = cursor.is_some_and(|cursor| cursor.gap) || !page.gaps.is_empty();
    let next_cursor = next_cursor.map(|next| Cursor { gap, ..next }.to_string());

    Ok(QueryResult {
        complete: next_cursor.is_none() && !gap,
        entries: page.entries,
        next_cursor,
        head_cursor: head_cursor.map(|head| head.to_string()),
        gaps: page.gaps,
        searched_back_to: page.searched_back_to,
        invalid_lines: page.invalid_lines,
    })
}

struct LogFile {
    path: PathBuf,
    file: File,
    len: u64,
    compressed: bool,
}

impl LogFile {
    fn name(&self) -> String {
        match self.path.file_name() {
            Some(name) => name.to_string_lossy().into_owned(),
            None => self.path.to_string_lossy().into_owned(),
        }
    }
}

fn identity(metadata: &std::fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

/// Opens a log and its rotated copies, checking that no rotation renamed them in between.
///
/// Symbolic links and other special files are refused, as a privileged daemon reads these files in
/// a directory that the unprivileged one writing them controls.
fn open_log_files(path: &Path) -> Result<Vec<LogFile>, Error> {
    for attempt in 0..3 {
        if attempt > 0 {
            // give a rotation in progress time to finish its renames
            std::thread::sleep(Duration::from_millis(10));
        }

        let paths = log_files(path)?;
        let mut files = Vec::with_capacity(paths.len());
        let mut identities = Vec::with_capacity(paths.len());
        for path in &paths {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path);
            let file = match file {
                Ok(file) => file,
                Err(err) if err.kind() == io::ErrorKind::NotFound => break,
                Err(err) => bail!("unable to open log file {path:?} - {err}"),
            };
            let metadata = file
                .metadata()
                .map_err(|err| format_err!("unable to stat log file {path:?} - {err}"))?;
            if !metadata.is_file() {
                bail!("log file {path:?} is not a regular file");
            }
            identities.push(identity(&metadata));
            files.push(LogFile {
                path: path.clone(),
                file,
                len: metadata.len(),
                compressed: is_compressed(path),
            });
        }
        if files.len() < paths.len() {
            continue;
        }

        let mut unique = identities.clone();
        unique.sort_unstable();
        unique.dedup();
        let unchanged = log_files(path)? == paths
            && paths.iter().zip(&identities).all(|(path, id)| {
                std::fs::metadata(path).is_ok_and(|metadata| identity(&metadata) == *id)
            });
        if unique.len() == identities.len() && unchanged {
            return Ok(files);
        }
    }
    bail!("log files of {path:?} kept changing while opening them");
}

/// Where a page continues within a file: before this offset, which is the start of a line, or
/// within a line too long to read, which the page skips to its start first, or at the end of the
/// file, for a page that did not get to start reading it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Position {
    Line(u64),
    WithinLine(u64),
    End,
}

/// How scanning a file ended.
enum Outcome {
    /// It got to the start of the file.
    Done,
    /// The page is full or out of budget, and continues before this position.
    Stopped(Position),
    /// The budget left was not enough to start reading the file.
    NotStarted,
}

/// The position a page continues at, with the file it is in identified by its first lines, which
/// stay the same while the file grows and gets rotated, and whether earlier pages had a gap.
///
/// Formatted as `1.<lines>.<fingerprint>.<offset>.<flags>`, with the number of lines that make up
/// the fingerprint, the fingerprint as 16 hexadecimal digits, the decimal offset or `e` for the end
/// of the file, and the flags as a decimal number: 1 for a gap, 2 for an offset within a line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cursor {
    lines: usize,
    fingerprint: u64,
    position: Position,
    gap: bool,
}

impl Cursor {
    fn parse(text: &str) -> Result<Self, Error> {
        let invalid = || invalid("invalid access log cursor");
        if text.len() > MAX_CURSOR_LENGTH {
            return Err(invalid());
        }
        let mut parts = text.split('.');
        let mut next = || parts.next().ok_or_else(invalid);
        if next()? != "1" {
            return Err(invalid());
        }
        let lines: usize = crate::parse_decimal(next()?).ok_or_else(invalid)?;
        let fingerprint = next()?;
        if fingerprint.len() != 16 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid());
        }
        let fingerprint = u64::from_str_radix(fingerprint, 16).map_err(|_| invalid())?;
        let offset = match next()? {
            "e" => None,
            // offsets fit the integers of the API schema, as they show up in gaps
            offset => Some(
                crate::parse_decimal::<u64>(offset)
                    .filter(|&offset| offset <= i64::MAX as u64)
                    .ok_or_else(invalid)?,
            ),
        };
        let flags: u8 = crate::parse_decimal(next()?).ok_or_else(invalid)?;
        if parts.next().is_some() || !(1..=FINGERPRINT_LINES).contains(&lines) || flags > 3 {
            return Err(invalid());
        }

        let cursor = Self {
            lines,
            fingerprint,
            position: match (offset, flags & 2) {
                (Some(offset), 0) => Position::Line(offset),
                (Some(offset), _) => Position::WithinLine(offset),
                (None, 0) => Position::End,
                (None, _) => return Err(invalid()),
            },
            gap: flags & 1 != 0,
        };
        // only accept the canonical form, so equal positions have equal cursors
        if cursor.to_string() != text {
            return Err(invalid());
        }
        Ok(cursor)
    }
}

impl fmt::Display for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (offset, within_line) = match self.position {
            Position::Line(offset) => (offset.to_string(), false),
            Position::WithinLine(offset) => (offset.to_string(), true),
            Position::End => ("e".to_string(), false),
        };
        let flags = u8::from(self.gap) | (u8::from(within_line) << 1);
        write!(
            f,
            "1.{}.{:016x}.{offset}.{flags}",
            self.lines, self.fingerprint
        )
    }
}

/// The 64-bit FNV-1a hash, which stays the same across releases, unlike the hasher of the standard
/// library. Its input holds no secrets, so it needs no cryptographic strength.
struct Fnv(u64);

impl Fnv {
    fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 ^= u64::from(byte);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    fn write_field(&mut self, field: &[u8]) {
        self.write(&(field.len() as u32).to_le_bytes());
        self.write(field);
    }
}

/// A complete line of a compressed copy, kept to look at once the page reached its position.
struct Buffered {
    offset: u64,
    len: u64,
    /// The line without terminator, or nothing for a line too long to keep.
    line: Option<Vec<u8>>,
    /// The oldest time of the lines after this one that got skipped by their first fields.
    skipped_after: Option<i64>,
}

/// How to go on after looking at a line. The scan runs from the newest line to the oldest.
enum Look {
    /// The line is dealt with, continue with the next older one.
    Continue,
    /// Stop without taking the line, so the next page starts with it.
    Deferred,
    /// The line was taken and filled the page, so the next page starts with the next older one.
    PageFull,
}

struct Page<'a> {
    filter: &'a AccessLogFilter,
    format: LogFormat,
    limit: usize,
    limits: &'a Limits,
    read: u64,
    parsed: u64,
    entries: Vec<AccessLogEntry>,
    entry_bytes: usize,
    searched_back_to: Option<i64>,
    invalid_lines: u64,
    gaps: Vec<Gap>,
}

impl Page<'_> {
    fn note_time(&mut self, time: i64) {
        self.searched_back_to = Some(
            self.searched_back_to
                .map_or(time, |oldest| oldest.min(time)),
        );
    }

    /// Parses the fields a line starts with, returning the time if they show it does not match.
    /// Lines whose first fields fail to parse need parsing completely, to tell whether they are
    /// invalid.
    fn skim(&self, line: &[u8]) -> Option<i64> {
        // a quote ends the timestamp field, as none of the first fields contains one in practice
        let end = line.iter().position(|&b| b == b'"')?;
        let text = String::from_utf8_lossy(&line[..=end]);
        let prefix = Prefix::parse(&text).ok()?;
        (!self.filter.matches_prefix(&prefix)).then_some(prefix.time)
    }

    /// Looks at a complete line, without its terminator.
    fn look_at(&mut self, line: &[u8]) -> Look {
        if let Some(time) = self.skim(line) {
            self.note_time(time);
            return Look::Continue;
        }

        let len = line.len() as u64;
        if self.parsed + len > self.limits.parse {
            return Look::Deferred;
        }
        let entry = match parse_line(line, self.format) {
            Ok(entry) => entry,
            Err(_) => {
                self.parsed += len;
                self.invalid_lines += 1;
                return Look::Continue;
            }
        };

        if self.filter.matches(&entry) {
            let size = entry_size(&entry);
            // Always take one, as lossy decoding can make an entry larger than the limit.
            if !self.entries.is_empty() && self.entry_bytes + size > self.limits.entries {
                return Look::Deferred;
            }
            self.parsed += len;
            self.note_time(entry.time);
            self.entry_bytes += size;
            self.entries.push(entry);
            if self.entries.len() >= self.limit {
                return Look::PageFull;
            }
        } else {
            self.parsed += len;
            self.note_time(entry.time);
        }
        Look::Continue
    }

    /// Whether the page read nothing yet, so it always has the budget to get further.
    fn fresh(&self) -> bool {
        self.read == 0
    }

    /// Reads a plain file backwards in windows, from `start` on, down to the line at `floor`.
    fn scan_plain(
        &mut self,
        file: &LogFile,
        start: Position,
        floor: u64,
    ) -> Result<Outcome, Error> {
        let fresh = self.fresh();
        let read_at = |buf: &mut [u8], offset: u64| {
            file.file
                .read_exact_at(buf, offset)
                .map_err(|err| format_err!("unable to read log file {:?} - {err}", file.path))
        };

        // Drop either an unterminated tail or the remaining bytes of an oversized line.
        let (mut end, mut dropping) = match start {
            Position::End => (file.len, true),
            Position::Line(offset) => {
                check_line_start(file, offset)?;
                (offset, false)
            }
            Position::WithinLine(offset) => {
                if offset > file.len {
                    return Err(invalid(
                        "invalid access log cursor, beyond the end of the file",
                    ));
                }
                (offset, true)
            }
        };
        // Unknown until the first complete line boundary is found.
        let mut oldest = matches!(start, Position::Line(_)).then_some(end);
        // the part of a line that continues above the current window, with its line terminator
        let mut tail = Vec::new();

        while end > floor {
            let start = end.saturating_sub(self.limits.window as u64).max(floor);
            // also read the byte before the window, which tells if a line starts at the window
            let extra = u64::from(start > floor);
            let size = end - start + extra;
            if self.read + size > self.limits.read {
                return Ok(match (dropping, oldest) {
                    (false, Some(oldest)) => Outcome::Stopped(Position::Line(oldest)),
                    (_, None) if !fresh => Outcome::NotStarted,
                    _ => Outcome::Stopped(Position::WithinLine(end)),
                });
            }
            self.read += size;

            let mut region = vec![0; size as usize];
            read_at(&mut region, start - extra)?;

            if dropping {
                match region.iter().rposition(|&b| b == b'\n') {
                    Some(last) => {
                        region.truncate(last + 1);
                        dropping = false;
                        // An oversized line was already counted; an unterminated tail is ignored.
                        oldest = Some(start - extra + last as u64 + 1);
                    }
                    None => region.clear(),
                }
            } else {
                region.append(&mut tail);
            }

            // The prefix through the first newline belongs to a line starting before this window.
            let lines_start = match start == floor {
                true => 0,
                false => region
                    .iter()
                    .position(|&b| b == b'\n')
                    .map_or(region.len(), |first| first + 1),
            };

            let lines_offset = start - extra + lines_start as u64;
            let mut line_end = lines_offset + (region.len() - lines_start) as u64;
            for line in region[lines_start..].split_inclusive(|&b| b == b'\n').rev() {
                let line_start = line_end - line.len() as u64;
                if line.len() > MAX_LINE_LENGTH + 1 {
                    self.invalid_lines += 1;
                } else {
                    match self.look_at(&line[..line.len() - 1]) {
                        Look::Continue => {}
                        Look::Deferred => return Ok(Outcome::Stopped(Position::Line(line_end))),
                        Look::PageFull => {
                            return Ok(Outcome::Stopped(Position::Line(line_start)));
                        }
                    }
                }
                oldest = Some(line_start);
                line_end = line_start;
            }

            if start > floor && !dropping {
                region.truncate(lines_start);
                region.drain(..region.len().min(extra as usize));
                if region.len() > MAX_LINE_LENGTH {
                    self.invalid_lines += 1;
                    dropping = true;
                } else {
                    tail = region;
                }
            }

            end = start;
        }

        Ok(Outcome::Done)
    }

    /// Reads a compressed file up to `start`, keeping the lines that can match, then looks at
    /// these from the newest on.
    fn scan_compressed(
        &mut self,
        file: &LogFile,
        start: Position,
        floor: u64,
    ) -> Result<Outcome, Error> {
        let fresh = self.fresh();
        // a position within a line too long to read stems from before compressing the file
        let (resume, resume_offset) = match start {
            Position::End => (None, None),
            position @ (Position::Line(offset) | Position::WithinLine(offset)) => {
                (Some(position), Some(offset))
            }
        };
        if resume_offset == Some(0) {
            return Ok(Outcome::Done);
        }

        let budget = self.limits.read.saturating_sub(self.read);
        let read = Rc::new(Cell::new(0));
        let input_failed = Rc::new(Cell::new(false));
        let outcome = self.read_compressed(file, resume, floor, budget, &read, &input_failed);
        self.read += read.get();

        let Buffer {
            lines: buffered,
            evicted,
            skipped_before,
        } = match outcome {
            Ok(Decompressed::Reached(buffer)) => buffer,
            Ok(Decompressed::OutOfBudget { .. }) if !fresh => return Ok(Outcome::NotStarted),
            Ok(Decompressed::OutOfBudget { buffer, reached }) => {
                // even a page of its own cannot get further into this copy
                self.gaps.push(Gap {
                    file: file.name(),
                    reason: GapReason::TooLarge,
                    start: reached,
                    end: resume_offset,
                });
                buffer
            }
            Err(ReadError::Cursor(err)) => return Err(err),
            Err(ReadError::Io(err)) if input_failed.get() => {
                bail!("unable to read log file {:?} - {err}", file.path)
            }
            Err(ReadError::Io(err)) => {
                // a checksum only fails at the end of the data it covers, so nothing before the
                // error can be trusted
                log::warn!("skipping damaged log file {:?} - {err}", file.path);
                self.gaps.push(Gap {
                    file: file.name(),
                    reason: GapReason::Damaged,
                    start: 0,
                    end: resume_offset,
                });
                return Ok(Outcome::Done);
            }
        };

        let mut oldest = None;
        for item in buffered.into_iter().rev() {
            // the lines after this one were skipped, and are covered by now
            if let Some(time) = item.skipped_after {
                self.note_time(time);
            }
            match item.line {
                None => self.invalid_lines += 1,
                Some(line) => match self.look_at(&line) {
                    Look::Continue => {}
                    Look::Deferred => {
                        return Ok(Outcome::Stopped(Position::Line(item.offset + item.len)));
                    }
                    Look::PageFull => return Ok(Outcome::Stopped(Position::Line(item.offset))),
                },
            }
            oldest = Some(item.offset);
        }

        if evicted && let Some(oldest) = oldest {
            return Ok(Outcome::Stopped(Position::Line(oldest)));
        }
        if let Some(time) = skipped_before {
            self.note_time(time);
        }
        Ok(Outcome::Done)
    }

    /// Decompresses a file up to `resume`, or its end, keeping the lines from `floor` on that can
    /// match.
    fn read_compressed(
        &self,
        file: &LogFile,
        resume: Option<Position>,
        floor: u64,
        budget: u64,
        read: &Rc<Cell<u64>>,
        input_failed: &Rc<Cell<bool>>,
    ) -> Result<Decompressed, ReadError> {
        let input =
            InputReader::new(&file.file, read, budget, input_failed).map_err(ReadError::Io)?;
        let input_cut = Rc::clone(&input.cut);
        let decoder = decompress(input, &file.path).map_err(ReadError::Io)?;
        let cut = Rc::new(Cell::new(false));
        let produced = Rc::new(Cell::new(0));
        let reader = CountingReader {
            inner: decoder,
            read: Rc::clone(read),
            limit: budget,
            cut: Rc::clone(&cut),
            produced: Rc::clone(&produced),
        };
        let mut lines = LineReader::new(BufReader::new(reader));
        let invalid_cursor =
            |what| ReadError::Cursor(invalid(format!("invalid access log cursor, {what}")));

        let mut buffer = Buffer {
            lines: VecDeque::new(),
            evicted: false,
            skipped_before: None,
        };
        let mut buffered_bytes = 0;
        let min_time = |time: Option<i64>, other: i64| Some(time.map_or(other, |t| t.min(other)));

        loop {
            // stop before reading the line at the position, which could go beyond the budget
            if let Some(Position::Line(resume)) = resume {
                match lines.offset().cmp(&resume) {
                    std::cmp::Ordering::Less => {}
                    std::cmp::Ordering::Equal => return Ok(Decompressed::Reached(buffer)),
                    std::cmp::Ordering::Greater => {
                        return Err(invalid_cursor("not at the start of a line"));
                    }
                }
            }
            let (offset, len, line) = match lines.next_line() {
                Ok(Some(line)) => line,
                Ok(None) => break,
                // the decoder saw the compressed data end where the budget did
                Err(_) if input_cut.get() => break,
                Err(err) => return Err(ReadError::Io(err)),
            };
            if offset < floor {
                if offset + len > floor {
                    return Err(invalid_cursor("not at the start of a line"));
                }
                continue;
            }
            // Do not recount the oversized line containing the resume offset.
            if let Some(Position::WithinLine(within)) = resume
                && offset + len > within
            {
                if offset >= within {
                    return Err(invalid_cursor("not within a line"));
                }
                return Ok(Decompressed::Reached(buffer));
            }

            let line = match line {
                Line::TooLong(_) => None,
                Line::Complete(line) => {
                    if let Some(time) = self.skim(line) {
                        match buffer.lines.back_mut() {
                            Some(last) => last.skipped_after = min_time(last.skipped_after, time),
                            None => buffer.skipped_before = min_time(buffer.skipped_before, time),
                        }
                        continue;
                    }
                    Some(line.to_vec())
                }
            };
            buffered_bytes += buffered_size(&line);
            buffer.lines.push_back(Buffered {
                offset,
                len,
                line,
                skipped_after: None,
            });
            while buffered_bytes > self.limits.buffered && buffer.lines.len() > 1 {
                let first = buffer.lines.pop_front().unwrap();
                buffered_bytes -= buffered_size(&first.line);
                buffer.evicted = true;
                buffer.skipped_before = None;
            }
        }

        if cut.get() || input_cut.get() {
            // the line too long to read that the position is in was looked at by earlier pages
            if let Some(Position::WithinLine(within)) = resume
                && lines.offset() < within
                && produced.get() >= within
            {
                return Ok(Decompressed::Reached(buffer));
            }
            return Ok(Decompressed::OutOfBudget {
                buffer,
                reached: lines.offset(),
            });
        }
        // a position within a line can also be in an unterminated last one, which is ignored
        match resume {
            Some(Position::Line(resume)) if resume > lines.offset() => {
                return Err(invalid_cursor("beyond the end of the file"));
            }
            Some(Position::WithinLine(within)) if within > produced.get() => {
                return Err(invalid_cursor("beyond the end of the file"));
            }
            _ => (),
        }
        if floor > lines.offset() {
            return Err(invalid_cursor("beyond the end of the file"));
        }
        Ok(Decompressed::Reached(buffer))
    }

    /// Identifies a file by the fields of up to `lines` of its first lines that no client chose.
    ///
    /// This reads at most [`FINGERPRINT_BYTES`] of the file, so it depends only on what was written
    /// there. It does not count towards the page's budget, so a page that has to identify all files
    /// to find where it continues still gets further.
    fn identify(&self, file: &LogFile, lines: usize) -> Result<Identity, Error> {
        let read = Rc::new(Cell::new(0));
        let input_failed = Rc::new(Cell::new(false));
        let (fields, error) = match file.compressed {
            true => {
                // Bound compressed input as well as output, including streams that emit no lines.
                let input =
                    InputReader::new(&file.file, &read, 2 * FINGERPRINT_BYTES, &input_failed)?;
                match decompress(input, &file.path) {
                    Ok(decoder) => identifying_fields(decoder, lines),
                    Err(err) => (Vec::new(), Some(err)),
                }
            }
            false => identifying_fields(
                ReadAt {
                    file: &file.file,
                    offset: 0,
                    end: file.len,
                    read: &read,
                },
                lines,
            ),
        };

        if let Some(err) = &error
            && (input_failed.get() || !file.compressed)
        {
            bail!("unable to read log file {:?} - {err}", file.path);
        }
        if fields.is_empty() {
            return Ok(match error {
                Some(_) => Identity::Damaged,
                None => Identity::Empty,
            });
        }

        let mut hash = Fnv::new();
        hash.write_field(b"proxmox-access-log 1");
        hash.write(&(fields.len() as u32).to_le_bytes());
        for line in &fields {
            match line {
                Some(line) => line.iter().for_each(|field| hash.write_field(field)),
                None => hash.write(&u32::MAX.to_le_bytes()),
            }
        }
        // a copy damaged after its first lines can still be continued in, before the damage
        Ok(Identity::Lines(fields.len(), hash.0))
    }

    /// The position right after the newest complete line of the log, in the newest file holding
    /// one, as a cursor.
    fn head(&self, files: &[LogFile]) -> Result<Option<Cursor>, Error> {
        for file in files {
            let position = match file.compressed {
                true => Position::End,
                // Do not search beyond a maximum-length unfinished tail.
                false => match last_line_end(file, MAX_LINE_LENGTH as u64 + 1)? {
                    LineEnd::At(end) => Position::Line(end),
                    LineEnd::None => continue,
                    LineEnd::Unknown => return Ok(None),
                },
            };
            if let Identity::Lines(lines, fingerprint) = self.identify(file, FINGERPRINT_LINES)? {
                return Ok(Some(Cursor {
                    lines,
                    fingerprint,
                    position,
                    gap: false,
                }));
            }
        }
        Ok(None)
    }

    /// Reads the entries logged after the position of a head cursor, see [`query_newer`].
    fn newer(
        mut self,
        files: &[LogFile],
        head: &Cursor,
        head_cursor: Option<Cursor>,
    ) -> Result<QueryResult, Error> {
        let index = self.locate(files, head)?;
        let floor = match head.position {
            Position::Line(offset) => Some(offset),
            Position::End => None,
            Position::WithinLine(_) => return Err(invalid("invalid access log head cursor")),
        };

        let mut complete = true;
        for (current, file) in files.iter().enumerate().take(index + 1) {
            let floor = match (current == index, floor) {
                (false, _) => 0,
                (true, Some(floor)) => floor,
                // nothing in the file of the head got logged after its end
                (true, None) => break,
            };
            if floor > 0 && !file.compressed {
                check_line_start(file, floor)?;
            }
            let outcome = match file.compressed {
                true => self.scan_compressed(file, Position::End, floor)?,
                false => self.scan_plain(file, Position::End, floor)?,
            };
            match outcome {
                Outcome::Done => {}
                // the limit got reached with the first entry logged after the head
                Outcome::Stopped(Position::Line(position))
                    if current == index && position == floor => {}
                _ => {
                    complete = false;
                    break;
                }
            }
        }

        Ok(QueryResult {
            complete: complete && self.gaps.is_empty(),
            entries: self.entries,
            next_cursor: None,
            head_cursor: head_cursor.map(|head| head.to_string()),
            gaps: self.gaps,
            searched_back_to: self.searched_back_to,
            invalid_lines: self.invalid_lines,
        })
    }

    /// Finds the file a cursor points into.
    ///
    /// Rule out plain files that cannot contain the cursor's position. Checking a compressed
    /// file's line boundaries would require decompressing it.
    fn locate(&self, files: &[LogFile], cursor: &Cursor) -> Result<usize, Error> {
        let mut found = Vec::new();
        for (index, file) in files.iter().enumerate() {
            if self.identify(file, cursor.lines)?
                == Identity::Lines(cursor.lines, cursor.fingerprint)
            {
                found.push(index);
            }
        }
        if found.len() > 1 {
            let mut candidates = Vec::new();
            for index in found {
                if holds_position(&files[index], cursor.position)? {
                    candidates.push(index);
                }
            }
            found = candidates;
        }
        if found.len() > 1 {
            return Err(invalid(
                "cannot continue the access log query, as several log files match, which can \
                happen during rotation",
            ));
        }
        found.first().copied().ok_or_else(|| {
            invalid(
                "cannot continue the access log query, as the log file it got to was rotated \
                away, or the query was for another node",
            )
        })
    }

    /// The cursor continuing at `position` in the file at `index`, without the gap flag.
    ///
    /// A page that did not get to start reading a file continues at its end. If that file cannot
    /// be identified, it holds nothing to continue in, so the next one that can is used, reporting
    /// damaged files in between as gaps.
    fn cursor_at(
        &mut self,
        files: &[LogFile],
        index: usize,
        position: Position,
    ) -> Result<Option<Cursor>, Error> {
        for file in &files[index..] {
            match self.identify(file, FINGERPRINT_LINES)? {
                Identity::Lines(lines, fingerprint) => {
                    return Ok(Some(Cursor {
                        lines,
                        fingerprint,
                        position,
                        gap: false,
                    }));
                }
                _ if position != Position::End => {
                    bail!("unable to identify log file {:?}", file.path)
                }
                Identity::Empty => {}
                Identity::Damaged => {
                    log::warn!("skipping damaged log file {:?}", file.path);
                    self.gaps.push(Gap {
                        file: file.name(),
                        reason: GapReason::Damaged,
                        start: 0,
                        end: None,
                    });
                }
            }
        }
        Ok(None)
    }
}

/// Where the last complete line of a plain file ends.
enum LineEnd {
    At(u64),
    /// The file holds no complete line.
    None,
    /// No complete line ends within the bytes looked at.
    Unknown,
}

/// Finds where the last complete line of a plain file ends, reading at most `max_read` bytes from
/// its end.
fn last_line_end(file: &LogFile, max_read: u64) -> Result<LineEnd, Error> {
    let mut end = file.len;
    let floor = file.len.saturating_sub(max_read);
    while end > floor {
        let start = end.saturating_sub(64 * 1024).max(floor);
        let mut region = vec![0; (end - start) as usize];
        file.file
            .read_exact_at(&mut region, start)
            .map_err(|err| format_err!("unable to read log file {:?} - {err}", file.path))?;
        if let Some(last) = region.iter().rposition(|&b| b == b'\n') {
            return Ok(LineEnd::At(start + last as u64 + 1));
        }
        end = start;
    }
    Ok(match floor {
        0 => LineEnd::None,
        _ => LineEnd::Unknown,
    })
}

/// Whether a file can hold a position: an uncompressed one only if it is not beyond its end and,
/// for a line start, follows a line end.
fn holds_position(file: &LogFile, position: Position) -> Result<bool, Error> {
    match position {
        _ if file.compressed => Ok(true),
        Position::End => Ok(true),
        Position::WithinLine(offset) => Ok(offset <= file.len),
        Position::Line(offset) => match check_line_start(file, offset) {
            Ok(()) => Ok(true),
            Err(err) if err.is::<InvalidRequest>() => Ok(false),
            Err(err) => Err(err),
        },
    }
}

/// Checks that a position in a plain file is at the start of a line.
fn check_line_start(file: &LogFile, offset: u64) -> Result<(), Error> {
    if offset > file.len {
        return Err(invalid(
            "invalid access log cursor, beyond the end of the file",
        ));
    }
    if offset > 0 {
        let mut before = [0];
        file.file
            .read_exact_at(&mut before, offset - 1)
            .map_err(|err| format_err!("unable to read log file {:?} - {err}", file.path))?;
        if before[0] != b'\n' {
            return Err(invalid(
                "invalid access log cursor, not at the start of a line",
            ));
        }
    }
    Ok(())
}

/// What identifies a file in a cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Identity {
    /// The fingerprint of this many first lines.
    Lines(usize, u64),
    /// The file holds no complete line.
    Empty,
    /// The compressed copy is damaged before its first complete line.
    Damaged,
}

/// The address, auth-id and timestamp fields of lines, or nothing for an invalid line.
type Fields = Vec<Option<[Vec<u8>; 3]>>;

/// Reads the fields of up to `lines` first lines that no client chose, stopping at an error, which
/// is returned too. A line too long to read, also one going beyond [`FINGERPRINT_BYTES`], counts
/// with the fields its first bytes hold, and a line without them with a marker.
fn identifying_fields<R: Read>(reader: R, lines: usize) -> (Fields, Option<io::Error>) {
    let mut reader = LineReader::new(BufReader::new(reader.take(FINGERPRINT_BYTES)));
    let mut fields = Vec::with_capacity(lines);
    while fields.len() < lines {
        let line = match reader.next_line() {
            Ok(Some((_, _, Line::Complete(line) | Line::TooLong(line)))) => line,
            Ok(None) => {
                if reader.get_ref().get_ref().limit() == 0 {
                    fields.push(prefix_fields(reader.pending()));
                }
                break;
            }
            Err(err) => return (fields, Some(err)),
        };
        fields.push(prefix_fields(line));
    }
    (fields, None)
}

/// The address, auth-id and timestamp fields at the start of a line, which the servers write
/// before any client text.
fn prefix_fields(line: &[u8]) -> Option<[Vec<u8>; 3]> {
    let end = line.iter().position(|&b| b == b'"')?;
    let prefix = Prefix::parse(std::str::from_utf8(&line[..=end]).ok()?).ok()?;
    Some(prefix.raw.map(|field| field.as_bytes().to_vec()))
}

/// The memory a buffered line takes, which also counts for empty ones and ones too long to keep.
fn buffered_size(line: &Option<Vec<u8>>) -> usize {
    std::mem::size_of::<Buffered>() + line.as_ref().map_or(0, Vec::len)
}

/// The approximate memory an entry takes.
fn entry_size(entry: &AccessLogEntry) -> usize {
    let text = |field: &Option<String>| field.as_ref().map_or(0, String::len);
    std::mem::size_of::<AccessLogEntry>()
        + text(&entry.auth_id)
        + text(&entry.method)
        + text(&entry.uri)
        + text(&entry.http_version)
        + text(&entry.request_line)
        + text(&entry.user_agent)
}

/// The lines of a compressed copy kept to look at.
struct Buffer {
    lines: VecDeque<Buffered>,
    /// Whether older lines that can match got dropped, to keep the buffer's size limit.
    evicted: bool,
    /// The oldest time of the skipped lines before the first one kept, unless that got evicted.
    skipped_before: Option<i64>,
}

/// How decompressing a file up to the position a page continues at went.
enum Decompressed {
    Reached(Buffer),
    /// The budget ended before, after reading the lines up to this offset.
    OutOfBudget {
        buffer: Buffer,
        reached: u64,
    },
}

enum ReadError {
    Cursor(Error),
    Io(io::Error),
}

/// Reads a file from an offset up to a fixed end, as the file can grow while reading it.
struct ReadAt<'a> {
    file: &'a File,
    offset: u64,
    end: u64,
    read: &'a Cell<u64>,
}

impl Read for ReadAt<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.end.saturating_sub(self.offset);
        let len = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        let read = self.file.read_at(&mut buf[..len], self.offset)?;
        self.offset += read as u64;
        self.read.set(self.read.get() + read as u64);
        Ok(read)
    }
}

/// Reads a file from its start, independent of other readers of the same file description, counts
/// the compressed data read and notes a failure to read the file itself, to tell it apart from
/// damaged compressed data.
///
/// It ends the data once the count reaches a limit, noting that, as compressed data can be large
/// without producing any output, like with skippable zstd frames or empty gzip members.
struct InputReader {
    inner: File,
    offset: u64,
    read: Rc<Cell<u64>>,
    limit: u64,
    cut: Rc<Cell<bool>>,
    failed: Rc<Cell<bool>>,
}

impl InputReader {
    fn new(
        file: &File,
        read: &Rc<Cell<u64>>,
        limit: u64,
        failed: &Rc<Cell<bool>>,
    ) -> io::Result<Self> {
        Ok(Self {
            inner: file.try_clone().inspect_err(|_| failed.set(true))?,
            offset: 0,
            read: Rc::clone(read),
            limit,
            cut: Rc::new(Cell::new(false)),
            failed: Rc::clone(failed),
        })
    }
}

impl Read for InputReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.limit.saturating_sub(self.read.get());
        if left == 0 && !buf.is_empty() {
            // tell the end of the budget from the end of the file
            let mut probe = [0];
            let more = self
                .inner
                .read_at(&mut probe, self.offset)
                .inspect_err(|_| self.failed.set(true))?;
            if more > 0 {
                self.cut.set(true);
            }
            return Ok(0);
        }
        let len = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        let read = self
            .inner
            .read_at(&mut buf[..len], self.offset)
            .inspect_err(|_| self.failed.set(true))?;
        self.offset += read as u64;
        self.read.set(self.read.get() + read as u64);
        Ok(read)
    }
}

/// Counts the bytes produced by a decoder on top of the compressed data it read, and ends the data
/// once the count reaches a limit, noting whether there was more.
struct CountingReader<R> {
    inner: R,
    read: Rc<Cell<u64>>,
    limit: u64,
    cut: Rc<Cell<bool>>,
    /// The decompressed data produced.
    produced: Rc<Cell<u64>>,
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cut.get() || buf.is_empty() {
            return Ok(0);
        }
        let left = self.limit.saturating_sub(self.read.get());
        if left == 0 {
            // Probe for EOF: input and output can exhaust the budget exactly at stream end.
            let mut probe = [0];
            if self.inner.read(&mut probe)? > 0 {
                self.cut.set(true);
            }
            return Ok(0);
        }
        let len = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        let read = self.inner.read(&mut buf[..len])?;
        self.read.set(self.read.get() + read as u64);
        self.produced.set(self.produced.get() + read as u64);
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(file: usize, number: usize) -> String {
        let user = if number.is_multiple_of(3) {
            "root@pam"
        } else {
            "-"
        };
        // older copies hold older lines, like after rotation
        format!(
            "192.0.2.10 - {user} [22/10/2026:{:02}:{:02}:{:02} +0000] \"GET /{file}/{number}\" 200 5 -\n",
            20 - file,
            number / 60 % 60,
            number % 60,
        )
    }

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(test: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("access-log-query-{test}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn write(&self, name: &str, data: &[u8]) {
            std::fs::write(self.0.join(name), data).unwrap();
        }

        fn log(&self) -> PathBuf {
            self.0.join("access.log")
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn zstd(data: &[u8]) -> Vec<u8> {
        zstd::encode_all(data, 0).unwrap()
    }

    const UNLIMITED: Limits = Limits {
        read: u64::MAX,
        parse: u64::MAX,
        buffered: usize::MAX,
        entries: usize::MAX,
        window: WINDOW_SIZE,
    };

    fn paths(result: &QueryResult) -> Vec<String> {
        result
            .entries
            .iter()
            .map(|entry| entry.uri.clone().unwrap())
            .collect()
    }

    /// Follows the cursors from the first page on, returning the paths of all entries and the
    /// pages.
    fn all_pages(
        path: &Path,
        filter: &AccessLogFilter,
        limit: Option<u64>,
        limits: &Limits,
    ) -> (Vec<String>, Vec<QueryResult>) {
        let mut found = Vec::new();
        let mut pages: Vec<QueryResult> = Vec::new();
        let mut cursor = None;
        loop {
            let result = query_with_limits(
                path,
                LogFormat::RestServer,
                filter,
                limit,
                Direction::Older(cursor.as_deref()),
                limits,
            )
            .unwrap();
            assert!(result.entries.len() <= limit.unwrap_or(DEFAULT_LIMIT) as usize);
            found.extend(paths(&result));
            cursor = result.next_cursor.clone();
            if let (Some(last), Some(current)) = (
                pages.last().and_then(|page| page.next_cursor.as_ref()),
                cursor.as_ref(),
            ) {
                assert!(last != current || !result.entries.is_empty(), "no progress");
            }
            pages.push(result);
            if cursor.is_none() {
                return (found, pages);
            }
            assert!(pages.len() < 10_000, "too many pages");
        }
    }

    /// A log with 20 lines in the current file, the last one unterminated, and 10 lines in each of
    /// three rotated copies, of which two are compressed, with an invalid line in two files.
    fn rotated_log(test: &str) -> (TestDir, Vec<String>) {
        let dir = TestDir::new(test);
        let copy = |file: usize, count: usize| -> String {
            (0..count).map(|number| line(file, number)).collect()
        };

        let mut current = copy(0, 20);
        current.push_str(&line(0, 20)[..30]);
        dir.write("access.log", current.as_bytes());
        dir.write(
            "access.log.1",
            (copy(1, 5) + "invalid\n" + &copy(1, 10)[..]).as_bytes(),
        );
        dir.write("access.log.2.gz", &gzip(copy(2, 10).as_bytes()));
        dir.write(
            "access.log.3.zst",
            &zstd(("invalid\n".to_string() + &copy(3, 10)).as_bytes()),
        );

        let expected = [(0, 0..20), (1, 0..10), (1, 0..5), (2, 0..10), (3, 0..10)]
            .into_iter()
            .flat_map(|(file, numbers)| {
                numbers.rev().map(move |number| format!("/{file}/{number}"))
            })
            .collect();

        (dir, expected)
    }

    #[test]
    fn pages_cover_each_line_once() {
        let (dir, expected) = rotated_log("cover");
        for limit in [1, 2, 3, 7, 1000] {
            for window in [7, 64, 4096] {
                let filter = AccessLogFilter::default();
                let filter_limit = Some(limit);
                let limits = Limits {
                    window,
                    ..UNLIMITED
                };
                let (found, pages) = all_pages(&dir.log(), &filter, filter_limit, &limits);
                assert_eq!(found, expected, "limit {limit}, window {window}");
                assert!(pages.last().unwrap().complete);
                assert!(pages.iter().all(|page| page.gaps.is_empty()));
                let invalid: u64 = pages.iter().map(|page| page.invalid_lines).sum();
                assert_eq!(invalid, 2, "limit {limit}, window {window}");
            }
        }
    }

    #[test]
    fn pages_with_small_budgets() {
        let (dir, expected) = rotated_log("budgets");
        // the longest lines, of root@pam
        let line_len = line(0, 0).len();
        // the largest copy has to fit, else it gets skipped as gap
        let copy_len = 11 * line_len as u64;
        for (read, parse, buffered, entries) in [
            (2 * copy_len, u64::MAX, usize::MAX, usize::MAX),
            (2 * copy_len, line_len as u64, usize::MAX, usize::MAX),
            (2 * copy_len, u64::MAX, 1, usize::MAX),
            (2 * copy_len, u64::MAX, 3 * line_len, 400),
            (2 * copy_len, 3 * line_len as u64, 2 * line_len, 600),
        ] {
            let limits = Limits {
                read,
                parse,
                buffered,
                entries,
                window: 64,
            };
            let (found, pages) = all_pages(&dir.log(), &AccessLogFilter::default(), None, &limits);
            assert_eq!(found, expected, "{read} {parse} {buffered} {entries}");
            assert!(pages.last().unwrap().complete);
        }
    }

    #[test]
    fn filtered_pages() {
        let (dir, expected) = rotated_log("filtered");
        let filter = AccessLogFilter {
            auth_id: Some("root@pam".into()),
            ..Default::default()
        };
        let filter_limit = Some(2);
        let limits = Limits {
            buffered: 2 * line(0, 1).len(),
            window: 64,
            ..UNLIMITED
        };
        let (found, pages) = all_pages(&dir.log(), &filter, filter_limit, &limits);
        let expected: Vec<_> = expected
            .into_iter()
            .filter(|path| path.rsplit('/').next().unwrap().parse::<usize>().unwrap() % 3 == 0)
            .collect();
        assert_eq!(found, expected);
        assert!(pages.last().unwrap().complete);

        let filter = AccessLogFilter {
            auth_id: Some("nobody@pam".into()),
            ..Default::default()
        };
        let result = query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            &filter,
            filter_limit,
            Direction::Older(None),
            &UNLIMITED,
        )
        .unwrap();
        assert!(result.entries.is_empty());
        assert!(result.complete);
        assert_eq!(result.searched_back_to, Some(1792688400));
    }

    #[test]
    fn rotation_between_pages() {
        let (dir, expected) = rotated_log("rotation");
        let filter = AccessLogFilter::default();
        let filter_limit = Some(25);
        let first = query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            &filter,
            filter_limit,
            Direction::Older(None),
            &UNLIMITED,
        )
        .unwrap();
        assert_eq!(paths(&first), expected[..25]);

        rotate(&dir);
        let path = |name: &str| dir.0.join(name);
        dir.write("access.log", line(9, 0).as_bytes());

        let mut found = paths(&first);
        let mut cursor = first.next_cursor;
        while let Some(current) = cursor {
            let result = query_with_limits(
                &dir.log(),
                LogFormat::RestServer,
                &filter,
                filter_limit,
                Direction::Older(Some(&current)),
                &UNLIMITED,
            )
            .unwrap();
            found.extend(paths(&result));
            cursor = result.next_cursor;
        }
        let kept = expected
            .iter()
            .filter(|path| !path.starts_with("/3/"))
            .count();
        assert_eq!(found, expected[..kept]);

        let filter = AccessLogFilter::default();
        let filter_limit = Some(1);
        let (_, pages) = all_pages(&dir.log(), &filter, filter_limit, &UNLIMITED);
        let into_oldest = pages[pages.len() - 2].next_cursor.clone().unwrap();
        std::fs::remove_file(path("access.log.3.gz")).unwrap();
        let err = query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            &filter,
            filter_limit,
            Direction::Older(Some(&into_oldest)),
            &UNLIMITED,
        )
        .unwrap_err();
        assert!(err.to_string().contains("rotated away"), "{err}");
    }

    #[test]
    fn invalid_cursors() {
        let (dir, _) = rotated_log("cursors");
        let filter = AccessLogFilter::default();
        let filter_limit = Some(3);
        let first = query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            &filter,
            filter_limit,
            Direction::Older(None),
            &UNLIMITED,
        )
        .unwrap();
        let cursor = Cursor::parse(first.next_cursor.as_deref().unwrap()).unwrap();
        let Position::Line(offset) = cursor.position else {
            panic!("unexpected position");
        };

        let moved = |position| Cursor { position, ..cursor }.to_string();
        for invalid in [
            "".to_string(),
            "garbage".to_string(),
            first.next_cursor.clone().unwrap().replacen('1', "2", 1),
            first.next_cursor.clone().unwrap() + ".0",
            format!("1.{}.{:016X}.{offset}.0", cursor.lines, cursor.fingerprint),
            format!("1.{}.{:016x}.0{offset}.0", cursor.lines, cursor.fingerprint),
            format!("1.{}.{:016x}.{offset}.4", cursor.lines, cursor.fingerprint),
            format!("1.0.{:016x}.{offset}.0", cursor.fingerprint),
            moved(Position::Line(offset - 1)),
            moved(Position::Line(u64::MAX)),
            Cursor {
                fingerprint: cursor.fingerprint ^ 1,
                ..cursor
            }
            .to_string(),
        ] {
            assert!(
                query_with_limits(
                    &dir.log(),
                    LogFormat::RestServer,
                    &filter,
                    filter_limit,
                    Direction::Older(Some(&invalid)),
                    &UNLIMITED
                )
                .is_err_and(|err| err.is::<InvalidRequest>()),
                "{invalid}"
            );
        }

        let (_, pages) = all_pages(&dir.log(), &AccessLogFilter::default(), Some(1), &UNLIMITED);
        let last = pages[pages.len() - 2].next_cursor.as_deref().unwrap();
        let last = Cursor::parse(last).unwrap();
        let Position::Line(offset) = last.position else {
            panic!("unexpected position");
        };
        let crafted = Cursor {
            position: Position::Line(offset + 1),
            ..last
        };
        assert!(
            query_with_limits(
                &dir.log(),
                LogFormat::RestServer,
                &filter,
                filter_limit,
                Direction::Older(Some(&crafted.to_string())),
                &UNLIMITED
            )
            .is_err_and(|err| err.is::<InvalidRequest>())
        );

        for page in &pages[..pages.len() - 1] {
            let cursor = Cursor::parse(page.next_cursor.as_deref().unwrap()).unwrap();
            let crafted = Cursor {
                position: Position::WithinLine(1_000_000),
                ..cursor
            };
            assert!(
                query_with_limits(
                    &dir.log(),
                    LogFormat::RestServer,
                    &filter,
                    filter_limit,
                    Direction::Older(Some(&crafted.to_string())),
                    &UNLIMITED
                )
                .is_err_and(|err| err.is::<InvalidRequest>()),
                "{crafted}"
            );
        }
    }

    #[test]
    fn too_large_and_damaged_copies() {
        let (dir, expected) = rotated_log("gaps");
        let line_len = line(0, 10).len() as u64;

        // Allow only a prefix of the ten-line compressed copy.
        let limits = Limits {
            read: 5 * line_len + 100,
            window: 64,
            ..UNLIMITED
        };
        let (found, pages) = all_pages(&dir.log(), &AccessLogFilter::default(), None, &limits);
        let gaps: Vec<_> = pages.iter().flat_map(|page| &page.gaps).collect();
        assert!(!gaps.is_empty());
        assert!(gaps.iter().all(|gap| gap.reason == GapReason::TooLarge));
        assert!(!pages.last().unwrap().complete);
        assert!(found.iter().all(|path| expected.contains(path)));
        assert!(found.contains(&"/3/0".to_string()));
        assert!(found.contains(&"/2/0".to_string()));
        assert!(!found.contains(&"/2/9".to_string()));
        // Once set, the cursor's gap flag survives later pages.
        let first_gap = pages.iter().position(|page| !page.gaps.is_empty()).unwrap();
        assert!(pages[first_gap..].iter().all(|page| !page.complete));

        let copy: String = (0..10).map(|number| line(2, number)).collect();
        let zstd = zstd(copy.as_bytes());
        let gzip = gzip(copy.as_bytes());
        std::fs::remove_file(dir.0.join("access.log.2.gz")).unwrap();
        for (name, data) in [("access.log.2.zst", zstd), ("access.log.2.gz", gzip)] {
            let path = dir.0.join(name);
            std::fs::write(&path, &data[..data.len() - 10]).unwrap();

            let (found, pages) =
                all_pages(&dir.log(), &AccessLogFilter::default(), None, &UNLIMITED);
            let gaps: Vec<_> = pages.iter().flat_map(|page| &page.gaps).collect();
            assert_eq!(gaps.len(), 1, "{name}");
            assert_eq!(gaps[0].reason, GapReason::Damaged, "{name}");
            assert_eq!(gaps[0].file, name);
            assert!(!found.iter().any(|path| path.starts_with("/2/")), "{name}");
            assert!(found.contains(&"/3/0".to_string()), "{name}");
            assert!(!pages.last().unwrap().complete);

            std::fs::remove_file(&path).unwrap();
        }
    }

    #[test]
    fn earlier_gap_keeps_later_pages_incomplete() {
        let dir = TestDir::new("carried-gap");
        dir.write("access.log", line(0, 0).as_bytes());
        dir.write("access.log.1.gz", b"damaged gzip");
        let older: String = (0..4).map(|number| line(2, number)).collect();
        dir.write("access.log.2", older.as_bytes());
        let (found, pages) =
            all_pages(&dir.log(), &AccessLogFilter::default(), Some(2), &UNLIMITED);
        assert_eq!(found.len(), 5);
        assert!(pages.len() > 1);
        assert_eq!(pages[0].gaps.len(), 1);
        assert_eq!(pages[0].gaps[0].reason, GapReason::Damaged);
        assert!(pages[1..].iter().all(|page| page.gaps.is_empty()));
        assert!(pages.iter().all(|page| !page.complete));
        assert!(pages.last().unwrap().next_cursor.is_none());
    }

    #[test]
    fn line_too_long_to_read_in_one_page() {
        let dir = TestDir::new("long-line");
        let mut log = line(0, 0);
        log.push_str(&"x".repeat(3 * MAX_LINE_LENGTH));
        log.push('\n');
        log.push_str(&line(0, 1));
        dir.write("access.log", log.as_bytes());

        let limits = Limits {
            read: (MAX_LINE_LENGTH + 3 * 64 * 1024) as u64,
            window: 64 * 1024,
            ..UNLIMITED
        };
        let (found, pages) = all_pages(&dir.log(), &AccessLogFilter::default(), None, &limits);
        assert_eq!(found, ["/0/1", "/0/0"]);
        assert!(pages.len() >= 3);
        assert!(pages.last().unwrap().complete);
        let invalid: u64 = pages.iter().map(|page| page.invalid_lines).sum();
        assert_eq!(invalid, 1);
    }

    #[test]
    fn line_too_long_after_a_long_line() {
        // the line before the one too long to read spans windows itself, so a page can end
        // right after skipping to the start of the long one
        let dir = TestDir::new("long-lines");
        let window = 64 * 1024;
        let mut log = line(0, 0);
        log.push_str(&format!(
            "192.0.2.10 - - [22/10/2026:20:00:01 +0000] \"GET /{}\" 200 5 -\n",
            "a".repeat(3 * window)
        ));
        log.push_str(&"x".repeat(3 * MAX_LINE_LENGTH));
        log.push('\n');
        log.push_str(&line(0, 2));
        dir.write("access.log", log.as_bytes());

        for windows in 3..24 {
            let limits = Limits {
                read: (MAX_LINE_LENGTH + windows * window) as u64,
                window,
                ..UNLIMITED
            };
            let (found, pages) = all_pages(&dir.log(), &AccessLogFilter::default(), None, &limits);
            assert_eq!(found.len(), 3, "{windows}");
            assert_eq!(found[0], "/0/2");
            assert_eq!(found[2], "/0/0");
            let invalid: u64 = pages.iter().map(|page| page.invalid_lines).sum();
            assert_eq!(invalid, 1, "{windows}");
        }
    }

    #[test]
    fn unidentifiable_copies_between_pages() {
        let empty = zstd(b"");
        for (name, data) in [
            ("access.log.2.zst", empty.as_slice()),
            ("access.log.2.zst", &[0; 64][..]),
            ("access.log.2.gz", &[0; 64][..]),
        ] {
            let (dir, expected) = rotated_log("unidentifiable");
            let copy: String = (0..10).map(|number| line(3, number)).collect();
            std::fs::remove_file(dir.0.join("access.log.2.gz")).unwrap();
            dir.write(name, data);
            dir.write("access.log.3.zst", &zstd(copy.as_bytes()));
            let current_len = std::fs::metadata(dir.log()).unwrap().len();
            // pages end before the copies following the current file
            let limits = Limits {
                read: current_len + 20,
                window: 64,
                ..UNLIMITED
            };
            let (found, pages) = all_pages(&dir.log(), &AccessLogFilter::default(), None, &limits);
            let expected: Vec<_> = expected
                .into_iter()
                .filter(|path| !path.starts_with("/2/"))
                .collect();
            assert_eq!(found, expected, "{name} {data:?}");
            let gaps: Vec<_> = pages.iter().flat_map(|page| &page.gaps).collect();
            match data.iter().all(|&b| b == 0) {
                true => assert!(
                    gaps.len() == 1 && gaps[0].reason == GapReason::Damaged,
                    "{name}"
                ),
                false => assert!(gaps.is_empty(), "{name}"),
            }
        }
    }

    #[test]
    fn position_within_a_line_after_compression() {
        let dir = TestDir::new("within-compressed");
        let mut log = line(0, 0);
        log.push_str(&"x".repeat(3 * MAX_LINE_LENGTH));
        log.push('\n');
        log.push_str(&line(0, 1));
        dir.write("access.log", log.as_bytes());

        let limits = Limits {
            read: (MAX_LINE_LENGTH + 3 * 64 * 1024) as u64,
            window: 64 * 1024,
            ..UNLIMITED
        };
        let filter = AccessLogFilter::default();
        let first = query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            &filter,
            None,
            Direction::Older(None),
            &limits,
        )
        .unwrap();
        let cursor = first.next_cursor.unwrap();
        let Position::WithinLine(within) = Cursor::parse(&cursor).unwrap().position else {
            panic!("not within a line");
        };

        std::fs::remove_file(dir.log()).unwrap();
        dir.write("access.log.1.zst", &zstd(log.as_bytes()));
        dir.write("access.log", b"");
        // also when decompressing gets past the position, but not to the end of the long line
        for read in [within + 64 * 1024, 2 * log.len() as u64] {
            let limits = Limits { read, ..limits };
            let next = query_with_limits(
                &dir.log(),
                LogFormat::RestServer,
                &filter,
                None,
                Direction::Older(Some(&cursor)),
                &limits,
            )
            .unwrap();
            assert_eq!(paths(&next), ["/0/0"], "{read}");
            assert!(next.complete, "{read}");
        }
    }

    #[test]
    fn compressed_data_without_output() {
        // empty gzip members, which take reading without producing any data
        let dir = TestDir::new("without-output");
        let mut data: Vec<u8> = (0..5000).flat_map(|_| gzip(b"")).collect();
        data.extend(gzip(line(1, 0).as_bytes()));
        dir.write("access.log", b"");
        dir.write("access.log.1.gz", &data);

        let limits = Limits {
            read: 10 * 1024,
            ..UNLIMITED
        };
        let filter = AccessLogFilter::default();
        let page = query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            &filter,
            None,
            Direction::Older(None),
            &limits,
        )
        .unwrap();
        assert!(page.entries.is_empty());
        assert_eq!(page.gaps.len(), 1);
        assert_eq!(page.gaps[0].reason, GapReason::TooLarge);

        let page = query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            &filter,
            None,
            Direction::Older(None),
            &UNLIMITED,
        )
        .unwrap();
        assert_eq!(paths(&page), ["/1/0"]);
        assert!(page.complete);
    }

    #[test]
    fn no_gaps_at_the_edge_of_the_budget() {
        let dir = TestDir::new("budget-edge");
        let copy: String = (0..40).map(|number| line(1, number)).collect();
        let compressed = zstd(copy.as_bytes());
        dir.write("access.log", b"");
        dir.write("access.log.1.zst", &compressed);
        let expected: Vec<_> = (0..40).rev().map(|number| format!("/1/{number}")).collect();

        let whole = (copy.len() + compressed.len()) as u64;
        for read in copy.len() as u64 / 2..whole + 100 {
            let limits = Limits {
                read,
                window: 64,
                ..UNLIMITED
            };
            let filter = AccessLogFilter::default();
            let filter_limit = Some(7);
            let (found, pages) = all_pages(&dir.log(), &filter, filter_limit, &limits);
            // Unconsumed compressed bytes may be only the trailer, so an open-ended gap can start
            // at EOF.
            for gap in pages.iter().flat_map(|page| &page.gaps) {
                match gap.end {
                    Some(end) => assert!(gap.start < end, "{read} {gap:?}"),
                    None => assert!(gap.start <= copy.len() as u64, "{read} {gap:?}"),
                }
            }
            if read >= whole {
                assert_eq!(found, expected, "{read}");
                assert!(pages.last().unwrap().complete, "{read}");
            }
        }
    }

    #[test]
    fn buffered_lines_count_with_their_overhead() {
        let dir = TestDir::new("overhead");
        let mut copy = line(1, 0);
        copy.push_str(&"\n".repeat(5000));
        copy.push_str(&line(1, 1));
        dir.write("access.log", b"");
        dir.write("access.log.1.zst", &zstd(copy.as_bytes()));

        let limits = Limits {
            buffered: 100 * std::mem::size_of::<Buffered>(),
            ..UNLIMITED
        };
        let (found, pages) = all_pages(&dir.log(), &AccessLogFilter::default(), None, &limits);
        assert_eq!(found, ["/1/1", "/1/0"]);
        assert!(pages.len() > 10);
        let invalid: u64 = pages.iter().map(|page| page.invalid_lines).sum();
        assert_eq!(invalid, 5000);
    }

    #[test]
    fn identification_reads_a_bounded_amount() {
        let (fields, error) = identifying_fields(std::io::repeat(b'x'), FINGERPRINT_LINES);
        assert!(error.is_none());
        assert_eq!(fields, [None]);
    }

    #[test]
    fn identification_of_lines_too_long() {
        let long = |second: usize| {
            format!(
                "192.0.2.10 - - [22/10/2026:20:00:{second:02} +0000] \"GET /{}\" 200 5 -\n",
                "a".repeat(MAX_LINE_LENGTH)
            )
        };
        let (first, _) = identifying_fields(long(1).as_bytes(), FINGERPRINT_LINES);
        let (second, _) = identifying_fields(long(2).as_bytes(), FINGERPRINT_LINES);
        assert_eq!(first.len(), 1);
        assert!(first[0].is_some());
        assert_ne!(first, second);

        let lines = FINGERPRINT_BYTES as usize / MAX_LINE_LENGTH + 2;
        let log: String = (0..lines).map(long).collect();
        let (fields, error) = identifying_fields(log.as_bytes(), FINGERPRINT_LINES);
        assert!(error.is_none());
        assert_eq!(fields.len(), lines - 1);
        assert!(fields.iter().all(Option::is_some));
    }

    #[test]
    fn files_without_identifying_fields() {
        let dir = TestDir::new("no-fields");
        let copy: String = (0..10).map(|number| line(1, number)).collect();
        dir.write("access.log.1", format!("invalid line\n{copy}").as_bytes());
        dir.write("access.log", b"invalid\n");
        let filter = AccessLogFilter::default();
        let first = query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            &filter,
            None,
            Direction::Older(None),
            &UNLIMITED,
        )
        .unwrap();
        let head = first.head_cursor.unwrap();
        append(&dir, "access.log", &line(0, 0));
        // only the current file has a line start at the cursor
        assert_eq!(paths(&newer(&dir, &filter, None, &head)), ["/0/0"]);

        dir.write("access.log.1", format!("invalid\n{copy}").as_bytes());
        let err = query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            &filter,
            None,
            Direction::Newer(&head),
            &UNLIMITED,
        )
        .unwrap_err();
        assert!(err.is::<InvalidRequest>(), "{err}");
        assert!(err.to_string().contains("several log files"), "{err}");
    }

    #[test]
    fn position_probe_propagates_read_failure() {
        let dir = TestDir::new("position-read-failure");
        dir.write("access.log", b"invalid\n");
        let files = open_log_files(&dir.log()).unwrap();
        let file = &files[0];
        assert!(holds_position(file, Position::Line(8)).unwrap());
        assert!(!holds_position(file, Position::Line(7)).unwrap());
        assert!(!holds_position(file, Position::Line(9)).unwrap());
        assert!(holds_position(file, Position::WithinLine(7)).unwrap());
        assert!(!holds_position(file, Position::WithinLine(9)).unwrap());
        dir.write("access.log", b"");
        let error = holds_position(file, Position::Line(8)).unwrap_err();
        assert!(!error.is::<InvalidRequest>(), "{error}");
        assert!(error.to_string().contains("unable to read log file"));
    }

    fn longest_pve_log() -> String {
        // A request line of up to 520 KiB plus one read of 128 KiB, with up to four bytes logged
        // for each, after an auth-id that fills the 8 KiB header limit.
        let raw = (512 + 8 + 128) * 1024 - 1;
        let request = format!("{} / HTTP/1.1", "\\xFF".repeat(raw - " / HTTP/1.1".len()));
        let longest = format!(
            "::ffff:192.0.2.10 - user@pve!{} [22/10/2026:20:00:00 +0000] \"{request}\" 501 -\n",
            "t".repeat(8 * 1024)
        );
        assert!(longest.len() <= MAX_LINE_LENGTH);
        let line = |second: usize| {
            format!(
                "192.0.2.10 - - [22/10/2026:20:00:{second:02} +0000] \"GET /{second} HTTP/1.1\" \
                 200 5\n"
            )
        };
        line(1) + &longest + &line(2)
    }

    #[test]
    fn longest_pve_http_server_lines() {
        let data = longest_pve_log();
        let dir = TestDir::new("longest-pve");
        dir.write("access.log", data.as_bytes());
        dir.write("access.log.1.gz", &gzip(data.as_bytes()));

        let filter = AccessLogFilter {
            min_status: Some(500),
            ..Default::default()
        };
        for (filter, count) in [(AccessLogFilter::default(), 6), (filter, 2)] {
            let result = query_with_limits(
                &dir.log(),
                LogFormat::PveHttpServer,
                &filter,
                None,
                Direction::Older(None),
                &LIMITS,
            )
            .unwrap();
            assert_eq!(result.entries.len(), count);
            assert_eq!(result.invalid_lines, 0);
            assert!(result.complete);
        }
    }

    #[test]
    fn single_oversized_entry_advances() {
        let dir = TestDir::new("oversized-entry");
        let mut log = b"192.0.2.10 - - [22/10/2026:20:00:00 +0000] \"x\t".to_vec();
        log.extend(std::iter::repeat_n(0xff, MAX_LINE_LENGTH - 100));
        log.extend_from_slice(b" / HTTP/1.1\" 501 -\n");
        dir.write("access.log", &log);
        let first = query_with_limits(
            &dir.log(),
            LogFormat::PveHttpServer,
            &AccessLogFilter::default(),
            None,
            Direction::Older(None),
            &LIMITS,
        )
        .unwrap();
        assert_eq!(first.entries.len(), 1);
        assert!(first.complete);
        assert!(entry_size(&first.entries[0]) > MAX_ENTRY_BYTES);
    }

    #[test]
    fn page_ends_before_the_next_file() {
        let (dir, expected) = rotated_log("next-file");
        let current_len = std::fs::metadata(dir.log()).unwrap().len();
        // enough for the current file, but not for the windows of `.1`
        let limits = Limits {
            read: current_len + 20,
            window: 64,
            ..UNLIMITED
        };
        let first = query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            &AccessLogFilter::default(),
            None,
            Direction::Older(None),
            &limits,
        )
        .unwrap();
        assert_eq!(paths(&first), expected[..20]);
        let cursor = Cursor::parse(first.next_cursor.as_deref().unwrap()).unwrap();
        assert_eq!(cursor.position, Position::End);

        let (found, _) = all_pages(&dir.log(), &AccessLogFilter::default(), None, &limits);
        assert_eq!(found, expected);
    }

    fn append(dir: &TestDir, name: &str, data: &str) {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(dir.0.join(name))
            .unwrap();
        file.write_all(data.as_bytes()).unwrap();
    }

    fn newer(
        dir: &TestDir,
        filter: &AccessLogFilter,
        limit: Option<u64>,
        head: &str,
    ) -> QueryResult {
        query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            filter,
            limit,
            Direction::Newer(head),
            &UNLIMITED,
        )
        .unwrap()
    }

    /// Rotates like proxmox-sys does, compressing `.1` and keeping three copies.
    fn rotate(dir: &TestDir) {
        let path = |name: &str| dir.0.join(name);
        let _ = std::fs::remove_file(path("access.log.3.zst"));
        let _ = std::fs::remove_file(path("access.log.3.gz"));
        for (from, to) in [
            ("access.log.2.gz", "access.log.3.gz"),
            ("access.log.2.zst", "access.log.3.zst"),
        ] {
            if path(from).exists() {
                std::fs::rename(path(from), path(to)).unwrap();
            }
        }
        let copy_1 = std::fs::read(path("access.log.1")).unwrap();
        dir.write("access.log.2.zst", &zstd(&copy_1));
        std::fs::remove_file(path("access.log.1")).unwrap();
        std::fs::rename(path("access.log"), path("access.log.1")).unwrap();
        dir.write("access.log", b"");
    }

    #[test]
    fn newer_entries_after_appends() {
        let (dir, expected) = rotated_log("newer");
        let filter = AccessLogFilter::default();
        let first = query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            &filter,
            None,
            Direction::Older(None),
            &UNLIMITED,
        )
        .unwrap();
        assert_eq!(paths(&first), expected);
        let first_head = first.head_cursor.unwrap();
        let head = first_head.clone();

        let nothing = newer(&dir, &filter, None, &head);
        assert!(nothing.entries.is_empty());
        assert!(nothing.complete);
        assert_eq!(nothing.next_cursor, None);
        assert_eq!(nothing.head_cursor.as_ref(), Some(&head));

        // the unterminated line gets completed, and one more gets started
        append(&dir, "access.log", &line(0, 20)[30..]);
        append(&dir, "access.log", &line(0, 21));
        append(&dir, "access.log", &line(0, 22)[..10]);
        let result = newer(&dir, &filter, None, &head);
        assert_eq!(paths(&result), ["/0/21", "/0/20"]);
        assert!(result.complete);
        let head = result.head_cursor.unwrap();

        append(&dir, "access.log", &line(0, 22)[10..]);
        let result = newer(&dir, &filter, None, &head);
        assert_eq!(paths(&result), ["/0/22"]);

        let root = AccessLogFilter {
            auth_id: Some("root@pam".into()),
            ..Default::default()
        };
        assert_eq!(paths(&newer(&dir, &root, None, &first_head)), ["/0/21"]);

        let limited = AccessLogFilter::default();
        let limited_limit = Some(3);
        let (_, pages) = all_pages(&dir.log(), &limited, limited_limit, &UNLIMITED);
        assert!(pages[0].head_cursor.is_some());
        assert!(pages[1..].iter().all(|page| page.head_cursor.is_none()));
    }

    #[test]
    fn newer_entries_across_rotation() {
        let (dir, _) = rotated_log("newer-rotation");
        let filter = AccessLogFilter::default();
        append(&dir, "access.log", &line(0, 20)[30..]);
        let first = query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            &filter,
            None,
            Direction::Older(None),
            &UNLIMITED,
        )
        .unwrap();
        let head = first.head_cursor.unwrap();

        append(&dir, "access.log", &line(0, 21));
        rotate(&dir);
        append(&dir, "access.log", &line(8, 0));
        let result = newer(&dir, &filter, None, &head);
        assert_eq!(paths(&result), ["/8/0", "/0/21"]);
        assert!(result.complete);

        // the copy of the head gets compressed, which keeps the position within it
        append(&dir, "access.log", &line(8, 1));
        rotate(&dir);
        append(&dir, "access.log", &line(9, 0));
        let result = newer(&dir, &filter, None, &head);
        assert_eq!(paths(&result), ["/9/0", "/8/1", "/8/0", "/0/21"]);
        assert!(result.complete);

        // the head of an empty current file is in the copy before it
        rotate(&dir);
        let result = query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            &filter,
            None,
            Direction::Older(None),
            &UNLIMITED,
        )
        .unwrap();
        let head = result.head_cursor.unwrap();
        append(&dir, "access.log", &line(9, 1));
        assert_eq!(paths(&newer(&dir, &filter, None, &head)), ["/9/1"]);

        for _ in 0..3 {
            rotate(&dir);
        }
        let err = query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            &filter,
            None,
            Direction::Newer(&head),
            &UNLIMITED,
        )
        .unwrap_err();
        assert!(err.to_string().contains("rotated away"), "{err}");
    }

    #[test]
    fn newer_entries_up_to_the_limit() {
        let (dir, _) = rotated_log("newer-limit");
        let filter = AccessLogFilter::default();
        let filter_limit = Some(2);
        let first = query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            &filter,
            filter_limit,
            Direction::Older(None),
            &UNLIMITED,
        )
        .unwrap();
        let head = first.head_cursor.unwrap();
        append(&dir, "access.log", &line(0, 20)[30..]);
        append(&dir, "access.log", &line(0, 21));
        append(&dir, "access.log", &line(0, 22));
        let result = newer(&dir, &filter, filter_limit, &head);
        assert_eq!(paths(&result), ["/0/22", "/0/21"]);
        assert!(!result.complete);
        assert_eq!(result.next_cursor, None);
        assert!(result.head_cursor.is_some());
    }

    #[test]
    fn invalid_head_cursors() {
        let (dir, _) = rotated_log("newer-invalid");
        let filter = AccessLogFilter::default();
        let first = query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            &filter,
            None,
            Direction::Older(None),
            &UNLIMITED,
        )
        .unwrap();
        let head = Cursor::parse(first.head_cursor.as_deref().unwrap()).unwrap();
        let Position::Line(offset) = head.position else {
            panic!("unexpected position");
        };
        let moved = |position| Cursor { position, ..head }.to_string();
        for invalid in [
            moved(Position::Line(offset - 1)),
            moved(Position::Line(offset + 1)),
            moved(Position::WithinLine(offset)),
        ] {
            assert!(
                query_with_limits(
                    &dir.log(),
                    LogFormat::RestServer,
                    &filter,
                    None,
                    Direction::Newer(&invalid),
                    &UNLIMITED
                )
                .is_err_and(|err| err.is::<InvalidRequest>()),
                "{invalid}"
            );
        }

        let data = std::fs::read(dir.log()).unwrap();
        dir.write("access.log", &data[..offset as usize - 1]);
        assert!(
            query_with_limits(
                &dir.log(),
                LogFormat::RestServer,
                &filter,
                None,
                Direction::Newer(&head.to_string()),
                &UNLIMITED
            )
            .is_err_and(|err| err.is::<InvalidRequest>())
        );

        dir.write("access.log", &data);
        rotate(&dir);
        rotate(&dir);
        for crafted in [
            moved(Position::Line(offset - 1)),
            moved(Position::Line(offset << 20)),
        ] {
            assert!(
                query_with_limits(
                    &dir.log(),
                    LogFormat::RestServer,
                    &filter,
                    None,
                    Direction::Newer(&crafted),
                    &UNLIMITED
                )
                .is_err_and(|err| err.is::<InvalidRequest>()),
                "{crafted}"
            );
        }
        let result = newer(&dir, &filter, None, &head.to_string());
        assert!(result.entries.is_empty());
        assert!(result.complete);
    }

    #[test]
    fn head_before_a_long_partial_tail() {
        let dir = TestDir::new("newer-tail");
        dir.write("access.log.1", line(1, 0).as_bytes());
        let tail = "x".repeat(MAX_LINE_LENGTH);
        dir.write("access.log", (line(0, 0) + &tail).as_bytes());
        let filter = AccessLogFilter::default();
        let first = query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            &filter,
            None,
            Direction::Older(None),
            &UNLIMITED,
        )
        .unwrap();
        assert_eq!(paths(&first), ["/0/0", "/1/0"]);
        let head = first.head_cursor.unwrap();
        assert!(newer(&dir, &filter, None, &head).entries.is_empty());

        append(&dir, "access.log", &("\n".to_string() + &line(0, 1)));
        let result = newer(&dir, &filter, None, &head);
        assert_eq!(paths(&result), ["/0/1"]);
        assert_eq!(result.invalid_lines, 1);

        // behind a tail longer than any line there is no head, however large the budget
        dir.write("access.log", (line(0, 0) + &tail + "x").as_bytes());
        let first = query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            &filter,
            None,
            Direction::Older(None),
            &UNLIMITED,
        )
        .unwrap();
        assert_eq!(paths(&first), ["/0/0", "/1/0"]);
        assert_eq!(first.head_cursor, None);
    }

    #[test]
    fn newer_entries_filling_the_limit() {
        let (dir, _) = rotated_log("newer-full");
        let filter = AccessLogFilter::default();
        let filter_limit = Some(2);
        let first = query_with_limits(
            &dir.log(),
            LogFormat::RestServer,
            &filter,
            filter_limit,
            Direction::Older(None),
            &UNLIMITED,
        )
        .unwrap();
        let head = first.head_cursor.unwrap();
        append(&dir, "access.log", &line(0, 20)[30..]);
        append(&dir, "access.log", &line(0, 21));
        let result = newer(&dir, &filter, filter_limit, &head);
        assert_eq!(paths(&result), ["/0/21", "/0/20"]);
        assert!(result.complete);

        append(&dir, "access.log", &line(0, 22));
        rotate(&dir);
        rotate(&dir);
        let filter = AccessLogFilter::default();
        let filter_limit = Some(1);
        let result = newer(&dir, &filter, filter_limit, &result.head_cursor.unwrap());
        assert_eq!(paths(&result), ["/0/22"]);
        assert!(result.complete);
    }
}
