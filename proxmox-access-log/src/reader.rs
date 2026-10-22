use std::io::{BufRead, Read};

use crate::{AccessLogEntry, LogFormat, ParseError};

/// Lines longer than this are skipped as invalid without retaining them in full. PVE can accept
/// about 648 KiB of request line: its 520 KiB buffer limit plus one read of up to 128 KiB. Escaping
/// expands each byte up to fourfold; this bound also leaves room for the server-written fields.
/// proxmox-rest-server truncates URI and user agent.
pub(crate) const MAX_LINE_LENGTH: usize = 3 * 1024 * 1024;

/// An error reading an access log.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to read access log - {0}")]
    Io(#[from] std::io::Error),
    #[error("line {line}: {error}")]
    Parse { line: u64, error: ParseError },
}

/// A line read by a [`LineReader`].
pub(crate) enum Line<'a> {
    /// A complete line, without its line terminator.
    Complete(&'a [u8]),
    /// A line longer than [`MAX_LINE_LENGTH`], which got skipped, with its first bytes.
    TooLong(#[allow(dead_code)] &'a [u8]),
}

/// Reads the lines of a log, skipping lines too long to stem from the servers without keeping them
/// in memory.
///
/// A last line without line terminator is ignored, as the servers terminate every line they log,
/// so it is either still being written or the rest of it got lost.
pub(crate) struct LineReader<R> {
    reader: R,
    buffer: Vec<u8>,
    offset: u64,
}

impl<R: BufRead> LineReader<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: Vec::new(),
            offset: 0,
        }
    }

    /// The offset of the next line, which is the number of bytes read in lines so far.
    pub(crate) fn offset(&self) -> u64 {
        self.offset
    }

    /// Reads the next line, returning it with the offset it starts at and its length, including
    /// its line terminator.
    pub(crate) fn next_line(&mut self) -> std::io::Result<Option<(u64, u64, Line<'_>)>> {
        let offset = self.offset;
        self.buffer.clear();
        let limit = MAX_LINE_LENGTH as u64 + 1;
        let read = (&mut self.reader)
            .take(limit)
            .read_until(b'\n', &mut self.buffer)?;

        if self.buffer.ends_with(b"\n") {
            self.offset += read as u64;
            self.buffer.pop();
            return Ok(Some((offset, read as u64, Line::Complete(&self.buffer))));
        }
        if self.buffer.len() <= MAX_LINE_LENGTH {
            return Ok(None);
        }

        // An oversized tail is invalid only after its newline is found.
        let mut len = read as u64;
        loop {
            let available = self.reader.fill_buf()?;
            if available.is_empty() {
                return Ok(None);
            }
            let (consumed, terminated) = match available.iter().position(|&b| b == b'\n') {
                Some(end) => (end + 1, true),
                None => (available.len(), false),
            };
            self.reader.consume(consumed);
            len += consumed as u64;
            if terminated {
                self.offset += len;
                return Ok(Some((offset, len, Line::TooLong(&self.buffer))));
            }
        }
    }
}

/// An iterator over the entries of an access log.
///
/// A line that fails to parse yields an [`Error::Parse`], iteration continues with the next line.
/// After an [`Error::Io`] iteration ends, as the reader cannot be expected to recover.
///
/// A last line without line terminator is skipped, as the servers terminate every line they log,
/// so it is either still being written or the rest of it got lost.
pub struct AccessLogReader<R> {
    lines: LineReader<R>,
    format: LogFormat,
    line_number: u64,
    failed: bool,
}

impl<R: BufRead> AccessLogReader<R> {
    pub fn new(reader: R, format: LogFormat) -> Self {
        Self {
            lines: LineReader::new(reader),
            format,
            line_number: 0,
            failed: false,
        }
    }

    /// The number of the line last read, starting at 1.
    pub fn line_number(&self) -> u64 {
        self.line_number
    }

    /// The number of bytes of the lines read so far, including line terminators.
    pub fn bytes_read(&self) -> u64 {
        self.lines.offset()
    }
}

impl<R: BufRead> Iterator for AccessLogReader<R> {
    type Item = Result<AccessLogEntry, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }

        let format = self.format;
        let entry = match self.lines.next_line() {
            Ok(Some((_, _, Line::Complete(line)))) => parse_line(line, format),
            Ok(Some((_, _, Line::TooLong(_)))) => Err(ParseError::TooLong),
            Ok(None) => return None,
            Err(err) => {
                self.failed = true;
                return Some(Err(err.into()));
            }
        };
        self.line_number += 1;

        Some(entry.map_err(|error| Error::Parse {
            line: self.line_number,
            error,
        }))
    }
}

/// Parses a log line given as bytes, without its line terminator.
pub(crate) fn parse_line(line: &[u8], format: LogFormat) -> Result<AccessLogEntry, ParseError> {
    // Request lines of pve-http-server before 6.0.6 can contain any bytes except LF.
    AccessLogEntry::parse(&String::from_utf8_lossy(line), format)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_lines() {
        let log: &[u8] = b"\
            192.0.2.10 - root@pam [22/10/2026:14:03:51 +0200] \"GET / HTTP/1.1\" 200 5\n\
            garbage\n\
            192.0.2.10 - - [22/10/2026:14:03:52 +0200] \"\xff GET /\xfe HTTP/1.1\" 501 -\n\
            192.0.2.10 - - [22/10/2026:14:03:53 +0200] \"GET /x HTTP/1.1\" 404 0\n\
            192.0.2.10 - - [22/10/2026:14:03:54 +0200] \"GET /y HTTP/1.1\" 200 12";
        let mut reader = AccessLogReader::new(log, LogFormat::PveHttpServer);

        let entry = reader.next().unwrap().unwrap();
        assert_eq!(entry.auth_id.as_deref(), Some("root@pam"));
        assert_eq!(reader.line_number(), 1);

        assert!(matches!(
            reader.next(),
            Some(Err(Error::Parse {
                line: 2,
                error: ParseError::Client
            }))
        ));

        let entry = reader.next().unwrap().unwrap();
        assert_eq!(
            entry.request_line.as_deref(),
            Some("\u{fffd} GET /\u{fffd} HTTP/1.1")
        );
        assert_eq!(entry.uri.as_deref(), Some("/\u{fffd}"));

        let entry = reader.next().unwrap().unwrap();
        assert_eq!(entry.status, Some(404));
        assert_eq!(reader.line_number(), 4);

        assert!(reader.next().is_none());
        let last_line_start = log.iter().rposition(|&b| b == b'\n').unwrap() + 1;
        assert_eq!(reader.bytes_read(), last_line_start as u64);
    }

    #[test]
    fn too_long_line() {
        let line = "192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"GET / HTTP/1.1\" 200 5\n";
        let mut log = line.to_string();
        log.push_str(&"x".repeat(MAX_LINE_LENGTH + 10));
        log.push('\n');
        log.push_str(line);

        let mut reader = AccessLogReader::new(log.as_bytes(), LogFormat::PveHttpServer);
        assert!(reader.next().unwrap().is_ok());
        assert!(matches!(
            reader.next(),
            Some(Err(Error::Parse {
                line: 2,
                error: ParseError::TooLong
            }))
        ));
        assert!(reader.next().unwrap().is_ok());
        assert!(reader.next().is_none());
        assert_eq!(reader.bytes_read(), log.len() as u64);

        let mut log = line.to_string();
        log.push_str(&"x".repeat(MAX_LINE_LENGTH + 10));
        let mut reader = AccessLogReader::new(log.as_bytes(), LogFormat::PveHttpServer);
        assert!(reader.next().unwrap().is_ok());
        assert!(reader.next().is_none());
        assert_eq!(reader.bytes_read(), line.len() as u64);
    }
}
