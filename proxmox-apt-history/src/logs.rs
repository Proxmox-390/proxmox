use std::io::BufRead;
use std::path::{Path, PathBuf};

use crate::{
    APT_LOG_DIR, Error, HISTORY_LOG_NAME, HistoryEntry, HistoryListOptions, HistoryParser,
    TERM_LOG_NAME, TermLogFormat, TermLogParser, clean_terminal_output, open_log_file,
    rotated_log_files,
};

/// Lists the entries of the APT history log, including the rotated ones, newest first.
///
/// Entries that cannot be parsed are skipped with a warning, so that a single corrupted entry does
/// not hide the rest of the history. If a file cannot be read, the listing stops there with a
/// warning, so it only contains the entries of the newer files, or fails if there are none.
pub fn list_history(options: &HistoryListOptions) -> Result<Vec<HistoryEntry>, Error> {
    list_history_from(
        open_logs(Path::new(APT_LOG_DIR), HISTORY_LOG_NAME)?,
        options,
    )
}

/// Returns the terminal output of the transaction with the given start time and start index, see
/// [`HistoryEntry::start_index`], in the given format.
///
/// Returns `None` if the terminal log has no output for it, for example because logrotate already
/// removed it, or an error if a file that could contain it cannot be read or has damaged sections.
pub fn get_term_log(
    start_time: i64,
    start_index: u32,
    format: TermLogFormat,
) -> Result<Option<String>, Error> {
    let logs = open_logs(Path::new(APT_LOG_DIR), TERM_LOG_NAME)?;
    get_term_log_from(logs, start_time, start_index, format)
}

type LogReader = Box<dyn BufRead + Send>;

/// A log file and its reader, or the error opening it.
type OpenedLog = (PathBuf, Result<LogReader, Error>);

/// Opens all files of a log right away, newest first, which narrows the window in which a log
/// rotation can make a file be read twice or skipped, but does not close it, as listing and opening
/// the files is not atomic.
fn open_logs(dir: &Path, name: &str) -> Result<Vec<OpenedLog>, Error> {
    Ok(rotated_log_files(dir, name)?
        .into_iter()
        .map(|path| {
            let reader = open_log_file(&path);
            (path, reader)
        })
        .collect())
}

fn list_history_from(
    logs: Vec<OpenedLog>,
    options: &HistoryListOptions,
) -> Result<Vec<HistoryEntry>, Error> {
    let limit = options.limit.map_or(usize::MAX, |limit| {
        usize::try_from(limit).unwrap_or(usize::MAX)
    });
    let mut entries = Vec::new();

    for (path, reader) in logs {
        if entries.len() >= limit {
            break;
        }

        match reader.and_then(|reader| read_history(&path, reader, options)) {
            Ok(file_entries) => entries.extend(file_entries.into_iter().rev()),
            Err(err) if entries.is_empty() => return Err(err),
            Err(err) => {
                log::warn!("listing APT history only up to {path:?} - {err}");
                break;
            }
        }
    }

    entries.truncate(limit);
    Ok(entries)
}

/// Reads the matching entries of a history log file, oldest first.
fn read_history(
    path: &Path,
    reader: LogReader,
    options: &HistoryListOptions,
) -> Result<Vec<HistoryEntry>, Error> {
    let mut entries = Vec::new();

    for entry in HistoryParser::new(reader) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err @ Error::Parse { .. }) => {
                log::warn!("skipping APT history entry in {path:?} - {err}");
                continue;
            }
            Err(Error::Io(error)) => {
                return Err(Error::File {
                    path: path.to_owned(),
                    error,
                });
            }
            Err(err) => return Err(err),
        };

        if options.since.is_some_and(|since| entry.start_time < since)
            || options.until.is_some_and(|until| entry.start_time > until)
        {
            continue;
        }
        if let Some(package) = &options.package
            && !entry
                .packages
                .iter()
                .any(|change| &change.package == package)
        {
            continue;
        }
        entries.push(entry);
    }

    Ok(entries)
}

fn get_term_log_from(
    logs: Vec<OpenedLog>,
    start_time: i64,
    start_index: u32,
    format: TermLogFormat,
) -> Result<Option<String>, Error> {
    let mut first_error = None;

    // Search all files, the timestamps alone cannot tell which one to stop at, as the clock can
    // be set back.
    for (path, reader) in logs {
        let reader = match reader {
            Ok(reader) => reader,
            Err(err) => {
                first_error.get_or_insert(err);
                continue;
            }
        };

        for section in TermLogParser::new(reader) {
            match section {
                Ok(section)
                    if section.start_time == start_time && section.start_index == start_index =>
                {
                    return Ok(Some(clean_terminal_output(&section.output, format)));
                }
                Ok(_) => (),
                // a damaged section could be the one looked for, so report it if none matches
                Err(Error::Parse { line, message }) => {
                    first_error.get_or_insert(Error::Parse {
                        line,
                        message: format!("{message} in {path:?}"),
                    });
                }
                Err(Error::Io(error)) => {
                    first_error.get_or_insert(Error::File {
                        path: path.clone(),
                        error,
                    });
                }
                Err(err) => {
                    first_error.get_or_insert(err);
                }
            }
        }
    }

    match first_error {
        Some(err) => Err(err),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;
    use crate::time::parse_log_time;

    fn time(value: &str) -> i64 {
        parse_log_time(value).expect("valid test timestamp")
    }

    /// Reader that fails after yielding its content, like a truncated compressed file.
    struct Truncated(&'static [u8]);

    impl io::Read for Truncated {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "corrupt"));
            }
            self.0.read(buf)
        }
    }

    enum Log {
        Valid(&'static str),
        Unreadable,
        Truncated(&'static str),
    }

    /// In-memory logs, newest first.
    fn logs(contents: &[Log]) -> Vec<OpenedLog> {
        contents
            .iter()
            .enumerate()
            .map(|(index, content)| {
                let path = PathBuf::from(format!("log.{index}"));
                let reader: Result<LogReader, Error> = match content {
                    Log::Valid(content) => Ok(Box::new(content.as_bytes())),
                    Log::Truncated(content) => {
                        Ok(Box::new(io::BufReader::new(Truncated(content.as_bytes()))))
                    }
                    Log::Unreadable => Err(Error::File {
                        path: path.clone(),
                        error: io::ErrorKind::PermissionDenied.into(),
                    }),
                };
                (path, reader)
            })
            .collect()
    }

    const HISTORY_LOG: &str = "
Start-Date: 2026-10-02  10:00:00
Upgrade: foo:amd64 (1.0, 1.1)
End-Date: 2026-10-02  10:00:10

Start-Date: 2026-10-02  11:00:00
Install: bar:amd64 (2.0)
End-Date: 2026-10-02  11:00:10

Start-Date: 2026-10-02  12:00:00
Upgrade: corrupted
End-Date: 2026-10-02  12:00:10

Start-Date: 2026-10-02  13:00:00
Upgrade: foo:amd64 (1.1, 1.2), bar:amd64 (2.0, 2.1)
End-Date: 2026-10-02  13:00:10
";

    const HISTORY_LOG_1: &str = "
Start-Date: 2026-09-02  10:00:00
Install: foo:amd64 (1.0)
End-Date: 2026-09-02  10:00:10
";

    fn list(options: HistoryListOptions, contents: &[Log]) -> Vec<i64> {
        list_history_from(logs(contents), &options)
            .expect("listing history")
            .into_iter()
            .map(|entry| entry.start_time)
            .collect()
    }

    #[test]
    fn list_options_from_strings() {
        // the Perl API handlers pass their parameters on as is, including the node
        let options: HistoryListOptions = serde_json::from_value(serde_json::json!({
            "node": "localhost",
            "since": "1790000000",
            "until": 1800000000,
            "limit": "10",
        }))
        .expect("valid options");
        assert_eq!(
            options,
            HistoryListOptions {
                since: Some(1790000000),
                until: Some(1800000000),
                package: None,
                limit: Some(10),
            }
        );

        let options: HistoryListOptions =
            serde_json::from_value(serde_json::json!({})).expect("valid options");
        assert_eq!(options, HistoryListOptions::default());
    }

    #[test]
    fn list_history_entries() {
        let all = [Log::Valid(HISTORY_LOG), Log::Valid(HISTORY_LOG_1)];

        assert_eq!(
            list(HistoryListOptions::default(), &all),
            [
                time("2026-10-02  13:00:00"),
                time("2026-10-02  11:00:00"),
                time("2026-10-02  10:00:00"),
                time("2026-09-02  10:00:00"),
            ]
        );

        assert_eq!(
            list(
                HistoryListOptions {
                    package: Some("foo".to_string()),
                    ..Default::default()
                },
                &all
            ),
            [
                time("2026-10-02  13:00:00"),
                time("2026-10-02  10:00:00"),
                time("2026-09-02  10:00:00"),
            ]
        );

        assert_eq!(
            list(
                HistoryListOptions {
                    since: Some(time("2026-10-02  10:30:00")),
                    until: Some(time("2026-10-02  12:30:00")),
                    ..Default::default()
                },
                &all
            ),
            [time("2026-10-02  11:00:00")]
        );

        assert_eq!(
            list(
                HistoryListOptions {
                    limit: Some(2),
                    ..Default::default()
                },
                &all
            ),
            [time("2026-10-02  13:00:00"), time("2026-10-02  11:00:00")]
        );
    }

    #[test]
    fn list_history_after_clock_set_back() {
        // the newest file has older timestamps than the rotated one
        let logs = [Log::Valid(HISTORY_LOG_1), Log::Valid(HISTORY_LOG)];
        assert_eq!(
            list(
                HistoryListOptions {
                    since: Some(time("2026-10-02  12:30:00")),
                    ..Default::default()
                },
                &logs
            ),
            [time("2026-10-02  13:00:00")]
        );
    }

    #[test]
    fn list_history_with_unreadable_files() {
        let options = HistoryListOptions::default;

        for older in [Log::Unreadable, Log::Truncated(HISTORY_LOG_1)] {
            assert_eq!(
                list(options(), &[Log::Valid(HISTORY_LOG), older]),
                [
                    time("2026-10-02  13:00:00"),
                    time("2026-10-02  11:00:00"),
                    time("2026-10-02  10:00:00"),
                ]
            );
        }

        // does not need to read an older file if the limit is reached
        assert_eq!(
            list(
                HistoryListOptions {
                    limit: Some(1),
                    ..Default::default()
                },
                &[Log::Valid(HISTORY_LOG), Log::Unreadable]
            ),
            [time("2026-10-02  13:00:00")]
        );

        for contents in [
            [Log::Unreadable, Log::Valid(HISTORY_LOG_1)],
            [Log::Truncated(HISTORY_LOG), Log::Valid(HISTORY_LOG_1)],
            [Log::Valid(""), Log::Unreadable],
        ] {
            let err = list_history_from(logs(&contents), &options()).expect_err("unreadable file");
            assert!(matches!(err, Error::File { .. }), "{err:?}");
        }
        let err = list_history_from(
            logs(&[Log::Valid(HISTORY_LOG_1), Log::Unreadable]),
            &HistoryListOptions {
                package: Some("bar".to_string()),
                ..Default::default()
            },
        )
        .expect_err("unreadable file");
        assert!(matches!(err, Error::File { .. }), "{err:?}");
    }

    const TERM_LOG: &str = "
Log started: 2026-10-02  10:00:00
Setting up foo (1.1) ...\r
Log ended: 2026-10-02  10:00:10

Log started: 2026-10-02  13:00:00
\x1b[1mSetting up foo (1.2) ...\x1b[0m\r
Log ended: 2026-10-02  13:00:10

Log started: 2026-10-02  13:00:00
Setting up foo (1.3) ...\r
Log ended: 2026-10-02  13:00:10
";

    const TERM_LOG_1: &str = "
Log started: 2026-09-02  10:00:00
Setting up foo (1.0) ...\r
Log ended: 2026-09-02  10:00:10
";

    #[test]
    fn find_term_log() {
        let get = |contents: &[Log], start_time, start_index| {
            get_term_log_from(
                logs(contents),
                start_time,
                start_index,
                TermLogFormat::Plain,
            )
        };
        let all = [Log::Valid(TERM_LOG), Log::Valid(TERM_LOG_1)];

        assert_eq!(
            get(&all, time("2026-10-02  13:00:00"), 0).expect("valid logs"),
            Some("Setting up foo (1.2) ...\n".to_string())
        );
        assert_eq!(
            get(&all, time("2026-10-02  13:00:00"), 1).expect("valid logs"),
            Some("Setting up foo (1.3) ...\n".to_string())
        );
        assert_eq!(
            get(&all, time("2026-09-02  10:00:00"), 0).expect("valid logs"),
            Some("Setting up foo (1.0) ...\n".to_string())
        );
        assert_eq!(
            get(&all, time("2026-10-02  11:00:00"), 0).expect("valid logs"),
            None
        );
        assert_eq!(
            get(&all, time("2026-10-02  13:00:00"), 2).expect("valid logs"),
            None
        );

        // found in an older file after the clock was set back, or behind an unreadable file
        for contents in [
            [Log::Valid(TERM_LOG_1), Log::Valid(TERM_LOG)],
            [Log::Unreadable, Log::Valid(TERM_LOG)],
            [Log::Truncated(TERM_LOG_1), Log::Valid(TERM_LOG)],
        ] {
            assert_eq!(
                get(&contents, time("2026-10-02  13:00:00"), 1).expect("found output"),
                Some("Setting up foo (1.3) ...\n".to_string())
            );
        }

        let err = get(
            &[Log::Valid(TERM_LOG), Log::Unreadable],
            time("2026-10-02  11:00:00"),
            0,
        )
        .expect_err("unreadable file");
        assert!(matches!(err, Error::File { .. }), "{err:?}");
    }

    const DAMAGED_TERM_LOG: &str = "
Log started: 2026-10-02  11:00:00
Setting up bar (2.0) ...\r
Log ended: damaged
";

    #[test]
    fn find_term_log_with_damaged_sections() {
        let get = |contents: &[Log], start_time| {
            get_term_log_from(logs(contents), start_time, 0, TermLogFormat::Plain)
        };

        // not found, but a section that could be the one looked for is damaged
        let err = get(
            &[Log::Valid(DAMAGED_TERM_LOG)],
            time("2026-10-02  11:00:00"),
        )
        .expect_err("damaged section");
        assert!(matches!(err, Error::Parse { .. }), "{err:?}");
        assert!(err.to_string().contains("log.0"), "{err}");

        let err = get(
            &[Log::Valid(DAMAGED_TERM_LOG), Log::Unreadable],
            time("2026-10-02  11:00:00"),
        )
        .expect_err("damaged section");
        assert!(matches!(err, Error::Parse { .. }), "{err:?}");

        assert_eq!(
            get(
                &[Log::Valid(DAMAGED_TERM_LOG), Log::Valid(TERM_LOG)],
                time("2026-10-02  13:00:00")
            )
            .expect("found output"),
            Some("Setting up foo (1.2) ...\n".to_string())
        );
    }
}
