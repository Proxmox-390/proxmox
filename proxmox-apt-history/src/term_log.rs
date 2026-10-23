use std::collections::HashMap;
use std::io::BufRead;

use crate::Error;
use crate::files::LineReader;
use crate::history::{next_start_index, quote};
use crate::time::parse_log_time;

/// Terminal output of one APT transaction, which can include several dpkg runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TermLogSection {
    /// Start time as Unix epoch, the same as of the corresponding history entry.
    pub start_time: i64,
    /// Number of earlier sections with the same start time in the same log file, the same as of
    /// the corresponding history entry, see [`HistoryEntry::start_index`](crate::HistoryEntry).
    pub start_index: u32,
    /// End time as Unix epoch, missing if the transaction is still running or got interrupted.
    pub end_time: Option<i64>,
    /// Output as recorded, including terminal control sequences and the carriage returns of
    /// progress updates, see [`clean_terminal_output`](crate::clean_terminal_output).
    pub output: String,
}

/// Iterator over the sections of an APT terminal log, oldest first.
///
/// APT frames the output of each transaction with `Log started` and `Log ended` lines, which carry
/// the same timestamps as the `Start-Date` and `End-Date` of the corresponding history log entry.
///
/// A section with an invalid timestamp yields an [`Error::Parse`], after which iteration continues
/// with the next section. Iteration ends after the first [`Error::Io`]. Like for the history log,
/// the start index counts the sections read by this parser, so it should be used for a whole file.
pub struct TermLogParser<R> {
    lines: LineReader<R>,
    /// Line number and date of a `Log started` line consumed while parsing the previous section.
    next_start: Option<(usize, String)>,
    start_indices: HashMap<i64, u32>,
    failed: bool,
}

impl<R: BufRead> TermLogParser<R> {
    /// Creates a parser for the terminal log read from `reader`.
    pub fn new(reader: R) -> Self {
        crate::time::update_time_zone();
        Self {
            lines: LineReader::new(reader),
            next_start: None,
            start_indices: HashMap::new(),
            failed: false,
        }
    }

    fn parse_section(&mut self) -> Result<Option<TermLogSection>, Error> {
        let (start_line, start_date) = match self.next_start.take() {
            Some(start) => start,
            None => loop {
                let Some(line) = self.lines.next_line()? else {
                    return Ok(None);
                };
                if let Some(value) = line.strip_prefix("Log started:") {
                    break (self.lines.line(), value.trim().to_string());
                }
            },
        };

        let mut problem = None;

        // Count the start even if the section turns out invalid, like for the history log.
        let start = parse_log_time(&start_date)
            .ok_or_else(|| format!("invalid start date {}", quote(&start_date)))
            .and_then(|start_time| {
                let index = next_start_index(&mut self.start_indices, start_time)
                    .ok_or_else(|| "too many transactions with the same start time".to_string())?;
                Ok((start_time, index))
            });
        let (start_time, start_index) = start.unwrap_or_else(|message| {
            problem = Some(message);
            (0, 0)
        });

        let mut section = TermLogSection {
            start_time,
            start_index,
            end_time: None,
            output: String::new(),
        };

        while let Some(line) = self.lines.next_line()? {
            if let Some(value) = line.strip_prefix("Log started:") {
                self.next_start = Some((self.lines.line(), value.trim().to_string()));
                // APT starts the next section on a new line, drop that line break
                if section.output.ends_with('\n') {
                    section.output.pop();
                }
                break;
            }
            if let Some(value) = line.strip_prefix("Log ended:") {
                let value = value.trim();
                section.end_time = parse_log_time(value);
                if section.end_time.is_none() {
                    problem.get_or_insert_with(|| format!("invalid end date {}", quote(value)));
                }
                break;
            }
            // APT appends the end marker directly to output not ending with a line break
            if let Some((output, value)) = line.rsplit_once("Log ended: ")
                && let Some(end_time) = parse_log_time(value)
            {
                section.output.push_str(output);
                section.end_time = Some(end_time);
                break;
            }
            section.output.push_str(&line);
        }

        match problem {
            Some(message) => Err(Error::Parse {
                line: start_line,
                message,
            }),
            None => Ok(Some(section)),
        }
    }
}

impl<R: BufRead> Iterator for TermLogParser<R> {
    type Item = Result<TermLogSection, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }

        match self.parse_section() {
            Ok(section) => section.map(Ok),
            Err(err) => {
                self.failed = matches!(err, Error::Io(_));
                Some(Err(err))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TermLogFormat, clean_terminal_output};

    const TERM_LOG: &str = concat!(
        "\n",
        "Log started: 2026-10-01  11:33:47\n",
        "(Reading database ... \r(Reading database ... 50%\r",
        "(Reading database ... 54231 files and directories currently installed.)\r\n",
        "Preparing to unpack .../pve-manager_9.2.2_amd64.deb ...\r\n",
        "\x1b[1mdpkg:\x1b[0m \x1b[1;33mwarning:\x1b[0m downgrading pve-manager:amd64\r\n",
        "Setting up pve-manager (9.2.2) ...\r\n",
        "Log ended: 2026-10-01  11:34:22\n",
        "\n",
        "\n",
        "Log started: 2026-10-02  07:05:11\n",
        "Selecting previously unselected package tshark.\r\n",
        "\n",
        "Log started: 2026-10-02  07:34:02\n",
        "Log ended: 2026-10-02  07:34:10\n",
    );

    fn time(value: &str) -> i64 {
        parse_log_time(value).expect("valid test timestamp")
    }

    #[test]
    fn parse_term_log() {
        let sections = TermLogParser::new(TERM_LOG.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("valid terminal log");
        assert_eq!(sections.len(), 3);

        assert_eq!(sections[0].start_time, time("2026-10-01  11:33:47"));
        assert_eq!(sections[0].end_time, Some(time("2026-10-01  11:34:22")));
        assert!(sections[0].output.starts_with("(Reading database ... \r"));
        assert!(
            sections[0]
                .output
                .ends_with("Setting up pve-manager (9.2.2) ...\r\n")
        );
        assert_eq!(
            clean_terminal_output(&sections[0].output, TermLogFormat::Plain),
            "(Reading database ... 54231 files and directories currently installed.)\n\
             Preparing to unpack .../pve-manager_9.2.2_amd64.deb ...\n\
             dpkg: warning: downgrading pve-manager:amd64\n\
             Setting up pve-manager (9.2.2) ...\n",
        );

        assert_eq!(sections[1].start_time, time("2026-10-02  07:05:11"));
        assert_eq!(sections[1].end_time, None);
        assert_eq!(
            sections[1].output,
            "Selecting previously unselected package tshark.\r\n"
        );

        assert_eq!(sections[2].start_time, time("2026-10-02  07:34:02"));
        assert_eq!(sections[2].end_time, Some(time("2026-10-02  07:34:10")));
        assert_eq!(sections[2].output, "");
    }

    #[test]
    fn end_marker_after_output() {
        // as written by APT if the output does not end with a line break
        let log = "Log started: 2026-10-01  11:33:47\nno line break\
                   Log ended: 2026-10-01  11:34:22\n\n\
                   Log started: 2026-10-01  11:35:00\ninterrupted\n\
                   Log started: 2026-10-01  11:36:00\nmentions Log ended: in output\n";
        let sections = TermLogParser::new(log.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("valid terminal log");
        assert_eq!(sections.len(), 3);
        assert_eq!(sections[0].output, "no line break");
        assert_eq!(sections[0].end_time, Some(time("2026-10-01  11:34:22")));
        assert_eq!(sections[1].output, "interrupted");
        assert_eq!(sections[1].end_time, None);
        assert_eq!(sections[2].output, "mentions Log ended: in output\n");
        assert!(matches!(
            TermLogParser::new("Log started: 2026-10-01  11:36:00\nLog ended: never\n".as_bytes())
                .next(),
            Some(Err(Error::Parse { .. }))
        ));
    }

    #[test]
    fn same_start_time() {
        let log = "Log started: 2026-10-23  00:40:50\nfirst\nLog ended: 2026-10-23  00:40:50\n\
                   Log started: 2026-10-23  00:40:50\nsecond\nLog ended: 2026-10-23  00:40:51\n\
                   Log started: 2026-10-23  00:40:51\nthird\nLog ended: 2026-10-23  00:40:51\n";
        let indices: Vec<_> = TermLogParser::new(log.as_bytes())
            .map(|section| {
                let section = section.expect("valid section");
                (section.output, section.start_index)
            })
            .collect();
        assert_eq!(
            indices,
            [
                ("first\n".to_string(), 0),
                ("second\n".to_string(), 1),
                ("third\n".to_string(), 0)
            ]
        );
    }

    #[test]
    fn skip_invalid_sections() {
        let log = "Log started: never\nfoo\nLog ended: 2026-10-01  11:34:22\n\
                   Log started: 2026-10-01  11:33:47\nbar\nLog ended: 2026-10-01  11:34:22\n";
        let sections: Vec<_> = TermLogParser::new(log.as_bytes()).collect();
        assert_eq!(sections.len(), 2);
        assert!(matches!(sections[0], Err(Error::Parse { line: 1, .. })));
        assert_eq!(sections[1].as_ref().expect("valid section").output, "bar\n");
    }

    #[test]
    fn styled_output_matches_plain() {
        let sections = TermLogParser::new(TERM_LOG.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("valid terminal log");
        for section in sections {
            let text: String = crate::styled_segments(&clean_terminal_output(
                &section.output,
                TermLogFormat::Styled,
            ))
            .map(|(_, text)| text)
            .collect();
            assert_eq!(
                text,
                clean_terminal_output(&section.output, TermLogFormat::Plain)
            );
        }
    }
}
