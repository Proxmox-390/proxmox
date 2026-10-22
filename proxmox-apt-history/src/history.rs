use std::collections::HashMap;
use std::io::BufRead;

use crate::files::LineReader;
use crate::time::parse_log_time;
use crate::{Error, HistoryEntry, PackageAction, PackageChange};

/// Iterator over the entries of an APT history log, oldest first.
///
/// Lines with unknown keys are ignored. An entry that cannot be parsed yields an [`Error::Parse`],
/// after which iteration continues with the next entry. Iteration ends after the first
/// [`Error::Io`]. The [`HistoryEntry::start_index`] counts the entries of the log read by this
/// parser, so it should be used for a whole log file.
///
/// ```
/// use proxmox_apt_history::{HistoryParser, PackageAction};
///
/// let log = "
/// Start-Date: 2026-10-01  11:33:47
/// Commandline: apt full-upgrade
/// Upgrade: pve-manager:amd64 (9.1.1, 9.1.2)
/// End-Date: 2026-10-01  11:34:22
/// ";
///
/// let entries = HistoryParser::new(log.as_bytes()).collect::<Result<Vec<_>, _>>()?;
/// assert_eq!(entries.len(), 1);
/// assert_eq!(entries[0].command_line.as_deref(), Some("apt full-upgrade"));
/// assert_eq!(entries[0].packages[0].action, PackageAction::Upgrade);
/// assert_eq!(entries[0].packages[0].new_version.as_deref(), Some("9.1.2"));
/// # Ok::<(), proxmox_apt_history::Error>(())
/// ```
pub struct HistoryParser<R> {
    lines: LineReader<R>,
    /// Line number and date of a `Start-Date` line consumed while parsing the previous entry.
    next_start: Option<(usize, String)>,
    start_indices: HashMap<i64, u32>,
    failed: bool,
}

impl<R: BufRead> HistoryParser<R> {
    /// Creates a parser for the history log read from `reader`.
    pub fn new(reader: R) -> Self {
        crate::time::update_time_zone();
        Self {
            lines: LineReader::new(reader),
            next_start: None,
            start_indices: HashMap::new(),
            failed: false,
        }
    }

    fn parse_entry(&mut self) -> Result<Option<HistoryEntry>, Error> {
        let (start_line, start_date) = match self.next_start.take() {
            Some(start) => start,
            None => loop {
                let Some(line) = self.lines.next_line()? else {
                    return Ok(None);
                };
                if let Some(("Start-Date", value)) = split_field(&line) {
                    break (self.lines.line(), value.to_string());
                }
            },
        };

        let mut problem = None;

        // Count the start even if the entry turns out invalid, to stay in line with the terminal
        // log, which has a section for each transaction too.
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

        let mut entry = HistoryEntry {
            start_time,
            start_index,
            end_time: None,
            command_line: None,
            requested_by: None,
            requested_by_uid: None,
            comment: None,
            error: None,
            packages: Vec::new(),
        };

        while let Some(line) = self.lines.next_line()? {
            let Some((key, value)) = split_field(&line) else {
                continue;
            };

            let action = match key {
                "Start-Date" => {
                    self.next_start = Some((self.lines.line(), value.to_string()));
                    break;
                }
                "End-Date" => {
                    entry.end_time = parse_log_time(value);
                    if entry.end_time.is_none() {
                        problem.get_or_insert_with(|| format!("invalid end date {}", quote(value)));
                    }
                    break;
                }
                "Commandline" => {
                    entry.command_line = Some(value.to_string());
                    continue;
                }
                "Requested-By" => {
                    let (user, uid) = parse_requested_by(value);
                    entry.requested_by = Some(user);
                    entry.requested_by_uid = uid;
                    continue;
                }
                "Comment" => {
                    entry.comment = Some(value.to_string());
                    continue;
                }
                "Error" => {
                    entry.error = Some(value.to_string());
                    continue;
                }
                "Install" => PackageAction::Install,
                "Reinstall" => PackageAction::Reinstall,
                "Upgrade" => PackageAction::Upgrade,
                "Downgrade" => PackageAction::Downgrade,
                "Remove" => PackageAction::Remove,
                "Purge" => PackageAction::Purge,
                "Disappeared" => PackageAction::Disappear,
                _ => continue,
            };

            for item in split_package_list(value) {
                match parse_package_change(action, item) {
                    Ok(change) => entry.packages.push(change),
                    Err(message) => {
                        problem.get_or_insert_with(|| format!("{key}: {message}"));
                    }
                }
            }
        }

        match problem {
            Some(message) => Err(Error::Parse {
                line: start_line,
                message,
            }),
            None => Ok(Some(entry)),
        }
    }
}

impl<R: BufRead> Iterator for HistoryParser<R> {
    type Item = Result<HistoryEntry, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }

        match self.parse_entry() {
            Ok(entry) => entry.map(Ok),
            Err(err) => {
                self.failed = matches!(err, Error::Io(_));
                Some(Err(err))
            }
        }
    }
}

/// Returns the index of the next transaction starting at `start_time`, see
/// [`HistoryEntry::start_index`], or `None` if the index would overflow.
pub(crate) fn next_start_index(indices: &mut HashMap<i64, u32>, start_time: i64) -> Option<u32> {
    let next = indices.entry(start_time).or_insert(0);
    let index = *next;
    *next = index.checked_add(1)?;
    Some(index)
}

/// Splits a `Key: value` line, returning `None` for lines without a key, like empty ones.
fn split_field(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once(':')?;
    Some((key, value.trim()))
}

/// Splits `name (uid)` as APT records the requesting user, keeping other values as name.
fn parse_requested_by(value: &str) -> (String, Option<u32>) {
    if let Some((user, uid)) = value.rsplit_once(" (")
        && let Some(uid) = uid.strip_suffix(')')
        && let Ok(uid) = uid.parse()
    {
        return (user.to_string(), Some(uid));
    }
    (value.to_string(), None)
}

/// Splits a package list at the commas outside of parentheses.
///
/// APT logs `name:arch (details)` items separated by `, `, where the details are a comma separated
/// list too, and for packages that disappeared, also items without details.
fn split_package_list(value: &str) -> impl Iterator<Item = &str> {
    let mut depth = 0usize;
    value
        .split(move |c| {
            match c {
                '(' => depth += 1,
                ')' => depth = depth.saturating_sub(1),
                ',' => return depth == 0,
                _ => (),
            }
            false
        })
        .map(str::trim)
        .filter(|item| !item.is_empty())
}

/// Quotes a value for an error message, shortened, as damaged logs can have very long lines.
pub(crate) fn quote(value: &str) -> String {
    match value.char_indices().nth(64) {
        Some((end, _)) => format!("'{}...'", &value[..end]),
        None => format!("'{value}'"),
    }
}

/// Parses a single item of a package list, e.g. `foo:amd64 (1.0-1, 1.1-1)` for an upgrade.
fn parse_package_change(action: PackageAction, item: &str) -> Result<PackageChange, String> {
    let (name, details) = match item.split_once('(') {
        Some((name, details)) => {
            let details = details
                .strip_suffix(')')
                .ok_or_else(|| format!("unterminated details in {}", quote(item)))?;
            (name.trim(), details)
        }
        None => (item, ""),
    };

    let (package, arch) = match name.split_once(':') {
        Some((package, arch)) => (package, Some(arch.to_string())),
        None => (name, None),
    };
    if package.is_empty() || package.contains(char::is_whitespace) {
        return Err(format!("invalid package name in {}", quote(item)));
    }

    // APT writes the details by position: the new version and an optional `automatic` flag for
    // installs, the installed version for reinstalls and removals, which is empty when purging a
    // package of which only configuration files were left, and both versions for up- and
    // downgrades. Versions cannot contain commas, further details are ignored.
    let mut details = details.split(',').map(str::trim);
    let mut next_version = || details.next().filter(|v| !v.is_empty()).map(str::to_string);
    let (old_version, new_version) = match action {
        PackageAction::Install => (None, next_version()),
        PackageAction::Reinstall => {
            let version = next_version();
            (version.clone(), version)
        }
        PackageAction::Upgrade | PackageAction::Downgrade => (next_version(), next_version()),
        PackageAction::Remove | PackageAction::Purge | PackageAction::Disappear => {
            (next_version(), None)
        }
    };
    let automatic = action == PackageAction::Install && details.any(|d| d == "automatic");

    let complete = match action {
        PackageAction::Install | PackageAction::Reinstall => new_version.is_some(),
        PackageAction::Upgrade | PackageAction::Downgrade => {
            old_version.is_some() && new_version.is_some()
        }
        PackageAction::Remove | PackageAction::Purge | PackageAction::Disappear => true,
    };
    if !complete {
        return Err(format!("missing versions in {}", quote(item)));
    }

    Ok(PackageChange {
        action,
        package: package.to_string(),
        arch,
        old_version,
        new_version,
        automatic,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HISTORY_LOG: &str = "
Start-Date: 2026-10-01  11:33:47
Commandline: apt full-upgrade
Requested-By: admin (1000)
Install: proxmox-kernel-7.0.14-21-pve-signed:amd64 (7.0.14-21, automatic)
Upgrade: pve-qemu-kvm:amd64 (11.1.1-1, 11.1.1-2), proxmox-kernel-7.0:amd64 (7.0.14-20, 7.0.14-21)
End-Date: 2026-10-01  11:34:22

Start-Date: 2026-10-02  07:05:11
Commandline: apt-get install -y tshark
Install: libwireshark-data:all (4.4.15-0+deb13u1, automatic), tshark:amd64 (4.4.15-0+deb13u1)

Start-Date: 2026-10-02  07:34:02
Commandline: /usr/bin/unattended-upgrade
Comment: nightly security updates
Upgrade: libpng16-16t64:amd64 (1.6.48-1+deb13u5, 1.6.48-1+deb13u6)
Downgrade: pve-manager:amd64 (9.2.3, 9.2.2)
Reinstall: pve-docs:all (9.2.1)
Remove: proxmox-kernel-7.0.14-8-pve-signed:amd64 (7.0.14-8)
Purge: libfoo1:amd64 (1:2.0-1), libbar1:amd64 ()
Disappeared: libfoo-common, libbar0:i386 (0.9-2)
Error: Sub-process /usr/bin/dpkg returned an error code (1)
End-Date: 2026-10-02  07:34:10
";

    fn time(value: &str) -> i64 {
        parse_log_time(value).expect("valid test timestamp")
    }

    fn change(
        action: PackageAction,
        package: &str,
        arch: Option<&str>,
        old_version: Option<&str>,
        new_version: Option<&str>,
    ) -> PackageChange {
        PackageChange {
            action,
            package: package.to_string(),
            arch: arch.map(str::to_string),
            old_version: old_version.map(str::to_string),
            new_version: new_version.map(str::to_string),
            automatic: false,
        }
    }

    fn parse(log: &str) -> Vec<Result<HistoryEntry, Error>> {
        HistoryParser::new(log.as_bytes()).collect()
    }

    fn parse_valid(log: &str) -> Vec<HistoryEntry> {
        parse(log)
            .into_iter()
            .collect::<Result<_, _>>()
            .expect("valid history log")
    }

    #[test]
    fn parse_history_log() {
        let entries = parse_valid(HISTORY_LOG);
        assert_eq!(entries.len(), 3);

        use PackageAction::*;

        assert_eq!(
            entries[0],
            HistoryEntry {
                start_time: time("2026-10-01  11:33:47"),
                start_index: 0,
                end_time: Some(time("2026-10-01  11:34:22")),
                command_line: Some("apt full-upgrade".to_string()),
                requested_by: Some("admin".to_string()),
                requested_by_uid: Some(1000),
                comment: None,
                error: None,
                packages: vec![
                    PackageChange {
                        automatic: true,
                        ..change(
                            Install,
                            "proxmox-kernel-7.0.14-21-pve-signed",
                            Some("amd64"),
                            None,
                            Some("7.0.14-21"),
                        )
                    },
                    change(
                        Upgrade,
                        "pve-qemu-kvm",
                        Some("amd64"),
                        Some("11.1.1-1"),
                        Some("11.1.1-2"),
                    ),
                    change(
                        Upgrade,
                        "proxmox-kernel-7.0",
                        Some("amd64"),
                        Some("7.0.14-20"),
                        Some("7.0.14-21"),
                    ),
                ],
            }
        );

        assert_eq!(entries[1].start_time, time("2026-10-02  07:05:11"));
        assert_eq!(entries[1].end_time, None);
        assert_eq!(entries[1].requested_by, None);
        assert_eq!(entries[1].packages.len(), 2);
        assert!(entries[1].packages[0].automatic);
        assert!(!entries[1].packages[1].automatic);

        assert_eq!(
            entries[2],
            HistoryEntry {
                start_time: time("2026-10-02  07:34:02"),
                start_index: 0,
                end_time: Some(time("2026-10-02  07:34:10")),
                command_line: Some("/usr/bin/unattended-upgrade".to_string()),
                requested_by: None,
                requested_by_uid: None,
                comment: Some("nightly security updates".to_string()),
                error: Some("Sub-process /usr/bin/dpkg returned an error code (1)".to_string()),
                packages: vec![
                    change(
                        Upgrade,
                        "libpng16-16t64",
                        Some("amd64"),
                        Some("1.6.48-1+deb13u5"),
                        Some("1.6.48-1+deb13u6"),
                    ),
                    change(
                        Downgrade,
                        "pve-manager",
                        Some("amd64"),
                        Some("9.2.3"),
                        Some("9.2.2"),
                    ),
                    change(
                        Reinstall,
                        "pve-docs",
                        Some("all"),
                        Some("9.2.1"),
                        Some("9.2.1"),
                    ),
                    change(
                        Remove,
                        "proxmox-kernel-7.0.14-8-pve-signed",
                        Some("amd64"),
                        Some("7.0.14-8"),
                        None,
                    ),
                    change(Purge, "libfoo1", Some("amd64"), Some("1:2.0-1"), None),
                    // only configuration files were left
                    change(Purge, "libbar1", Some("amd64"), None, None),
                    change(Disappear, "libfoo-common", None, None, None),
                    change(Disappear, "libbar0", Some("i386"), Some("0.9-2"), None),
                ],
            }
        );
    }

    #[test]
    fn same_start_time() {
        let log = "
Start-Date: 2026-10-23  00:40:50
Remove: foo:amd64 (1.0)
End-Date: 2026-10-23  00:40:50

Start-Date: 2026-10-23  00:40:50
Remove: bar:amd64
End-Date: 2026-10-23  00:40:50

Start-Date: 2026-10-23  00:40:50
Upgrade: baz:amd64 (1.0)
End-Date: 2026-10-23  00:40:50

Start-Date: 2026-10-23  00:40:50
Remove: qux:amd64 (1.0)
End-Date: 2026-10-23  00:40:51

Start-Date: 2026-10-23  00:40:51
Remove: quux:amd64 (1.0)
End-Date: 2026-10-23  00:40:51
";
        let indices: Vec<_> = parse(log)
            .into_iter()
            .map(|entry| entry.ok().map(|entry| entry.start_index))
            .collect();
        // the invalid entry counts too, as the terminal log has a section for it
        assert_eq!(indices, [Some(0), Some(1), None, Some(3), Some(0)]);
    }

    #[test]
    fn skip_invalid_entries() {
        let log = "garbage before the first entry

Start-Date: 2026-10-01  11:33:47
Upgrade: foo:amd64 (1.0)
End-Date: 2026-10-01  11:34:22

Start-Date: yesterday
End-Date: 2026-10-01  11:34:22

Start-Date: 2026-10-02  07:05:11
Install: foo:amd64 (1.0
Upgrade: bar:amd64 (1.0, 1.1)
Start-Date: 2026-10-02  07:34:02
Some-Future-Field: value
Install: foo:amd64 (1.0, some-future-flag)
End-Date: 2026-10-02  07:34:10
";
        let entries = parse(log);
        assert_eq!(entries.len(), 4);

        let lines: Vec<_> = entries[..3]
            .iter()
            .map(|entry| match entry {
                Err(Error::Parse { line, .. }) => *line,
                other => panic!("expected parse error, got {other:?}"),
            })
            .collect();
        assert_eq!(lines, [3, 7, 10]);

        let entry = entries[3].as_ref().expect("valid entry");
        assert_eq!(entry.start_time, time("2026-10-02  07:34:02"));
        assert_eq!(
            entry.packages,
            [change(
                PackageAction::Install,
                "foo",
                Some("amd64"),
                None,
                Some("1.0")
            )]
        );
    }

    #[test]
    fn requested_by() {
        assert_eq!(
            parse_requested_by("admin (1000)"),
            ("admin".to_string(), Some(1000))
        );
        assert_eq!(
            parse_requested_by("some user (1001)"),
            ("some user".to_string(), Some(1001))
        );
        assert_eq!(parse_requested_by("admin"), ("admin".to_string(), None));
        assert_eq!(
            parse_requested_by("admin (x)"),
            ("admin (x)".to_string(), None)
        );
    }

    #[test]
    fn package_list() {
        assert_eq!(
            split_package_list("a:amd64 (1.0, 2.0), b, c (3.0), ").collect::<Vec<_>>(),
            ["a:amd64 (1.0, 2.0)", "b", "c (3.0)"]
        );
        assert_eq!(split_package_list("").count(), 0);
        assert_eq!(quote(&"x".repeat(100)), format!("'{}...'", "x".repeat(64)));

        use PackageAction::*;

        for (action, item, expected) in [
            // versions not starting with a digit, which dpkg tolerates in its database
            (
                Remove,
                "foo:amd64 (git20200101)",
                change(Remove, "foo", Some("amd64"), Some("git20200101"), None),
            ),
            (
                Install,
                "foo:amd64 (1.0, automatic, some-future-flag)",
                PackageChange {
                    automatic: true,
                    ..change(Install, "foo", Some("amd64"), None, Some("1.0"))
                },
            ),
            (
                Upgrade,
                "foo:amd64 (1.0, 2.0, some-future-detail)",
                change(Upgrade, "foo", Some("amd64"), Some("1.0"), Some("2.0")),
            ),
            (Disappear, "foo", change(Disappear, "foo", None, None, None)),
        ] {
            assert_eq!(
                parse_package_change(action, item),
                Ok(expected),
                "{action:?} {item:?}"
            );
        }

        for (action, item) in [
            (Install, "foo:amd64"),
            (Install, "foo:amd64 ()"),
            (Reinstall, "foo:amd64 ()"),
            (Upgrade, "foo:amd64 (1.0)"),
            (Downgrade, "foo:amd64 (, 1.0)"),
            (Install, ":amd64 (1.0)"),
            (Install, "foo bar:amd64 (1.0)"),
            (Remove, "foo:amd64 (1.0"),
        ] {
            assert!(
                parse_package_change(action, item).is_err(),
                "{action:?} {item:?}"
            );
        }
    }

    #[test]
    fn wire_format() {
        let mut entries = parse_valid(HISTORY_LOG);

        assert_eq!(
            serde_json::to_value(&entries[0]).expect("serializable entry"),
            serde_json::json!({
                "start-time": time("2026-10-01  11:33:47"),
                "end-time": time("2026-10-01  11:34:22"),
                "command-line": "apt full-upgrade",
                "requested-by": "admin",
                "requested-by-uid": 1000,
                "packages": [
                    {
                        "action": "install",
                        "package": "proxmox-kernel-7.0.14-21-pve-signed",
                        "arch": "amd64",
                        "new-version": "7.0.14-21",
                        "automatic": true,
                    },
                    {
                        "action": "upgrade",
                        "package": "pve-qemu-kvm",
                        "arch": "amd64",
                        "old-version": "11.1.1-1",
                        "new-version": "11.1.1-2",
                    },
                    {
                        "action": "upgrade",
                        "package": "proxmox-kernel-7.0",
                        "arch": "amd64",
                        "old-version": "7.0.14-20",
                        "new-version": "7.0.14-21",
                    },
                ],
            }),
        );

        entries[1].start_index = 1;
        assert_eq!(
            serde_json::to_value(&entries[1]).expect("serializable entry")["start-index"],
            1
        );

        for entry in entries {
            let value = serde_json::to_value(&entry).expect("serializable entry");

            let parsed: HistoryEntry = serde_json::from_value(value).expect("deserializable entry");
            assert_eq!(parsed, entry);
        }
    }
}
