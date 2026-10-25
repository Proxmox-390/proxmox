//! Parser for Debian changelogs, as kept in the `debian/changelog` file of a source package and
//! installed with its binary packages, see [deb-changelog].
//!
//! The parser only needs a minimal set of dependencies. Optional features add more on top, the
//! latter two are not available on `wasm32`:
//!
//! - **`api-types`**: `proxmox-schema` API type derives.
//! - **`impl`**: reading the changelogs of installed packages, see `read_installed_changelog`.
//! - **`api`**: an API method for that, to be shared by the Rust based products, see `api`.
//!
//! [deb-changelog]: https://manpages.debian.org/stable/dpkg-dev/deb-changelog.5.en.html

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use proxmox_deb_version::{InvalidVersion, cmp_versions, validate_version};

#[cfg(feature = "api-types")]
use proxmox_schema::api;

#[cfg(all(feature = "api", not(target_arch = "wasm32")))]
pub mod api;

mod changes;
pub use changes::{ChangeBlock, parse_changes};

#[cfg(all(feature = "impl", not(target_arch = "wasm32")))]
mod installed;
#[cfg(all(feature = "impl", not(target_arch = "wasm32")))]
pub use installed::{DOC_DIR, Error, read_installed_changelog};

/// An entry of a Debian changelog, i.e. the changes of one version of a source package.
#[cfg_attr(feature = "api-types", api)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ChangelogEntry {
    /// Name of the source package.
    pub package: String,
    /// Version of the source package.
    pub version: String,
    /// Distributions the version was uploaded to, separated by spaces.
    pub distributions: String,
    /// Urgency of the upload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub urgency: Option<String>,
    /// The changes as written in the changelog, usually as an indented list.
    pub changes: String,
    /// Name and email address of the author of the entry, missing if the entry is incomplete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maintainer: Option<String>,
    /// Date of the entry as written in the changelog, missing if the entry is incomplete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
}

/// Parses a Debian changelog, keeping the order of its entries, i.e. usually newest first.
///
/// Lines outside of entries are ignored, like editor settings at the end. Like dpkg, comment lines
/// are skipped and parsing stops where the old changelog format of the early Debian days starts. An
/// entry without trailer line, for example at the end of a truncated changelog, is still returned,
/// without maintainer and date.
pub fn parse_changelog(text: &str) -> Vec<ChangelogEntry> {
    let mut entries = Vec::new();
    let mut current: Option<(ChangelogEntry, Vec<&str>)> = None;

    for line in text.lines() {
        if is_comment(line) {
            continue;
        }
        if let Some(header) = parse_header(line) {
            entries.extend(current.replace((header, Vec::new())).map(finish_entry));
        } else if starts_old_format(line) {
            break;
        } else if let Some((entry, changes)) = &mut current {
            match parse_trailer(line) {
                Some((maintainer, date)) => {
                    entry.maintainer = Some(maintainer.to_string());
                    entry.date = Some(date.to_string());
                    entries.extend(current.take().map(finish_entry));
                }
                None => changes.push(line),
            }
        }
    }
    entries.extend(current.map(finish_entry));

    entries
}

fn finish_entry((mut entry, changes): (ChangelogEntry, Vec<&str>)) -> ChangelogEntry {
    let start = changes.iter().position(|line| !line.trim().is_empty());
    let end = changes.iter().rposition(|line| !line.trim().is_empty());
    if let (Some(start), Some(end)) = (start, end) {
        entry.changes = changes[start..=end].join("\n");
    }
    entry
}

/// Whether dpkg skips a line as comment, wherever it is: `# ...`, `/* ... */` or an RCS keyword
/// like `$Id: ... $`.
fn is_comment(line: &str) -> bool {
    let rcs_keyword = line
        .strip_prefix('$')
        .and_then(|rest| rest.split_once(':'))
        .is_some_and(|(keyword, rest)| {
            !keyword.is_empty()
                && keyword.chars().all(|c| c.is_alphanumeric() || c == '_')
                && rest.contains('$')
        });
    line.starts_with("# ")
        || line
            .strip_prefix("/*")
            .is_some_and(|rest| rest.contains("*/"))
        || rcs_keyword
}

/// Whether a token is a package name in a header line as dpkg takes it, which also allows upper
/// case letters.
fn is_package_token(token: &str) -> bool {
    let mut chars = token.chars();
    chars
        .next()
        .is_some_and(|c| c.is_alphanumeric() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || "-+.".contains(c))
}

/// Whether a token is a version in a header line as dpkg takes it, checked in detail only where
/// versions get compared.
fn is_version_token(token: &str) -> bool {
    !token.is_empty() && !token.contains(['(', ')', ' ', '\t'])
}

/// Whether a line that is not a header starts the old changelog format, which dpkg leaves
/// unparsed. Of the delimiters it knows, only those that could be taken for an entry are checked,
/// with dpkg's syntax.
fn starts_old_format(line: &str) -> bool {
    if line.trim_end() == "Old Changelog:" {
        return true;
    }
    // any other header-like line, for example without distributions like
    // `dpkg (1.2.12); priority=LOW`, starting with a package name and a version in parentheses
    let Some((package, rest)) = line.split_once(" (") else {
        return false;
    };
    let Some((version, _)) = rest.split_once(')') else {
        return false;
    };
    is_package_token(package) && is_version_token(version)
}

/// Parses a header line, like `pve-manager (9.2.3) trixie; urgency=medium`, with dpkg's syntax.
fn parse_header(line: &str) -> Option<ChangelogEntry> {
    let (package, rest) = line.split_once(" (")?;
    let (version, rest) = rest.split_once(')')?;
    let (distributions, metadata) = rest.split_once(';')?;
    let valid_distributions = distributions.starts_with(char::is_whitespace)
        && distributions.split_whitespace().all(|distribution| {
            distribution
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-+.".contains(c))
        });
    let distributions = distributions.trim();
    if !is_package_token(package)
        || !is_version_token(version)
        || distributions.is_empty()
        || !valid_distributions
    {
        return None;
    }
    let urgency = metadata.split(',').find_map(|field| {
        let (key, value) = field.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("urgency")
            .then(|| value.trim().to_string())
    });

    Some(ChangelogEntry {
        package: package.to_string(),
        version: version.to_string(),
        distributions: distributions.to_string(),
        urgency,
        changes: String::new(),
        maintainer: None,
        date: None,
    })
}

/// Parses a trailer line, like ` -- Proxmox Support Team <support@proxmox.com>  <date>`.
fn parse_trailer(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix(" -- ")?;
    // the name can contain double spaces too, so split after the email address if there is one
    let (maintainer, date) = match rest.rfind('>') {
        Some(end) => rest.split_at(end + 1),
        None => rest.split_once("  ")?,
    };
    let date = date.trim();
    (!date.is_empty()).then_some((maintainer.trim(), date))
}

/// A range of versions later than `since` and up to including `to`, like `dpkg-parsechangelog
/// --since` and `--to` select, both limits being optional.
#[derive(Clone, Debug)]
pub struct VersionRange {
    since: Option<String>,
    to: Option<String>,
}

impl VersionRange {
    /// Creates a range, the limits must be valid versions.
    pub fn new(since: Option<&str>, to: Option<&str>) -> Result<Self, InvalidVersion> {
        Ok(Self {
            since: since.map(validate_version).transpose()?,
            to: to.map(validate_version).transpose()?,
        })
    }

    /// Whether the range contains the version, never for a version that cannot be compared if a
    /// limit is given.
    pub fn contains(&self, version: &str) -> bool {
        self.since.as_deref().is_none_or(|since| {
            cmp_versions(version, since).is_ok_and(|ord| ord == Ordering::Greater)
        }) && self
            .to
            .as_deref()
            .is_none_or(|to| cmp_versions(version, to).is_ok_and(|ord| ord != Ordering::Greater))
    }

    /// Whether the changelog has an entry for the upper limit, if there is one.
    ///
    /// Otherwise the limits are versions of the binary package that the changelog does not list,
    /// like for signed kernels or packages with their own epoch, so the range cannot tell which
    /// entries belong to them.
    pub fn is_listed(&self, entries: &[ChangelogEntry]) -> bool {
        self.to.as_deref().is_none_or(|to| {
            entries
                .iter()
                .any(|entry| cmp_versions(&entry.version, to).is_ok_and(Ordering::is_eq))
        })
    }

    /// The entries in the range, or only the newest one, which came with the installed package, if
    /// the upper limit is not listed, see [`is_listed`](Self::is_listed).
    pub fn select<'a>(
        &self,
        entries: &'a [ChangelogEntry],
    ) -> impl Iterator<Item = &'a ChangelogEntry> {
        let listed = self.is_listed(entries);
        entries
            .iter()
            .enumerate()
            .filter(move |(index, entry)| {
                if listed {
                    self.contains(&entry.version)
                } else {
                    *index == 0
                }
            })
            .map(|(_, entry)| entry)
    }
}

/// Keeps the entries that [`VersionRange::select`] selects for `since` and `to`.
pub fn filter_versions(
    entries: Vec<ChangelogEntry>,
    since: Option<&str>,
    to: Option<&str>,
) -> Result<Vec<ChangelogEntry>, InvalidVersion> {
    let range = VersionRange::new(since, to)?;
    Ok(range.select(&entries).cloned().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHANGELOG: &str = "\
pve-manager (9.2.3) trixie; urgency=medium

  * ui: node: show the APT history.

  * api: apt: add endpoints for the APT history.

 -- Proxmox Support Team <support@proxmox.com>  Thu, 22 Oct 2026 23:53:59 +0200

pve-manager (9.2.2) trixie; urgency=low, binary-only=yes
  * fix a bug.
 -- Proxmox Support Team <support@proxmox.com>  Mon, 19 Oct 2026 10:00:00 +0200

pve-manager (9.2.1-1~bpo1) trixie-backports pve; urgency=medium

  * backport.

 -- Some One <some.one@example.com>  Fri, 16 Oct 2026 09:00:00 +0200

Local variables:
mode: debian-changelog
End:
";

    fn versions(entries: &[ChangelogEntry]) -> Vec<&str> {
        entries.iter().map(|entry| entry.version.as_str()).collect()
    }

    #[test]
    fn parse() {
        let entries = parse_changelog(CHANGELOG);
        assert_eq!(versions(&entries), ["9.2.3", "9.2.2", "9.2.1-1~bpo1"]);
        assert_eq!(
            entries[0],
            ChangelogEntry {
                package: "pve-manager".into(),
                version: "9.2.3".into(),
                distributions: "trixie".into(),
                urgency: Some("medium".into()),
                changes: "  * ui: node: show the APT history.\n\n  * api: apt: add endpoints for \
                          the APT history."
                    .into(),
                maintainer: Some("Proxmox Support Team <support@proxmox.com>".into()),
                date: Some("Thu, 22 Oct 2026 23:53:59 +0200".into()),
            }
        );
        assert_eq!(entries[1].urgency.as_deref(), Some("low"));
        assert_eq!(entries[1].changes, "  * fix a bug.");
        assert_eq!(entries[2].distributions, "trixie-backports pve");
        assert_eq!(
            entries[2].maintainer.as_deref(),
            Some("Some One <some.one@example.com>")
        );
    }

    #[test]
    fn parse_incomplete() {
        assert_eq!(parse_changelog(""), []);
        assert_eq!(parse_changelog("no changelog\n  at all\n"), []);

        // truncated after the changes of the second entry
        let entries = parse_changelog(
            &CHANGELOG[..CHANGELOG
                .find(" -- Proxmox Support Team <support@proxmox.com>  Mon")
                .unwrap()],
        );
        assert_eq!(versions(&entries), ["9.2.3", "9.2.2"]);
        assert_eq!(entries[1].changes, "  * fix a bug.");
        assert_eq!(entries[1].maintainer, None);
        assert_eq!(entries[1].date, None);

        // the old format starts, like in dpkg's own changelog
        let entries = parse_changelog(
            "a (2) unstable;\n  * two\n -- A <a@example.com>  Mon, 1 Jan 1996 00:00:00 +0000\n\n\
             a (1.1); priority=LOW\n  * old\n\na (1) unstable;\n  * one\n",
        );
        assert_eq!(versions(&entries), ["2"]);
        assert_eq!(
            versions(&parse_changelog(
                "a (2) unstable;\n  * two\n\nOld Changelog:\na (1) unstable;\n"
            )),
            ["2"]
        );

        // comments are skipped like by dpkg, also those that look like headers
        assert_eq!(
            versions(&parse_changelog(
                "# (99) unstable; urgency=medium\na (2) unstable;\n  * two\n# a comment\n$Id: x $\n\
                 /* (3) unstable; */\n -- A <a@example.com>  Mon, 1 Jan 1996 00:00:00 +0000\n\n\
                 a (1) unstable;\n"
            )),
            ["2", "1"]
        );
        let entries = parse_changelog("a (2) unstable;\n  * two\n# a comment\n  * three\n");
        assert_eq!(entries[0].changes, "  * two\n  * three");
        for header in [
            "# (2) unstable;",
            "a (2)unstable;",
            "a (2 3) unstable;",
            "a (2) unstable/main;",
            "-a (2) unstable;",
        ] {
            assert_eq!(parse_changelog(header), [], "{header:?}");
        }
        assert_eq!(parse_changelog("A_b (2) unstable;"), []);
        assert_eq!(versions(&parse_changelog("Ab+c.d (2) UNRELEASED;")), ["2"]);
        assert_eq!(versions(&parse_changelog("_ab (2) unstable;")), ["2"]);

        // comments that look like headers do not end it, as dpkg skips them
        for comment in [
            "# Changelog (generated)",
            "/* Earlier release (1); */",
            "# Older releases (archived)",
        ] {
            let text = format!(
                "{comment}\na (2) unstable;\n  * two\n\n{comment}\na (1) unstable;\n  * one\n"
            );
            assert_eq!(versions(&parse_changelog(&text)), ["2", "1"], "{comment:?}");
        }
        // a header line without the distribution ends it like for dpkg
        assert_eq!(
            versions(&parse_changelog(
                "a (2) unstable;\n  * two\n\na (1) unstable\n  * one\n"
            )),
            ["2"]
        );

        let entries =
            parse_changelog("a (2) unstable; urgency=low\n  * two\nb (1) unstable;\n  * one\n");
        assert_eq!(versions(&entries), ["2", "1"]);
        assert_eq!(entries[0].changes, "  * two");
        assert_eq!(entries[1].urgency, None);
    }

    #[test]
    fn filter() {
        let entries = parse_changelog(CHANGELOG);
        let filtered = |since, to| {
            versions(&filter_versions(entries.clone(), since, to).expect("valid versions"))
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        assert_eq!(filtered(None, None), ["9.2.3", "9.2.2", "9.2.1-1~bpo1"]);
        // a missing revision compares like an empty one, which is older than "1~bpo1"
        assert_eq!(
            filtered(Some("9.2.1"), None),
            ["9.2.3", "9.2.2", "9.2.1-1~bpo1"]
        );
        assert_eq!(filtered(Some("9.2.1-1"), None), ["9.2.3", "9.2.2"]);
        assert_eq!(filtered(Some("9.2.1-1~bpo1"), Some("9.2.2")), ["9.2.2"]);
        assert_eq!(filtered(None, Some("9.2.2")), ["9.2.2", "9.2.1-1~bpo1"]);
        assert_eq!(filtered(Some("9.2.2+b1"), Some("9.2.3")), ["9.2.3"]);
        assert_eq!(filtered(Some("9.2.3"), None), Vec::<String>::new());

        let backports =
            parse_changelog("a (2.0) unstable;\n\na (1.0) unstable;\n\na (1.0-0~bpo1) unstable;\n");
        let filtered = |since, to| {
            versions(&filter_versions(backports.clone(), since, to).expect("valid versions"))
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        assert_eq!(filtered(Some("1.0"), None), ["2.0"]);
        assert_eq!(filtered(None, Some("1.0")), ["1.0", "1.0-0~bpo1"]);
        assert_eq!(filtered(Some("1.0-0~bpo1"), Some("1.0")), ["1.0"]);
        // a revision of zero is the same version
        assert_eq!(filtered(Some("1.0-0~bpo1"), Some("1.0-0")), ["1.0"]);

        // a signed kernel lists the version of its signed source package
        let kernel = parse_changelog(
            "proxmox-kernel-signed-7.0 (7.0.14+25) trixie;\n\n\
             proxmox-kernel-7.0 (7.0.14-24) trixie;\n",
        );
        let filtered = |since, to| {
            versions(&filter_versions(kernel.clone(), since, to).expect("valid versions"))
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        assert_eq!(filtered(None, Some("7.0.14-25")), ["7.0.14+25"]);
        assert_eq!(
            filtered(Some("7.0.14-24"), Some("7.0.14-25")),
            ["7.0.14+25"]
        );
        assert_eq!(filtered(Some("7.0.14-24"), None), ["7.0.14+25"]);

        assert!(filter_versions(entries.clone(), Some("1.0_1"), None).is_err());
        assert!(filter_versions(entries.clone(), None, Some("1.0-")).is_err());

        // epochs like dpkg takes them, which accepts a sign, leading zeros and surrounding spaces
        let epochs = parse_changelog("a (2:1) unstable;\n\na (1:1) unstable;\n\na (1) unstable;\n");
        let filtered = |since| {
            versions(&filter_versions(epochs.clone(), since, None).expect("valid versions"))
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        for since in ["1:1", "+1:1", "01:1", " 1:1 "] {
            assert_eq!(filtered(Some(since)), ["2:1"], "{since:?}");
        }
        for since in ["-0:1", "0:1", "+0:1"] {
            assert_eq!(filtered(Some(since)), ["2:1", "1:1"], "{since:?}");
        }
        assert_eq!(filtered(Some("2147483647:1")), Vec::<String>::new());
    }

    #[test]
    fn parse_trailer_spacing() {
        // a double space in the name, from debian-keyring 2024.02.28
        assert_eq!(
            parse_trailer(" -- John Sullivan  <johns@debian.org>  Wed, 28 Feb 2024 00:21:42 -0500"),
            Some((
                "John Sullivan  <johns@debian.org>",
                "Wed, 28 Feb 2024 00:21:42 -0500"
            ))
        );
        // dpkg accepts a single space before the date, and spaces within it
        assert_eq!(
            parse_trailer(" -- Some One <one@example.com> Wed,  8 Feb 2023 10:00:00 +0100"),
            Some((
                "Some One <one@example.com>",
                "Wed,  8 Feb 2023 10:00:00 +0100"
            ))
        );
        assert_eq!(
            parse_trailer(" -- Some One  Wed, 08 Feb 2023 10:00:00 +0100"),
            Some(("Some One", "Wed, 08 Feb 2023 10:00:00 +0100"))
        );
        assert_eq!(parse_trailer(" -- Some One <one@example.com>"), None);
        assert_eq!(parse_trailer("  * not a trailer"), None);
    }
}
