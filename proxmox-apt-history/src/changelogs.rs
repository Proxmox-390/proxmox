use proxmox_deb_changelog::{ChangelogEntry, VersionRange, read_installed_changelog};

use crate::{
    Error, HistoryListOptions, PackageAction, PackageChange, TransactionChangelog, list_history,
};

/// Returns the changelog entries for the package changes of the transaction with the given start
/// time and start index, see [`HistoryEntry::start_index`](crate::HistoryEntry::start_index),
/// grouped by source package as described for [`TransactionChangelog`], upgrades first, then
/// downgrades, installs and other changes, each sorted by name.
///
/// Returns `None` if the history has no such transaction. The entries come from the changelogs of
/// the installed packages, so packages that got removed since have none, and those that got
/// downgraded since lack the entries of the later versions.
pub fn get_transaction_changelogs(
    start_time: i64,
    start_index: u32,
) -> Result<Option<Vec<TransactionChangelog>>, Error> {
    let options = HistoryListOptions {
        since: Some(start_time),
        until: Some(start_time),
        ..Default::default()
    };
    let transaction = list_history(&options)?
        .into_iter()
        .find(|entry| entry.start_index == start_index);

    Ok(transaction
        .map(|transaction| group_changelogs(transaction.packages, read_installed_changelog)))
}

/// Groups the package changes that show the same entries of the same source package, reading the
/// changelogs with `read`, upgrades first, then downgrades, installs and other changes, each by
/// name.
fn group_changelogs(
    changes: Vec<PackageChange>,
    mut read: impl FnMut(&str) -> Result<Vec<ChangelogEntry>, proxmox_deb_changelog::Error>,
) -> Vec<TransactionChangelog> {
    let mut groups: Vec<TransactionChangelog> = Vec::new();

    for change in changes {
        let Some((since, to)) = change.changelog_range() else {
            continue;
        };
        let mut group = TransactionChangelog {
            source: None,
            packages: Vec::new(),
            entries: Vec::new(),
            unlisted_version: false,
            error: None,
        };
        match read(&change.package) {
            Ok(entries) => {
                group.source = entries.first().map(|entry| entry.package.clone());
                match VersionRange::new(since, Some(to)) {
                    Ok(range) => {
                        group.unlisted_version = !range.is_listed(&entries);
                        let selected = range.select(&entries).cloned();
                        group.entries = match since {
                            Some(_) => selected.collect(),
                            None => selected.take(1).collect(),
                        };
                    }
                    Err(err) => group.error = Some(err.to_string()),
                }
            }
            // for example removed since, or installed without its documentation
            Err(proxmox_deb_changelog::Error::NotFound(_)) => (),
            Err(err) => group.error = Some(err.to_string()),
        }

        let same = groups.iter_mut().find(|other| {
            group.source.is_some()
                && group.error.is_none()
                && other.error.is_none()
                && other.source == group.source
                && other.entries == group.entries
                && other.unlisted_version == group.unlisted_version
        });
        match same {
            Some(other) => other.packages.push(change),
            None => {
                group.packages.push(change);
                groups.push(group);
            }
        }
    }

    groups.sort_by(|a, b| {
        action_rank(a)
            .cmp(&action_rank(b))
            .then_with(|| group_name(a).cmp(group_name(b)))
    });
    groups
}

fn action_rank(group: &TransactionChangelog) -> u8 {
    group
        .packages
        .iter()
        .map(|change| match change.action {
            PackageAction::Upgrade => 0,
            PackageAction::Downgrade => 1,
            PackageAction::Install => 2,
            _ => 3,
        })
        .min()
        .unwrap_or(3)
}

fn group_name(group: &TransactionChangelog) -> &str {
    match &group.source {
        Some(source) => source,
        None => &group.packages[0].package,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use proxmox_deb_changelog::Error as ChangelogError;

    use super::*;

    fn change(
        action: PackageAction,
        package: &str,
        old_version: Option<&str>,
        new_version: Option<&str>,
    ) -> PackageChange {
        PackageChange {
            action,
            package: package.to_string(),
            arch: Some("amd64".to_string()),
            old_version: old_version.map(str::to_string),
            new_version: new_version.map(str::to_string),
            automatic: false,
        }
    }

    fn read(package: &str) -> Result<Vec<ChangelogEntry>, ChangelogError> {
        let source = match package {
            "libfoo1" | "foo-utils" | "foo-new" | "foo-doc" => "foo",
            "bar" | "baz" | "invalid" | "signed" => package,
            "broken" => {
                return Err(ChangelogError::TooLarge {
                    path: PathBuf::from("/usr/share/doc/broken/changelog.Debian.gz"),
                });
            }
            _ => return Err(ChangelogError::NotFound(package.to_string())),
        };
        Ok(["3.0-1", "2.0-1", "1.0-1"]
            .into_iter()
            .map(|version| ChangelogEntry {
                package: source.to_string(),
                version: version.to_string(),
                distributions: "trixie".to_string(),
                urgency: Some("medium".to_string()),
                changes: format!(
                    "  * change in {}",
                    if package == "foo-doc" {
                        package
                    } else {
                        source
                    }
                ),
                maintainer: None,
                date: None,
            })
            .collect())
    }

    #[test]
    fn group_by_source_and_entries() {
        use PackageAction::*;

        let groups = group_changelogs(
            vec![
                change(Upgrade, "libfoo1", Some("1.0-1"), Some("3.0-1")),
                change(Remove, "removed", Some("1.0"), None),
                change(Install, "bar", None, Some("2.0-1")),
                change(Upgrade, "foo-utils", Some("1.0-1"), Some("3.0-1")),
                change(Install, "foo-new", None, Some("3.0-1")),
                change(Downgrade, "baz", Some("3.0-1"), Some("2.0-1")),
                change(Reinstall, "gone", Some("1.0"), Some("1.0")),
                change(Upgrade, "broken", Some("1.0"), Some("2.0")),
                change(Upgrade, "invalid", Some("1.0"), Some("no version")),
                change(Upgrade, "foo-doc", Some("1.0-1"), Some("3.0-1")),
                change(Upgrade, "signed", Some("1.0+1"), Some("2.0+1")),
            ],
            read,
        );

        let summary: Vec<_> = groups
            .iter()
            .map(|group| {
                (
                    group.source.as_deref(),
                    group
                        .packages
                        .iter()
                        .map(|change| change.package.as_str())
                        .collect::<Vec<_>>(),
                    group
                        .entries
                        .iter()
                        .map(|entry| entry.version.as_str())
                        .collect::<Vec<_>>(),
                    group.error.is_some(),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                (None, vec!["broken"], vec![], true),
                (
                    Some("foo"),
                    vec!["libfoo1", "foo-utils"],
                    vec!["3.0-1", "2.0-1"],
                    false
                ),
                (Some("foo"), vec!["foo-doc"], vec!["3.0-1", "2.0-1"], false),
                (Some("invalid"), vec!["invalid"], vec![], true),
                (Some("signed"), vec!["signed"], vec!["3.0-1"], false),
                (Some("baz"), vec!["baz"], vec!["3.0-1"], false),
                (Some("bar"), vec!["bar"], vec!["2.0-1"], false),
                (Some("foo"), vec!["foo-new"], vec!["3.0-1"], false),
                (None, vec!["gone"], vec![], false),
            ]
        );
        let unlisted: Vec<_> = groups
            .iter()
            .filter(|group| group.unlisted_version)
            .map(|group| group.packages[0].package.as_str())
            .collect();
        assert_eq!(unlisted, ["signed"]);
    }

    #[cfg(feature = "api-types")]
    #[test]
    fn perl_booleans() {
        for (value, unlisted) in [
            (serde_json::json!(1), true),
            (serde_json::json!(0), false),
            (serde_json::json!(true), true),
        ] {
            let group: TransactionChangelog = serde_json::from_value(serde_json::json!({
                "source": "foo",
                "packages": [],
                "unlisted-version": value,
            }))
            .expect("deserializable group");
            assert_eq!(group.unlisted_version, unlisted, "{value}");
        }
    }
}
