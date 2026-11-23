use serde::{Deserialize, Serialize};

use proxmox_deb_changelog::ChangelogEntry;
#[cfg(feature = "api-types")]
use proxmox_schema::api;

/// What a transaction did to a package.
#[cfg_attr(feature = "api-types", api)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageAction {
    /// The package was newly installed.
    Install,
    /// The installed version of the package was installed again.
    Reinstall,
    /// The package was upgraded.
    Upgrade,
    /// The package was downgraded.
    Downgrade,
    /// The package was removed, keeping its configuration files.
    Remove,
    /// The package was removed together with its configuration files.
    Purge,
    /// dpkg dropped the package because packages of the transaction replaced all of its files.
    Disappear,
}

/// A change to a single package in a transaction.
#[cfg_attr(feature = "api-types", api(
    properties: {
        automatic: {
            optional: true,
            default: false,
        },
    },
))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PackageChange {
    /// What the transaction did to the package.
    pub action: PackageAction,
    /// Package name.
    pub package: String,
    /// Package architecture, not recorded for packages that disappeared if it is the native
    /// architecture or `all`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// Version installed before the transaction, if there was one and APT recorded it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_version: Option<String>,
    /// Version installed by the transaction, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_version: Option<String>,
    /// Whether APT marked the newly installed package as installed automatically, i.e. as a
    /// dependency.
    #[serde(default, skip_serializing_if = "is_false")]
    #[cfg_attr(
        feature = "api-types",
        serde(deserialize_with = "proxmox_serde::perl::deserialize_bool")
    )]
    pub automatic: bool,
}

impl PackageChange {
    /// A pending update of a package from `old_version` to `new_version`, or an install if there is
    /// no old version, like APT lists the available updates.
    pub fn pending_update(
        package: String,
        arch: Option<String>,
        old_version: Option<String>,
        new_version: String,
    ) -> Self {
        let old_version = old_version.filter(|version| !version.is_empty());
        Self {
            action: match old_version {
                Some(_) => PackageAction::Upgrade,
                None => PackageAction::Install,
            },
            package,
            arch,
            old_version,
            new_version: Some(new_version),
            automatic: false,
        }
    }

    /// The versions of the changelog entries that came with the change, those later than the first
    /// one and up to including the second one, or `None` for the first one if there is no earlier
    /// version, like for installs. The entries of a downgrade are the ones it reverted. Returns
    /// `None` for changes without a new version, like removals.
    pub fn changelog_range(&self) -> Option<(Option<&str>, &str)> {
        let new_version = self.new_version.as_deref()?;
        Some(match (self.action, self.old_version.as_deref()) {
            (PackageAction::Upgrade, Some(old)) if old != new_version => (Some(old), new_version),
            (PackageAction::Downgrade, Some(old)) if old != new_version => (Some(new_version), old),
            _ => (None, new_version),
        })
    }
}

fn is_false(value: &bool) -> bool {
    !value
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

/// A transaction recorded in the APT history log, i.e. one run of APT that changed packages, which
/// can call dpkg several times.
///
/// APT logs local time with second resolution, so if the clock was set back during a transaction,
/// for example at the end of daylight saving time, its end can lie before its start.
#[cfg_attr(feature = "api-types", api(
    properties: {
        "start-index": {
            optional: true,
            default: 0,
        },
        packages: {
            type: Array,
            items: {
                type: PackageChange,
            },
        },
    },
))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct HistoryEntry {
    /// Start time as Unix epoch.
    pub start_time: i64,
    /// Number of earlier transactions with the same start time in the same log file.
    ///
    /// Together with the start time, this identifies the transaction, for example to look up its
    /// terminal output. This can fail for transactions starting in the same second in different
    /// files, i.e. around a log rotation, or if a transaction is missing in one of the logs.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub start_index: u32,
    /// End time as Unix epoch, missing if the transaction is still running or got interrupted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<i64>,
    /// Whether a transaction without end time is still running, or else got interrupted. As APT
    /// runs one transaction at a time, only the newest one can still be running. Missing if that
    /// could not be checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(
        feature = "api-types",
        serde(deserialize_with = "proxmox_serde::perl::deserialize_bool")
    )]
    pub running: Option<bool>,
    /// Command line of the APT invocation, missing for frontends using APT as library.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    /// User who requested the transaction through sudo, pkexec or PackageKit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<String>,
    /// UID of the user who requested the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_by_uid: Option<u32>,
    /// Comment set through the `APT::History::Comment` option.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Error reported for the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Changed packages, in the order APT logged them.
    pub packages: Vec<PackageChange>,
}

impl HistoryEntry {
    /// The changes between major releases of Debian and Ceph that the transaction made, like an
    /// upgrade from Debian 12 to 13, from the major versions of the packages marking them.
    pub fn release_changes(&self) -> impl Iterator<Item = ReleaseChange> + '_ {
        self.packages.iter().filter_map(|change| {
            let (_, name) = RELEASE_PACKAGES
                .iter()
                .find(|(package, _)| *package == change.package)?;
            let old = major_version(change.old_version.as_deref()?)?;
            let new = major_version(change.new_version.as_deref()?)?;
            (old != new).then_some(ReleaseChange { name, old, new })
        })
    }
}

/// Packages whose major version is the major release of what they belong to, with its name.
///
/// Only Ceph services need `ceph-base`, unlike the client tools in `ceph-common` that Proxmox VE
/// installs on every node, also without a Ceph cluster.
const RELEASE_PACKAGES: [(&str, &str); 2] = [("base-files", "Debian"), ("ceph-base", "Ceph")];

/// A change between major releases, see [`HistoryEntry::release_changes`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseChange {
    /// What changed its release, `Debian` or `Ceph`.
    pub name: &'static str,
    /// The major release before the change.
    pub old: u32,
    /// The major release after the change.
    pub new: u32,
}

/// The leading number of the upstream part of a package version.
fn major_version(version: &str) -> Option<u32> {
    let upstream = version
        .split_once(':')
        .map_or(version, |(_, upstream)| upstream);
    let end = upstream
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(upstream.len());
    upstream[..end].parse().ok()
}

/// The changelog entries for the changes a transaction made to binary packages built from the same
/// source package, which share its changelog.
///
/// Upgrades and downgrades show the entries of the versions they changed between, other changes
/// with a new version only the newest entry up to that version, as the version of a binary package
/// can differ from the one of its source package. Changes with different entries, for example as
/// their old versions differ, are kept apart, and so are changes whose version the changelog does
/// not list.
#[cfg_attr(feature = "api-types", api(
    properties: {
        packages: {
            type: Array,
            items: {
                type: PackageChange,
            },
        },
        entries: {
            type: Array,
            items: {
                type: ChangelogEntry,
            },
        },
        "unlisted-version": {
            optional: true,
            default: false,
        },
    },
))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TransactionChangelog {
    /// Name of the source package as its changelog lists it, or as APT names it for a changelog
    /// that could not be downloaded. Missing if no changelog is installed for the packages, for
    /// example as they got removed since, or if the source package is not known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The changes to the packages, in the order APT logged them.
    pub packages: Vec<PackageChange>,
    /// The changelog entries, usually newest first.
    #[serde(default)]
    pub entries: Vec<ChangelogEntry>,
    /// The changelog does not list the version the entries go up to, as for signed kernels or
    /// packages with their own epoch, so the entries are only its newest one, which can belong to a
    /// later version.
    #[serde(default, skip_serializing_if = "is_false")]
    #[cfg_attr(
        feature = "api-types",
        serde(deserialize_with = "proxmox_serde::perl::deserialize_bool")
    )]
    pub unlisted_version: bool,
    /// Why the changelog could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Format of the terminal output of a transaction.
#[cfg_attr(feature = "api-types", api)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TermLogFormat {
    /// Plain text.
    #[default]
    Plain,
    /// Text with SGR escape sequences for bold, dim and the basic foreground colors other than
    /// black and white. Each sets the complete style, starting with a reset, and no style spans a
    /// line break.
    Styled,
}

// Numbers are also accepted as strings, as Perl API handlers pass on query parameters as such.
#[cfg(feature = "api-types")]
#[api(
    properties: {
        limit: {
            optional: true,
            minimum: 1,
        },
    },
)]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
/// Options for listing APT history entries.
pub struct HistoryListOptions {
    /// Only list entries that started at or after this Unix epoch.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "proxmox_serde::perl::deserialize_i64"
    )]
    pub since: Option<i64>,
    /// Only list entries that started at or before this Unix epoch.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "proxmox_serde::perl::deserialize_i64"
    )]
    pub until: Option<i64>,
    /// Only list entries that changed the package with this name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    /// List at most this many entries.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "proxmox_serde::perl::deserialize_u64"
    )]
    pub limit: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changelog_range() {
        use PackageAction::*;

        let change = |action, old_version: Option<&str>, new_version: Option<&str>| PackageChange {
            action,
            package: "foo".to_string(),
            arch: None,
            old_version: old_version.map(str::to_string),
            new_version: new_version.map(str::to_string),
            automatic: false,
        };
        for (action, old, new, expected) in [
            (Upgrade, Some("1"), Some("2"), Some((Some("1"), "2"))),
            (Downgrade, Some("2"), Some("1"), Some((Some("1"), "2"))),
            (Upgrade, Some("2"), Some("2"), Some((None, "2"))),
            (Install, None, Some("2"), Some((None, "2"))),
            (Reinstall, Some("2"), Some("2"), Some((None, "2"))),
            (Remove, Some("2"), None, None),
        ] {
            assert_eq!(
                change(action, old, new).changelog_range(),
                expected,
                "{action:?}"
            );
        }
    }

    #[test]
    fn release_changes() {
        let change = |package: &str, old: Option<&str>, new: Option<&str>| PackageChange {
            action: PackageAction::Upgrade,
            package: package.to_string(),
            arch: None,
            old_version: old.map(str::to_string),
            new_version: new.map(str::to_string),
            automatic: false,
        };
        let entry = HistoryEntry {
            start_time: 0,
            start_index: 0,
            end_time: None,
            running: None,
            command_line: None,
            requested_by: None,
            requested_by_uid: None,
            comment: None,
            error: None,
            packages: vec![
                change("ceph-base", Some("17.2.8-pve2"), Some("19.2.3-1~bpo12+2")),
                change("base-files", Some("12.4+deb12u13"), Some("13.8+deb13u4")),
                change("ceph-common", Some("17.2.8-pve2"), Some("19.2.3-pve4")),
                change("base-files", Some("1:12.4"), Some("2:12.5")),
                change("ceph-base", None, Some("19.2.3-pve4")),
                change("base-files", Some("12.4"), Some("x13")),
            ],
        };
        let release = |name, old, new| ReleaseChange { name, old, new };
        assert_eq!(
            entry.release_changes().collect::<Vec<_>>(),
            [release("Ceph", 17, 19), release("Debian", 12, 13)]
        );
    }
}
