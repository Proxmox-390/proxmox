use serde::{Deserialize, Serialize};

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
}
