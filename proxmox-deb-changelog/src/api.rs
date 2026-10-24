//! API method for getting the changelog of an installed package, for mounting it in the APT API of
//! a node.
//!
//! The products set the permissions with [`ApiMethod::access`](proxmox_router::ApiMethod::access),
//! until then only the superuser has access.

use anyhow::{Error, format_err};

use proxmox_http_error::http_err;
use proxmox_schema::api;
use proxmox_schema::api_types::NODE_SCHEMA;

use crate::installed::{self, read_installed_changelog};
use crate::{ChangelogEntry, filter_versions};

#[api(
    input: {
        properties: {
            node: {
                schema: NODE_SCHEMA,
            },
            name: {
                description: "Name of the installed package.",
                type: String,
                max_length: 128,
            },
            "since-version": {
                description: "Only list the entries of versions later than this one.",
                type: String,
                max_length: 128,
                optional: true,
            },
            "to-version": {
                description: "Only list the entries of versions up to including this one, or only \
                    the newest entry if the changelog does not list this version.",
                type: String,
                max_length: 128,
                optional: true,
            },
        },
    },
    returns: {
        description: "The changelog entries, usually newest first.",
        type: Array,
        items: {
            type: ChangelogEntry,
        },
    },
)]
/// Get the Debian changelog that an installed package ships, optionally limited to a version
/// range.
pub async fn get_installed_changelog(
    name: String,
    since_version: Option<String>,
    to_version: Option<String>,
) -> Result<Vec<ChangelogEntry>, Error> {
    // big changelogs, possibly not in the page cache, must not block the async runtime
    let entries = tokio::task::spawn_blocking(move || read_installed_changelog(&name))
        .await
        .map_err(|err| format_err!("reading the changelog failed - {err}"))?
        .map_err(|err| match err {
            installed::Error::NotFound(_) => http_err!(NOT_FOUND, "{err}"),
            installed::Error::InvalidPackageName(_) => http_err!(BAD_REQUEST, "{err}"),
            err => err.into(),
        })?;

    filter_versions(entries, since_version.as_deref(), to_version.as_deref())
        .map_err(|err| http_err!(BAD_REQUEST, "{err}"))
}

#[cfg(test)]
mod tests {
    use proxmox_router::Permission;

    use super::*;

    #[test]
    fn superuser_only_by_default() {
        let method = &API_METHOD_GET_INSTALLED_CHANGELOG;
        assert!(matches!(method.access.permission, Permission::Superuser));
    }
}
