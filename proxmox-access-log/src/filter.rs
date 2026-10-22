use std::borrow::Cow;
use std::net::IpAddr;

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};

#[cfg(feature = "api-types")]
use proxmox_schema::{api, api_types::IP_SCHEMA};

use crate::AccessLogEntry;

/// The longest auth-id a filter accepts, as API token names of Proxmox VE have no length limit.
pub const MAX_AUTH_ID_LENGTH: usize = 1024;

#[cfg_attr(feature = "api-types", api(
    properties: {
        "auth-id": {
            optional: true,
            max_length: MAX_AUTH_ID_LENGTH,
        },
        client: {
            schema: IP_SCHEMA,
            optional: true,
        },
        method: {
            optional: true,
            max_length: 32,
        },
        path: {
            optional: true,
            max_length: 1024,
        },
        search: {
            optional: true,
            max_length: 1024,
        },
        "min-status": {
            optional: true,
            minimum: 100,
            maximum: 999,
        },
        "max-status": {
            optional: true,
            minimum: 100,
            maximum: 999,
        },
    },
))]
/// Criteria for selecting access log entries.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AccessLogFilter {
    /// Only entries logged at or after this time, in seconds since the epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<i64>,

    /// Only entries logged at or before this time, in seconds since the epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<i64>,

    /// Only requests of this user or API token. A user also matches its own API tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_id: Option<String>,

    /// Only requests from this client address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<IpAddr>,

    /// Only requests with this method, compared case-insensitively.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Only requests whose path contains this text. Repeated slashes count as one, as the servers
    /// route requests that way, and both are also compared percent-decoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Only requests whose client address, user or path contains this text, ignoring case. The
    /// path compares like for the path filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,

    /// Only responses with a known status code of at least this value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_status: Option<u16>,

    /// Only responses with a known status code of at most this value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_status: Option<u16>,
}

impl AccessLogFilter {
    /// Whether an entry meets all criteria.
    pub fn matches(&self, entry: &AccessLogEntry) -> bool {
        self.matches_fields(entry.time, entry.auth_id.as_deref(), entry.client)
            && self.method.as_deref().is_none_or(|method| {
                entry
                    .method
                    .as_deref()
                    .is_some_and(|entry_method| entry_method.eq_ignore_ascii_case(method))
            })
            && self.path.as_deref().is_none_or(|path| {
                entry
                    .path()
                    .is_some_and(|entry_path| path_matches(entry_path, path))
            })
            && self
                .search
                .as_deref()
                .is_none_or(|search| search_matches(entry, search))
            && self
                .min_status
                .is_none_or(|min| entry.status.is_some_and(|status| status >= min))
            && self
                .max_status
                .is_none_or(|max| entry.status.is_some_and(|status| status <= max))
    }

    fn matches_fields(&self, time: i64, auth_id: Option<&str>, client: Option<IpAddr>) -> bool {
        self.since.is_none_or(|since| time >= since)
            && self.until.is_none_or(|until| time <= until)
            && self.auth_id.as_deref().is_none_or(|filter| {
                auth_id.is_some_and(|auth_id| auth_id_matches(auth_id, filter))
            })
            && self
                .client
                .is_none_or(|filter| client == Some(filter.to_canonical()))
    }
}

/// Whether the logged path contains `filter`, also when percent-decoding both, as clients encode
/// some characters that occur in API paths, like the colon in `local%3Aiso`.
///
/// Repeated slashes count as one, as both servers skip empty path components when routing, so a
/// client cannot hide a request from a filter like `/access/ticket` by sending `/access//ticket`.
/// URI user information does not count, including network-path references, as redacting hides it.
fn path_matches(path: &str, filter: &str) -> bool {
    path_contains(path, filter, false)
}

/// Whether `path` contains `filter`, each as given or percent-decoded, with repeated slashes
/// collapsed and, with `fold_case`, ignoring case after decoding.
fn path_contains(path: &str, filter: &str, fold_case: bool) -> bool {
    let path = normalize(crate::strip_userinfo(path), fold_case);
    let filter = normalize(crate::strip_userinfo(filter), fold_case);
    if path.contains(&*filter) {
        return true;
    }
    let path = normalize(percent_decode_str(&path).decode_utf8_lossy(), fold_case);
    let decoded = || normalize(percent_decode_str(&filter).decode_utf8_lossy(), fold_case);
    path.contains(&*filter) || path.contains(&*decoded())
}

/// Collapses repeated slashes and, with `fold_case`, lowercases, keeping a text that needs neither
/// as it is, as most paths and filters do not.
fn normalize(text: Cow<'_, str>, fold_case: bool) -> Cow<'_, str> {
    match collapse_slashes(&text) {
        collapsed if fold_case => Cow::Owned(collapsed.to_lowercase()),
        Cow::Owned(collapsed) => Cow::Owned(collapsed),
        Cow::Borrowed(_) => text,
    }
}

/// Whether the client address, user or path of an entry contains `text`, ignoring case.
fn search_matches(entry: &AccessLogEntry, text: &str) -> bool {
    let text = text.to_lowercase();
    entry
        .client
        .is_some_and(|client| client.to_string().contains(&text))
        || entry
            .auth_id
            .as_deref()
            .is_some_and(|auth_id| auth_id.to_lowercase().contains(&text))
        || entry
            .path()
            .is_some_and(|path| path_contains(path, &text, true))
}

fn collapse_slashes(text: &str) -> Cow<'_, str> {
    if !text.contains("//") {
        return Cow::Borrowed(text);
    }
    let mut collapsed = String::with_capacity(text.len());
    for c in text.chars() {
        if c != '/' || !collapsed.ends_with('/') {
            collapsed.push(c);
        }
    }
    Cow::Owned(collapsed)
}

/// Whether `auth_id` is the `filter` itself or, if that is a user, one of its `user!token` IDs.
fn auth_id_matches(auth_id: &str, filter: &str) -> bool {
    auth_id == filter
        || (!filter.contains('!')
            && auth_id
                .strip_prefix(filter)
                .is_some_and(|token| token.starts_with('!')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LogFormat;

    fn entry(auth_id: &str, request: &str, status: u16) -> AccessLogEntry {
        AccessLogEntry::parse(
            &format!(
                "::ffff:192.0.2.10 - {auth_id} [22/10/2026:14:03:51 +0200] \
                 \"{request}\" {status} 5 -"
            ),
            LogFormat::RestServer,
        )
        .unwrap()
    }

    #[test]
    fn search() {
        let entry = AccessLogEntry::parse(
            "::ffff:192.0.2.10 - Root@pam!t [22/10/2026:14:03:51 +0200] \
             \"GET /api2/json//nodes/pve/storage/local%3Aiso?secret=hunter2\" 200 5 -",
            LogFormat::RestServer,
        )
        .unwrap();
        for (search, expected) in [
            ("192.0.2", true),
            ("::ffff", false),
            ("root@PAM", true),
            ("pam!t", true),
            ("/json/nodes", true),
            ("local:ISO", true),
            ("hunter2", false),
            ("secret", false),
            ("other", false),
            // case only gets ignored after decoding
            ("LOCAL%3aiso", true),
            ("%4Eodes", true),
        ] {
            let filter = AccessLogFilter {
                search: Some(search.to_string()),
                ..Default::default()
            };
            assert_eq!(filter.matches(&entry), expected, "{search}");
        }

        let entry = AccessLogEntry::parse(
            "192.0.2.10 - root@pam [22/10/2026:14:03:51 +0200] \"GET /api2/json/%4Eodes\" 200 5 -",
            LogFormat::RestServer,
        )
        .unwrap();
        for search in ["nodes", "/json/NODES"] {
            let filter = AccessLogFilter {
                search: Some(search.to_string()),
                ..Default::default()
            };
            assert!(filter.matches(&entry), "{search}");
        }
    }

    #[test]
    fn userinfo_does_not_match() {
        for (target, prefix) in [
            ("http://user:secret@host/x", "http:"),
            ("//user:secret@host/x", ""),
        ] {
            let entry = AccessLogEntry::parse(
                &format!(
                    "192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"GET {target} HTTP/1.1\" 200 5"
                ),
                LogFormat::PveHttpServer,
            )
            .unwrap();
            for (path, expected) in [
                (format!("{prefix}//user:s"), false),
                ("secret".to_string(), false),
                (format!("{prefix}//host/x"), true),
                (format!("{prefix}//[REDACTED]@host/x"), true),
                (target.to_string(), true),
                (format!("{prefix}//other:password@host/x"), true),
                (format!("{prefix}//[REDACTED]@host/y"), false),
                ("host/x".to_string(), true),
            ] {
                let filter = AccessLogFilter {
                    path: Some(path.clone()),
                    ..Default::default()
                };
                assert_eq!(filter.matches(&entry), expected, "{target} {path}");
                let search = AccessLogFilter {
                    search: Some(path.to_uppercase()),
                    ..Default::default()
                };
                assert_eq!(search.matches(&entry), expected, "search {target} {path}");
            }
        }
    }

    #[test]
    fn repeated_slashes() {
        for (request, filter, expected) in [
            ("GET /api2/json/access//ticket", "/access/ticket", true),
            ("GET /api2/json//access/ticket", "json/access/", true),
            ("GET /api2/json/access/ticket", "/access//ticket", true),
            ("GET /api2/json/access/%2F/ticket", "/access/ticket", true),
            ("GET /api2/json/access%2F%2Fticket", "/access/ticket", true),
            ("GET /api2/json/access/tickets", "/access/ticket/", false),
        ] {
            let filter = AccessLogFilter {
                path: Some(filter.to_string()),
                ..Default::default()
            };
            assert_eq!(
                filter.matches(&entry("-", request, 200)),
                expected,
                "{request} {filter:?}"
            );
        }
    }

    #[test]
    fn criteria() {
        let entry = entry(
            "root@pam!t",
            "POST /api2/json/nodes/pve/qemu/100/status/start/storage/local%3Aiso/x?y=%25",
            403,
        );
        let matches = |filter: AccessLogFilter| filter.matches(&entry);

        assert!(matches(AccessLogFilter::default()));

        assert!(matches(AccessLogFilter {
            since: Some(entry.time),
            until: Some(entry.time),
            ..Default::default()
        }));
        assert!(!matches(AccessLogFilter {
            since: Some(entry.time + 1),
            ..Default::default()
        }));
        assert!(!matches(AccessLogFilter {
            until: Some(entry.time - 1),
            ..Default::default()
        }));

        for (auth_id, expected) in [
            ("root@pam!t", true),
            ("root@pam", true),
            ("root@pa", false),
            ("root@pam!", false),
            ("root@pam!other", false),
            ("t", false),
        ] {
            let filter = AccessLogFilter {
                auth_id: Some(auth_id.to_string()),
                ..Default::default()
            };
            assert_eq!(matches(filter), expected, "{auth_id}");
        }

        for (client, expected) in [
            ("192.0.2.10", true),
            ("::ffff:192.0.2.10", true),
            ("192.0.2.11", false),
        ] {
            let filter = AccessLogFilter {
                client: Some(client.parse().unwrap()),
                ..Default::default()
            };
            assert_eq!(matches(filter), expected, "{client}");
        }

        for (method, expected) in [("POST", true), ("post", true), ("GET", false)] {
            let filter = AccessLogFilter {
                method: Some(method.to_string()),
                ..Default::default()
            };
            assert_eq!(matches(filter), expected, "{method}");
        }

        for (path, expected) in [
            ("/qemu/100/", true),
            ("/qemu/1001", false),
            ("/storage/local:iso/", true),
            ("/storage/local%3Aiso/", true),
            ("/storage/local%3A", true),
            ("local%3aiso", true),
            ("/local:iso/x", true),
            ("y=", false),
        ] {
            let filter = AccessLogFilter {
                path: Some(path.to_string()),
                ..Default::default()
            };
            assert_eq!(matches(filter), expected, "{path}");
        }

        let unknown = AccessLogEntry::parse(
            "192.0.2.1 - - [22/10/2026:14:03:51 +0200] \
             \"GET / HTTP/1.1 [22/10/2026:14:03:51 +0200] \"x\" 200 0",
            LogFormat::PveHttpServer,
        )
        .unwrap();
        for (min_status, max_status) in [
            (Some(100), None),
            (None, Some(999)),
            (None, Some(399)),
            (Some(400), None),
            (Some(400), Some(499)),
            (Some(500), None),
        ] {
            let filter = AccessLogFilter {
                min_status,
                max_status,
                ..Default::default()
            };
            assert!(!filter.matches(&unknown));
        }
        assert!(AccessLogFilter::default().matches(&unknown));

        for (min_status, max_status, expected) in [
            (Some(400), None, true),
            (None, Some(403), true),
            (Some(403), Some(403), true),
            (Some(404), None, false),
            (None, Some(402), false),
        ] {
            let filter = AccessLogFilter {
                min_status,
                max_status,
                ..Default::default()
            };
            assert_eq!(matches(filter), expected, "{min_status:?} {max_status:?}");
        }
    }

    #[test]
    fn requests_without_user_or_line() {
        let unauthenticated = entry("-", "GET /", 401);
        assert!(
            !AccessLogFilter {
                auth_id: Some("root@pam".to_string()),
                ..Default::default()
            }
            .matches(&unauthenticated)
        );

        let no_request = AccessLogEntry::parse(
            "192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"-\" 400 11",
            LogFormat::PveHttpServer,
        )
        .unwrap();
        for filter in [
            AccessLogFilter {
                method: Some("GET".to_string()),
                ..Default::default()
            },
            AccessLogFilter {
                path: Some("/".to_string()),
                ..Default::default()
            },
        ] {
            assert!(!filter.matches(&no_request));
        }
    }
}
