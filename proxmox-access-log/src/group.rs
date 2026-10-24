use std::borrow::Cow;

use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};

use crate::LogFormat;

/// The longest path group a filter accepts.
pub const MAX_PATH_GROUP_LENGTH: usize = 1024;

/// Segments longer than this count as one group, as they name something rather than a resource.
const MAX_SEGMENT_LENGTH: usize = 64;

/// What gets encoded again in a decoded segment, so it cannot read like a placeholder or contain
/// a separator.
const SEGMENT_ESCAPES: &AsciiSet = &CONTROLS.add(b'{').add(b'}').add(b'/').add(b'%');

/// Groups request paths that only differ in what names one of many objects, for statistics.
///
/// This looks at the path alone, so it only approximates the API routes the servers have. In API
/// paths, `/api2/<format>/...`, task IDs become `{upid}`, node names `{node}`, numbers `{id}`,
/// segments with an `@` `{userid}`, with a `:` `{volume}`, and ones longer than 64 bytes `{long}`.
/// Node names follow `nodes` at the API root, after `cluster/config`, or after a PDM remote's
/// `{pve,pbs}/remotes/<remote>` prefix. Other segments stay, percent-decoded, with `{`, `}`, `/`,
/// `%` and control characters encoded again. Paths outside the API keep only their first segment,
/// as they lead to static files. The query, repeated and trailing slashes and, for an absolute URI,
/// its scheme and authority do not count. PVE network-path targets also lose their authority; REST
/// paths beginning with `//` instead retain those path segments, as the writer logs no authority.
pub fn path_group(path: &str, format: LogFormat) -> String {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    let authority = if format == LogFormat::PveHttpServer && path.starts_with("//") {
        Some(&path[2..])
    } else if !path.starts_with('/') {
        path.find("://").map(|end| &path[end + 3..])
    } else {
        None
    };
    let path = authority.map_or(path, |rest| {
        rest.find('/').map_or("", |start| &rest[start..])
    });
    let segments: Vec<Cow<'_, str>> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| percent_decode_str(segment).decode_utf8_lossy())
        .collect();

    let mut group = String::new();
    match segments.as_slice() {
        [] => group.push('/'),
        [api, format, rest @ ..] if api.as_ref() == "api2" => {
            group.push_str("/api2/");
            group.push_str(&segment_group(format, false));
            let node = match rest {
                [nodes, ..] if nodes == "nodes" => Some(1),
                [cluster, config, nodes, ..]
                    if cluster == "cluster" && config == "config" && nodes == "nodes" =>
                {
                    Some(3)
                }
                [product, remotes, _, nodes, ..]
                    if matches!(product.as_ref(), "pve" | "pbs")
                        && remotes == "remotes"
                        && nodes == "nodes" =>
                {
                    Some(4)
                }
                _ => None,
            };
            for (index, segment) in rest.iter().enumerate() {
                group.push('/');
                group.push_str(&segment_group(segment, node == Some(index)));
            }
        }
        [first, ..] => {
            group.push('/');
            group.push_str(&segment_group(first, false));
        }
    }
    group
}

fn segment_group(segment: &str, after_nodes: bool) -> Cow<'_, str> {
    if segment.starts_with("UPID:") {
        "{upid}".into()
    } else if after_nodes {
        "{node}".into()
    } else if segment.bytes().all(|b| b.is_ascii_digit()) {
        "{id}".into()
    } else if segment.contains('@') {
        "{userid}".into()
    } else if segment.contains(':') {
        "{volume}".into()
    } else if segment.len() > MAX_SEGMENT_LENGTH {
        "{long}".into()
    } else {
        utf8_percent_encode(segment, SEGMENT_ESCAPES).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_paths() {
        for resource in ["version", "access/users"] {
            let path = format!("/api2/json/{resource}");
            for authority in ["host", "user:SECRET@host", ""] {
                let target = format!("//{authority}{path}");
                assert_eq!(path_group(&target, LogFormat::PveHttpServer), path);
            }
            assert_eq!(path_group(&format!("/{path}"), LogFormat::RestServer), path);
        }
        assert_eq!(path_group("//host", LogFormat::PveHttpServer), "/");
        assert_eq!(
            path_group("//host/api2/json/version", LogFormat::RestServer),
            "/host"
        );
    }

    #[test]
    fn groups() {
        let long = "x".repeat(MAX_SEGMENT_LENGTH + 1);
        for (path, group) in [
            ("/api2/json/nodes", "/api2/json/nodes"),
            (
                "/api2/json/nodes/pve1/qemu/100/status/current",
                "/api2/json/nodes/{node}/qemu/{id}/status/current",
            ),
            (
                "/api2/extjs/nodes/pve1/tasks/UPID%3Apve1%3A0000A1B2%3A00:/log",
                "/api2/extjs/nodes/{node}/tasks/{upid}/log",
            ),
            (
                "/api2/json/access/users/root@pam/token/t1",
                "/api2/json/access/users/{userid}/token/t1",
            ),
            (
                "/api2/json/nodes/pve/storage/local/content/local%3Aiso%2Fdebian.iso",
                "/api2/json/nodes/{node}/storage/local/content/{volume}",
            ),
            (
                "/api2/json/admin/datastore/store1/snapshots?ns=a",
                "/api2/json/admin/datastore/store1/snapshots",
            ),
            (
                "/api2/json//cluster//resources/",
                "/api2/json/cluster/resources",
            ),
            ("/api2/json/nodes/1", "/api2/json/nodes/{node}"),
            (
                "/api2/json/nodes/nodes/status",
                "/api2/json/nodes/{node}/status",
            ),
            (
                "/api2/json/cluster/config/nodes/nodes",
                "/api2/json/cluster/config/nodes/{node}",
            ),
            (
                "/api2/json/pve/remotes/nodes/nodes/nodes/status",
                "/api2/json/pve/remotes/nodes/nodes/{node}/status",
            ),
            (
                "/api2/json/pbs/remotes/nodes/nodes/pbs1/tasks",
                "/api2/json/pbs/remotes/nodes/nodes/{node}/tasks",
            ),
            (
                "/api2/json/pbs/remotes/nodes/status",
                "/api2/json/pbs/remotes/nodes/status",
            ),
            (
                "/api2/json/pbs/remotes/nodes/tasks",
                "/api2/json/pbs/remotes/nodes/tasks",
            ),
            (
                "/api2/json/nodes/pve/storage/nodes/status",
                "/api2/json/nodes/{node}/storage/nodes/status",
            ),
            (
                "/api2/json/admin/datastore/nodes/status",
                "/api2/json/admin/datastore/nodes/status",
            ),
            (&format!("/api2/json/x/{long}"), "/api2/json/x/{long}"),
            // decoded separators and braces stay within their segment
            ("/api2/json/a%2Fb/%7Bid%7D", "/api2/json/a%2Fb/%7Bid%7D"),
            ("/api2/json/100%25", "/api2/json/100%25"),
            ("/pve2/js/pvemanagerlib.js", "/pve2"),
            ("/favicon.ico", "/favicon.ico"),
            ("/api2", "/api2"),
            ("/", "/"),
            ("", "/"),
            (
                "http://user:secret@host/api2/json/version",
                "/api2/json/version",
            ),
            ("http://host", "/"),
        ] {
            for format in [LogFormat::PveHttpServer, LogFormat::RestServer] {
                assert_eq!(path_group(path, format), group, "{path}");
            }
        }
    }
}
