//! Parser for the API access logs of Proxmox products.
//!
//! Two HTTP server implementations write these logs, see [`LogFormat`] for which product uses
//! which. Both log one line per request, modeled after the common log format of Apache, but with a
//! numeric month in the timestamp:
//!
//! ```text
//! ::ffff:192.0.2.10 - root@pam [22/10/2026:14:03:51 +0200] "GET /api2/json/nodes HTTP/1.1" 200 89
//! ```
//!
//! [`AccessLogEntry::parse`] parses a single line, [`AccessLogReader`] the lines of a whole log.
//!
//! A failed write or data lost before writeback can leave a line that the next record continues.
//! REST logs and those of pve-http-server before 6.0.6 contain unescaped client text, and nothing
//! marks escaped PVE lines, so a timestamp-shaped record start can also be client input. In a REST
//! user agent, the parser drops the whole agent while keeping the preceding fields. In a PVE
//! request region, it leaves the outcome unknown and keeps a request only if the server's first
//! match ends before the marker with a delimited version. It does not recover a following record.
//! Such PVE entries remain visible without request or status filters, but can be excluded by them.
//!
//! A cut within a client address can join it with the next address into another valid address. That
//! line cannot be distinguished from an intact record. pve-http-server before 6.0.6 could split
//! long lines across writes, allowing client text to appear as separate records. These logs are not
//! an integrity-protected audit trail.

use std::net::IpAddr;
use std::ops::Range;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[cfg(feature = "api-types")]
use proxmox_schema::{api, api_types::IP_SCHEMA};

mod filter;
mod reader;
mod time;

pub use filter::{AccessLogFilter, MAX_AUTH_ID_LENGTH};
pub use reader::{AccessLogReader, Error};

/// proxmox-rest-server truncates user agents to this length. A longer one without a recognized
/// record start cannot stem from an intact log entry.
const MAX_USER_AGENT_LENGTH: usize = 128;

/// The access log formats of the HTTP servers used by Proxmox products.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogFormat {
    /// The format of `PVE::APIServer::AnyEvent` from pve-http-server.
    ///
    /// Proxmox VE logs to `/var/log/pveproxy/access.log`, for both `pveproxy` and `spiceproxy`,
    /// Proxmox Mail Gateway to `/var/log/pmgproxy/pmgproxy.log`.
    ///
    /// The request is the request line as the client sent it, including the HTTP version. Since
    /// 6.0.6, pve-http-server logs only the matched method, the target as the server parsed it,
    /// without fragment, and the HTTP version, escaping quotes, backslashes and bytes outside
    /// printable ASCII as `\xHH`, which the parser keeps. A target that parses to an empty one is
    /// logged as sent. The response size is missing for responses without a body and for streamed
    /// ones, and the user agent is not logged.
    ///
    /// A request region containing a timestamp-shaped record start can be a cut line continued by
    /// another record, or text a client sent. Status and size are left out. The request is kept
    /// only if the server's first match ends before the marker and its version is followed by `"`
    /// or Perl byte whitespace (space, tab, LF, VT, FF, CR).
    PveHttpServer,

    /// The format of proxmox-rest-server.
    ///
    /// Proxmox Backup Server logs to `/var/log/proxmox-backup/api/access.log`, Proxmox Datacenter
    /// Manager to `/var/log/proxmox-datacenter-manager/api/access.log`.
    ///
    /// The request consists of the method and the path and query of the URI, truncated to 3072
    /// bytes. The user agent, truncated to 128 bytes, follows the response size unquoted and
    /// extends to the end of the line. A user agent containing a timestamp-shaped record start is
    /// left out, as it is indistinguishable from a cut agent continued by another record.
    RestServer,
}

#[cfg_attr(feature = "api-types", api(
    properties: {
        client: {
            schema: IP_SCHEMA,
            optional: true,
        },
    },
))]
/// A request as recorded in an access log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AccessLogEntry {
    /// When the server logged the request, in seconds since the epoch. Servers log a request
    /// around the time they answer it, not when it arrives.
    pub time: i64,

    /// The offset of the server's local time to UTC at the time of logging, in seconds.
    pub utc_offset: i32,

    /// The client address. IPv4 clients of a server listening on a dual-stack socket are logged as
    /// IPv4-mapped IPv6 addresses, these are converted to plain IPv4 addresses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<IpAddr>,

    /// The authenticated user or API token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_id: Option<String>,

    /// The request method, with special characters escaped as `\xHH` since pve-http-server 6.0.6.
    /// Missing if the server did not read a valid request line or the request's attribution is
    /// ambiguous.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// The request target as logged, normally percent-encoded, as sent by the client before
    /// pve-http-server 6.0.6. proxmox-rest-server logs only its path and query, which are empty
    /// for a CONNECT target like `example.com:443`. Missing if the request was not read or its
    /// attribution is ambiguous.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,

    /// The HTTP version, like `1.1`, only logged by pve-http-server. Missing if the request was not
    /// read or its attribution is ambiguous.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_version: Option<String>,

    /// The raw request region of a pve-http-server log line, set if it contains more than method,
    /// URI and HTTP version. It can include another record after a cut line or, before
    /// pve-http-server 6.0.6, padding the server accepts and ignores. API callers must restrict
    /// this unredacted text to privileged users.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_line: Option<String>,

    /// The HTTP status code of the response, missing when the log line leaves the outcome
    /// ambiguous.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,

    /// The size of the response body in bytes. pve-http-server logs none for responses without a
    /// body and for streamed ones. proxmox-rest-server logs 0 or no size for compressed and
    /// streamed responses. Also missing when the outcome is ambiguous.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,

    /// The `User-Agent` header of the request, only logged by proxmox-rest-server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

/// The fields a line starts with, which all come before any text a client chose.
pub(crate) struct Prefix<'a> {
    pub(crate) client: Option<IpAddr>,
    pub(crate) auth_id: Option<&'a str>,
    pub(crate) time: i64,
    pub(crate) utc_offset: i32,
    /// The rest of the line after the opening quote of the request.
    pub(crate) rest: &'a str,
}

impl<'a> Prefix<'a> {
    pub(crate) fn parse(line: &'a str) -> Result<Self, ParseError> {
        let (client, rest) = line.split_once(' ').ok_or(ParseError::Client)?;
        let client = match client {
            "-" => None,
            client => Some(
                IpAddr::from_str(client)
                    .map_err(|_| ParseError::Client)?
                    .to_canonical(),
            ),
        };

        // the client's identity according to its ident server, which is never queried
        let rest = rest.strip_prefix("- ").ok_or(ParseError::Ident)?;

        let (auth_id, rest) = rest.split_once(' ').ok_or(ParseError::AuthId)?;
        let auth_id = match auth_id {
            "" => return Err(ParseError::AuthId),
            "-" => None,
            auth_id => Some(auth_id),
        };

        let (time, rest) = rest
            .strip_prefix('[')
            .and_then(|rest| rest.split_once("] "))
            .ok_or(ParseError::Time)?;
        let (time, utc_offset) = time::parse_timestamp(time).ok_or(ParseError::Time)?;

        let rest = rest.strip_prefix('"').ok_or(ParseError::Request)?;

        Ok(Self {
            client,
            auth_id,
            time,
            utc_offset,
            rest,
        })
    }
}

impl AccessLogEntry {
    /// Parses a single log line without its line terminator.
    pub fn parse(line: &str, format: LogFormat) -> Result<Self, ParseError> {
        let prefix = Prefix::parse(line)?;

        let mut entry = Self {
            time: prefix.time,
            utc_offset: prefix.utc_offset,
            client: prefix.client,
            auth_id: prefix.auth_id.map(str::to_string),
            method: None,
            uri: None,
            http_version: None,
            request_line: None,
            status: None,
            size: None,
            user_agent: None,
        };

        match format {
            LogFormat::PveHttpServer => entry.parse_pve_http_server_tail(prefix.rest)?,
            LogFormat::RestServer => entry.parse_rest_server_tail(prefix.rest)?,
        }

        Ok(entry)
    }

    fn parse_pve_http_server_tail(&mut self, rest: &str) -> Result<(), ParseError> {
        // The request line can contain anything a client sends, quotes and spaces included, so
        // only the fields after it can be split off reliably, from the end of the line.
        let (rest, size) = rest.rsplit_once(' ').ok_or(ParseError::Size)?;
        let (request_line, status) = rest.rsplit_once(' ').ok_or(ParseError::Status)?;
        let request_line = request_line.strip_suffix('"').ok_or(ParseError::Request)?;

        // A continuation can supply another record's status and size; client text can mimic it.
        if let Some(joined) = find_record_start(request_line) {
            parse_status(status)?;
            parse_size(size)?;
            self.request_line = Some(request_line.to_string());
            // The request is that of the first record only if the server's match ends before the
            // start, and the digits of its version cannot go on with the address of the next.
            let request = match_request_line(request_line).filter(|request| {
                request.end < joined && {
                    let next = request_line.as_bytes()[request.end];
                    next == b'"' || is_perl_space(next)
                }
            });
            if let Some(request) = request {
                self.set_pve_http_server_request(request_line, request);
            }
            return Ok(());
        }

        if request_line != "-" {
            let request = match_request_line(request_line).ok_or(ParseError::Request)?;
            if !self.set_pve_http_server_request(request_line, request) {
                return Err(ParseError::Request);
            }
        }
        self.status = Some(parse_status(status)?);
        self.size = parse_size(size)?;

        Ok(())
    }

    /// Sets method, URI and version from a request line match, returning false for a match the
    /// server rejects before logging its request line.
    fn set_pve_http_server_request(
        &mut self,
        request_line: &str,
        request: RequestLineMatch,
    ) -> bool {
        let uri = &request_line[request.uri];
        let version = &request_line[request.version];

        let major = version.split_once('.').map_or(version, |(major, _)| major);
        let authority = uri.find('@').is_some_and(|at| !uri[..at].contains('/'));
        if parse_decimal::<u64>(major) != Some(1) || authority {
            return false;
        }

        self.method = Some(request_line[request.method].to_string());
        self.uri = Some(uri.to_string());
        self.http_version = Some(version.to_string());
        if request.start != 0 || request.end != request_line.len() {
            self.request_line = Some(request_line.to_string());
        }
        true
    }

    fn parse_rest_server_tail(&mut self, rest: &str) -> Result<(), ParseError> {
        // URIs may contain quotes, so split the REST tail on spaces.
        let (method, rest) = rest.split_once(' ').ok_or(ParseError::Request)?;
        let (uri, rest) = rest.split_once(' ').ok_or(ParseError::Request)?;
        let uri = uri.strip_suffix('"').ok_or(ParseError::Request)?;
        // the URI is empty for a request target without path, like `example.com:443` of CONNECT
        if method.is_empty() {
            return Err(ParseError::Request);
        }

        let (status, rest) = rest.split_once(' ').unwrap_or((rest, ""));

        // lines written before proxmox-rest-server logged the user agent end with the size
        let (size, user_agent) = match rest.split_once(' ') {
            Some((size, user_agent)) => (size, Some(user_agent)),
            None => (rest, None),
        };
        // A possible continuation in the agent makes only the agent unsafe to attribute.
        let user_agent = user_agent.filter(|user_agent| find_record_start(user_agent).is_none());
        if user_agent.is_some_and(|user_agent| user_agent.len() > MAX_USER_AGENT_LENGTH) {
            return Err(ParseError::UserAgent);
        }

        self.method = Some(method.to_string());
        self.uri = Some(uri.to_string());
        self.status = Some(parse_status(status)?);
        self.size = parse_size(size)?;
        self.user_agent = user_agent
            .filter(|user_agent| !matches!(*user_agent, "" | "-"))
            .map(str::to_string);

        Ok(())
    }

    /// The path of the request target, without the query.
    pub fn path(&self) -> Option<&str> {
        let uri = self.uri.as_deref()?;
        Some(uri.split_once('?').map_or(uri, |(path, _)| path))
    }

    /// The query of the request target, without the leading `?`.
    pub fn query(&self) -> Option<&str> {
        Some(self.uri.as_deref()?.split_once('?')?.1)
    }

    /// Removes what is most likely to contain secrets before showing an entry to API users.
    ///
    /// Both servers accept the parameters of any call in the query, passwords included, so this
    /// replaces the value of each query parameter, keeping its name, and drops the request line,
    /// which repeats the query. It also replaces URI user information, like
    /// `http://user:pass@host/` or `//user:pass@host/`, which pve-http-server logs as sent. Names
    /// and paths can still contain secrets in rare cases.
    pub fn redact(&mut self, format: LogFormat) {
        self.request_line = None;

        let Some(uri) = self.uri.take() else {
            return;
        };
        let (path, query) = match uri.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (uri.as_str(), None),
        };
        let mut redacted = redact_userinfo(path);
        let Some(query) = query else {
            self.uri = Some(redacted);
            return;
        };

        // pve-http-server also separates parameters with semicolons
        let is_separator = |c: char| c == '&' || (c == ';' && format == LogFormat::PveHttpServer);

        // TODO: replace only the values of parameters that the API schema marks as sensitive and
        // keep the others, like filters, readable.
        redacted.push('?');
        let mut rest = query;
        loop {
            let end = rest.find(is_separator).unwrap_or(rest.len());
            match rest[..end].split_once('=') {
                Some((name, _)) => {
                    redacted.push_str(name);
                    redacted.push_str("=[REDACTED]");
                }
                None => redacted.push_str(&rest[..end]),
            }
            let Some(separator) = rest[end..].chars().next() else {
                break;
            };
            redacted.push(separator);
            rest = &rest[end + separator.len_utf8()..];
        }
        self.uri = Some(redacted);
    }
}

/// Replaces the user information in a URI authority.
fn redact_userinfo(path: &str) -> String {
    match userinfo(path) {
        Some(userinfo) => format!(
            "{}[REDACTED]{}",
            &path[..userinfo.start],
            &path[userinfo.end..]
        ),
        None => path.to_string(),
    }
}

/// Removes the user information in a URI authority, with its `@`.
pub(crate) fn strip_userinfo(path: &str) -> std::borrow::Cow<'_, str> {
    match userinfo(path) {
        Some(userinfo) => {
            format!("{}{}", &path[..userinfo.start], &path[userinfo.end + 1..]).into()
        }
        None => path.into(),
    }
}

/// Where the user information in the authority of an absolute URI or a network-path reference
/// like `//user:password@host/` is, without its `@`. pve-http-server routes both by their path.
fn userinfo(path: &str) -> Option<Range<usize>> {
    let authority_start = match path.strip_prefix("//") {
        Some(_) => 2,
        None if path.starts_with('/') => return None,
        None => path.find("://")? + "://".len(),
    };
    let authority_end = path[authority_start..]
        .find('/')
        .map_or(path.len(), |end| authority_start + end);
    let at = path[authority_start..authority_end].rfind('@')?;
    Some(authority_start..authority_start + at)
}

/// Finds the first writer-shaped timestamp followed by the opening quote of a request. Recognition
/// is separate from converting an entry's own time: writers can emit leap seconds, variable-width
/// years and offsets, or `[-]` on a formatting failure, which the strict time parser rejects.
fn find_record_start(text: &str) -> Option<usize> {
    fn matches(mut rest: &[u8]) -> Option<()> {
        if rest.starts_with(b"-] \"") {
            return Some(());
        }
        for separator in [b'/', b'/'] {
            let (digits, tail) = rest.split_at_checked(2)?;
            if !digits.iter().all(u8::is_ascii_digit) {
                return None;
            }
            rest = tail.strip_prefix(&[separator])?;
        }
        rest = rest.strip_prefix(b"-").unwrap_or(rest);
        let year_end = digits_end(rest, 0);
        if year_end == 0 {
            return None;
        }
        rest = rest[year_end..].strip_prefix(b":")?;
        for separator in [b':', b':', b' '] {
            let (digits, tail) = rest.split_at_checked(2)?;
            if !digits.iter().all(u8::is_ascii_digit) {
                return None;
            }
            rest = tail.strip_prefix(&[separator])?;
        }
        let (sign, rest) = rest.split_first()?;
        if !matches!(sign, b'+' | b'-') {
            return None;
        }
        let offset_end = digits_end(rest, 0);
        (offset_end >= 4 && rest[offset_end..].starts_with(b"] \"")).then_some(())
    }

    text.as_bytes().iter().enumerate().find_map(|(start, &b)| {
        (b == b'[' && matches(&text.as_bytes()[start + 1..]).is_some()).then_some(start)
    })
}

/// Where a request line matched, and its method, URI and version groups.
struct RequestLineMatch {
    start: usize,
    end: usize,
    method: Range<usize>,
    uri: Range<usize>,
    version: Range<usize>,
}

/// Locates method, URI and HTTP version in a request line the way pve-http-server does.
///
/// The server matches request lines against `(\S+)\040(\S+)\040HTTP\/(\d+)\.(\d+)` without
/// any anchors, so it accepts, handles and logs request lines with arbitrary text around these.
fn match_request_line(line: &str) -> Option<RequestLineMatch> {
    let bytes = line.as_bytes();
    let mut start = 0;
    loop {
        // Trying word starts suffices: a match beginning inside a word has the same word end.
        start += bytes[start..].iter().position(|&b| !is_perl_space(b))?;
        let method = start..word_end(bytes, start);
        if let Some((uri, version)) = match_uri_and_version(bytes, method.end) {
            return Some(RequestLineMatch {
                start,
                end: version.end,
                method,
                uri,
                version,
            });
        }
        start = method.end;
    }
}

/// Matches `\040(\S+)\040HTTP\/(\d+)\.(\d+)` at `pos`, returning the URI and version ranges.
fn match_uri_and_version(bytes: &[u8], pos: usize) -> Option<(Range<usize>, Range<usize>)> {
    if bytes.get(pos) != Some(&b' ') {
        return None;
    }

    let uri_start = pos + 1;
    let uri = uri_start..word_end(bytes, uri_start);
    if uri.is_empty() || !bytes[uri.end..].starts_with(b" HTTP/") {
        return None;
    }

    let major_start = uri.end + b" HTTP/".len();
    let major_end = digits_end(bytes, major_start);
    if major_end == major_start || bytes.get(major_end) != Some(&b'.') {
        return None;
    }

    let minor_end = digits_end(bytes, major_end + 1);
    if minor_end == major_end + 1 {
        return None;
    }

    Some((uri, major_start..minor_end))
}

/// Whether `\s` of a Perl regular expression matches the byte in a byte string, which includes
/// the vertical tab, unlike [`u8::is_ascii_whitespace`].
fn is_perl_space(b: u8) -> bool {
    matches!(b, b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r' | b' ')
}

fn word_end(bytes: &[u8], start: usize) -> usize {
    bytes[start..]
        .iter()
        .position(|&b| is_perl_space(b))
        .map_or(bytes.len(), |len| start + len)
}

fn digits_end(bytes: &[u8], start: usize) -> usize {
    bytes[start..]
        .iter()
        .position(|b| !b.is_ascii_digit())
        .map_or(bytes.len(), |len| start + len)
}

/// Parses a decimal number, without the sign that [`FromStr`] of integers accepts.
fn parse_decimal<T: FromStr>(s: &str) -> Option<T> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn parse_status(status: &str) -> Result<u16, ParseError> {
    match parse_decimal::<u16>(status) {
        Some(code @ 100..=999) if status.len() == 3 => Ok(code),
        _ => Err(ParseError::Status),
    }
}

fn parse_size(size: &str) -> Result<Option<u64>, ParseError> {
    match size {
        "-" => Ok(None),
        size => parse_decimal(size).map(Some).ok_or(ParseError::Size),
    }
}

/// The field of an access log line that failed to parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    #[error("invalid client address")]
    Client,
    #[error("invalid ident field")]
    Ident,
    #[error("invalid user field")]
    AuthId,
    #[error("invalid timestamp")]
    Time,
    #[error("invalid request")]
    Request,
    #[error("invalid status code")]
    Status,
    #[error("invalid response size")]
    Size,
    #[error("invalid user agent")]
    UserAgent,
    #[error("line too long")]
    TooLong,
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn parse_pve(line: &str) -> Result<AccessLogEntry, ParseError> {
        AccessLogEntry::parse(line, LogFormat::PveHttpServer)
    }

    fn parse_rest(line: &str) -> Result<AccessLogEntry, ParseError> {
        AccessLogEntry::parse(line, LogFormat::RestServer)
    }

    fn request_parts(entry: &AccessLogEntry) -> (Option<&str>, Option<&str>, Option<&str>) {
        (
            entry.method.as_deref(),
            entry.uri.as_deref(),
            entry.http_version.as_deref(),
        )
    }

    #[test]
    fn pve_http_server_line() {
        let entry = parse_pve(
            "::ffff:192.0.2.10 - root@pam!monitoring [22/10/2026:14:03:51 +0200] \
             \"GET /api2/json/cluster/resources?type=vm HTTP/1.1\" 200 1234",
        )
        .unwrap();

        assert_eq!(
            entry,
            AccessLogEntry {
                time: 1792670631,
                utc_offset: 7200,
                client: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
                auth_id: Some("root@pam!monitoring".to_string()),
                method: Some("GET".to_string()),
                uri: Some("/api2/json/cluster/resources?type=vm".to_string()),
                http_version: Some("1.1".to_string()),
                request_line: None,
                status: Some(200),
                size: Some(1234),
                user_agent: None,
            }
        );
        assert_eq!(entry.path(), Some("/api2/json/cluster/resources"));
        assert_eq!(entry.query(), Some("type=vm"));
    }

    #[test]
    fn pve_http_server_unauthenticated_and_unsized() {
        let entry = parse_pve(
            "::1 - - [22/10/2026:14:03:51 -0330] \
             \"GET /api2/json/nodes/pve/qemu/100/vncwebsocket HTTP/1.1\" 101 -",
        )
        .unwrap();
        assert_eq!(entry.client, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(entry.auth_id, None);
        assert_eq!(entry.utc_offset, -(3 * 3600 + 30 * 60));
        assert_eq!(entry.status, Some(101));
        assert_eq!(entry.size, None);
        assert_eq!(entry.query(), None);
    }

    #[test]
    fn pve_http_server_without_request_line() {
        let entry = parse_pve("- - - [22/10/2026:14:03:51 +0200] \"-\" 400 11").unwrap();
        assert_eq!(entry.client, None);
        assert_eq!(request_parts(&entry), (None, None, None));
        assert_eq!(entry.request_line, None);
        assert_eq!(entry.path(), None);
        assert_eq!(entry.status, Some(400));
    }

    #[test]
    fn pve_http_server_request_line_with_extra_text() {
        let entry = parse_pve(
            "192.0.2.10 - root@pam [22/10/2026:14:03:51 +0200] \
             \"x\ty GET /api2/json/version HTTP/1.1\" 200 \"x\" 401 -\" 200 89",
        )
        .unwrap();
        assert_eq!(
            request_parts(&entry),
            (Some("GET"), Some("/api2/json/version"), Some("1.1"))
        );
        assert_eq!(
            entry.request_line.as_deref(),
            Some("x\ty GET /api2/json/version HTTP/1.1\" 200 \"x\" 401 -")
        );
        assert_eq!(entry.status, Some(200));
        assert_eq!(entry.size, Some(89));
    }

    #[test]
    fn pve_http_server_request_line_matching() {
        let line = |request: &str| {
            format!("192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"{request}\" 501 -")
        };

        let valid = [
            ("GET / HTTP/1.0", ("GET", "/", "1.0")),
            // the first two words can only start a match together
            ("a GET / HTTP/1.1", ("GET", "/", "1.1")),
            ("a b c HTTP/1.1", ("b", "c", "1.1")),
            // the separators must be a single space each
            ("GET  a / HTTP/1.1", ("a", "/", "1.1")),
            ("a\tGET / HTTP/1.1", ("GET", "/", "1.1")),
            ("a\x0bGET / HTTP/1.1", ("GET", "/", "1.1")),
            // non-ASCII bytes are no whitespace, even where they encode a Unicode space
            ("GET /\u{a0} HTTP/1.1", ("GET", "/\u{a0}", "1.1")),
            // the version digits are greedy, anything can follow them
            ("GET / HTTP/1.34x", ("GET", "/", "1.34")),
            ("GET / HTTP/01.1", ("GET", "/", "01.1")),
            ("GET / HTTP/1.1 HTTP/2.0", ("GET", "/", "1.1")),
            // only an `@` before the first slash makes the server reject the URL
            ("GET /a@b HTTP/1.1", ("GET", "/a@b", "1.1")),
            ("GET / HTTP/x GET /b HTTP/1.1", ("GET", "/b", "1.1")),
        ];
        for (request, (method, uri, version)) in valid {
            let entry = parse_pve(&line(request)).unwrap();
            assert_eq!(
                request_parts(&entry),
                (Some(method), Some(uri), Some(version)),
                "{request:?}"
            );
            let canonical = request == format!("{method} {uri} HTTP/{version}");
            assert_eq!(entry.request_line.is_none(), canonical, "{request:?}");
        }

        let invalid = [
            "",
            " ",
            "GET /",
            "GET\t/ HTTP/1.1",
            "GET  / HTTP/1.1",
            "GET / http/1.1",
            "GET / HTTP/",
            "GET / HTTP/1",
            "GET / HTTP/.1",
            // rejected by the server before it logs the request line
            "GET / HTTP/2.0",
            "GET / HTTP/12.34x",
            "GET / HTTP/2.0 GET /b HTTP/1.1",
            "GET example.com@evil/ HTTP/1.1",
            "GET a@b HTTP/1.1",
        ];
        for request in invalid {
            assert_eq!(
                parse_pve(&line(request)),
                Err(ParseError::Request),
                "{request:?}"
            );
        }
    }

    #[test]
    fn rest_server_line() {
        let entry = parse_rest(
            "::ffff:192.0.2.10 - root@pam [22/10/2026:14:03:51 +0200] \
             \"GET /api2/extjs/status/metrics?history=true\" 200 218905 \
             Mozilla/5.0 (X11; Linux x86_64; rv:157.0) Gecko/20100101 Firefox/157.0",
        )
        .unwrap();

        assert_eq!(
            entry,
            AccessLogEntry {
                time: 1792670631,
                utc_offset: 7200,
                client: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
                auth_id: Some("root@pam".to_string()),
                method: Some("GET".to_string()),
                uri: Some("/api2/extjs/status/metrics?history=true".to_string()),
                http_version: None,
                request_line: None,
                status: Some(200),
                size: Some(218905),
                user_agent: Some(
                    "Mozilla/5.0 (X11; Linux x86_64; rv:157.0) Gecko/20100101 Firefox/157.0"
                        .to_string()
                ),
            }
        );
        assert_eq!(entry.path(), Some("/api2/extjs/status/metrics"));
        assert_eq!(entry.query(), Some("history=true"));
    }

    #[test]
    fn rest_server_user_agent() {
        let line = |tail: &str| {
            format!("192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"POST /api2/json/x\" 401 0{tail}")
        };
        let user_agent = |tail: &str| parse_rest(&line(tail)).map(|entry| entry.user_agent);

        assert_eq!(user_agent(""), Ok(None));
        assert_eq!(user_agent(" "), Ok(None));
        assert_eq!(user_agent(" -"), Ok(None));
        assert_eq!(
            user_agent(" curl/8.14.1"),
            Ok(Some("curl/8.14.1".to_string()))
        );
        assert_eq!(
            user_agent(" a \" 200 5 b"),
            Ok(Some("a \" 200 5 b".to_string()))
        );

        let longest = "x".repeat(MAX_USER_AGENT_LENGTH);
        assert_eq!(
            user_agent(&format!(" {longest}")),
            Ok(Some(longest.clone()))
        );
        assert_eq!(
            user_agent(&format!(" {longest}x")),
            Err(ParseError::UserAgent)
        );
    }

    #[test]
    fn rest_server_uri_with_quotes() {
        let entry =
            parse_rest("192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"GET /a\"b\"\" 404 0 -")
                .unwrap();
        assert_eq!(request_parts(&entry), (Some("GET"), Some("/a\"b\""), None));
    }

    #[test]
    fn rest_server_request_without_path() {
        let entry = parse_rest(
            "192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"CONNECT \" 400 21 curl/8.14.1",
        )
        .unwrap();
        assert_eq!(request_parts(&entry), (Some("CONNECT"), Some(""), None));
        assert_eq!(entry.path(), Some(""));
        assert_eq!(entry.status, Some(400));
        assert_eq!(entry.user_agent.as_deref(), Some("curl/8.14.1"));

        assert_eq!(
            parse_rest("192.0.2.10 - - [22/10/2026:14:03:51 +0200] \" \" 400 21 -"),
            Err(ParseError::Request)
        );
    }

    #[test]
    fn rest_server_torn_lines() {
        assert_eq!(
            parse_rest(
                "::ffff:192.0.2.10 - root@pam!t [19/05/2026:23:40:19 +0200] \"GET /api2/json/ad\
                 ::ffff:192.0.2.10 - root@pam!t [19/05/2026:23:46:59 +0200] \
                 \"GET /api2/json/admin/datastore\" 200 100 libwww-perl/6.78"
            ),
            Err(ParseError::Request)
        );
        // cut within the user agent, everything before it is still the first record's
        let entry = parse_rest(
            "::ffff:192.0.2.10 - root@pam!t [21/09/2026:03:43:41 +0200] \
             \"GET /api2/json/admin/datastore\" 200 100 libwww-perl/6\
             ::ffff:192.0.2.10 - root@pam!t [21/09/2026:03:44:41 +0200] \
             \"GET /api2/json/admin/datastore\" 200 100 libwww-perl/6.78",
        )
        .unwrap();
        assert_eq!(entry.time, 1789955021);
        assert_eq!(entry.status, Some(200));
        assert_eq!(entry.user_agent, None);
    }

    #[test]
    fn rest_server_user_agent_with_record_start() {
        let line = |user_agent: &str| {
            format!(
                "::ffff:192.0.2.10 - root@pam [22/10/2026:14:03:51 +0200] \
                 \"GET /api2/json/version\" 200 89 {user_agent}"
            )
        };

        // a short next record fits into the length of a user agent
        let mut entry = parse_rest(&line(
            "curl::ffff:192.0.2.11 - - [22/10/2026:14:03:52 +0200] \
             \"POST /api2/json/access/ticket?password=SECRET\" 401 0 -",
        ))
        .unwrap();
        assert_eq!(
            request_parts(&entry),
            (Some("GET"), Some("/api2/json/version"), None)
        );
        assert_eq!((entry.status, entry.size), (Some(200), Some(89)));
        assert_eq!(entry.user_agent, None);
        entry.redact(LogFormat::RestServer);
        assert!(!serde_json::to_string(&entry).unwrap().contains("SECRET"));

        // a client can send such a user agent, and only loses it
        let entry = parse_rest(&line("x [22/10/2026:14:03:51 +0200] \"y")).unwrap();
        assert_eq!(entry.user_agent, None);
        assert_eq!(entry.status, Some(200));

        for user_agent in [
            "x [22/1/2026:14:03:51 +0200] \"y",
            "x [22/10/2026:14:03:51 +0200]\"y",
            "x [22/10/2026:14:03:51 +0200] y",
            "x [-]\"y",
            "x [22/10/2026:14:03:51 +0200] ",
        ] {
            let entry = parse_rest(&line(user_agent)).unwrap();
            assert_eq!(entry.user_agent.as_deref(), Some(user_agent));
        }
    }

    const RECORD_TIMES: &[&str] = &[
        "22/10/2026:14:03:51 +0200",
        "-",
        "31/12/2016:23:59:60 +0000",
        "01/01/10000:00:00:00 +0000",
        "01/01/-1:00:00:00 -0000",
        "01/01/1:00:00:00 +12345",
        "00/99/2026:99:99:99 +9999",
    ];

    #[test]
    fn record_start_shapes() {
        for time in RECORD_TIMES {
            let marker = format!("[{time}] \"");
            assert_eq!(find_record_start(&marker), Some(0));
            for end in 0..marker.len() {
                assert_eq!(find_record_start(&marker[..end]), None, "cut at {end}");
            }
            for prefix in ["é", "[[broken", "[22/10/2026:14:03:51 +020é"] {
                let text = format!("{prefix}{marker}tail{marker}");
                assert_eq!(find_record_start(&text), Some(prefix.len()));
            }
        }
        for text in [
            "[1/01/2026:00:00:00 +0000] \"",
            "[01/01/:00:00:00 +0000] \"",
            "[01/01/+:00:00:00 +0000] \"",
            "[01/01/2026:0:00:00 +0000] \"",
            "[01/01/2026:00:00:00 0000] \"",
            "[01/01/2026:00:00:00 +000] \"",
            "[01/01/2026:00:00:00 +0000]\"",
            "[01/01/2026:00:00:00 +0000]  \"",
            "[-] ",
            "[é",
        ] {
            assert_eq!(find_record_start(text), None, "{text:?}");
        }
        let text = String::from_utf8_lossy(b"\xff[\xe2\x82[-] \"");
        assert_eq!(find_record_start(&text), Some(text.find("[-]").unwrap()));
        let text = format!("[01/01/{}:00:00:00 +0000] \"", "1".repeat(4096));
        assert_eq!(find_record_start(&text), Some(0));
    }

    #[test]
    fn writer_timestamp_shapes_in_client_text() {
        for time in RECORD_TIMES {
            let mut entry = parse_rest(&format!(
                "192.0.2.10 - root@pam [22/10/2026:14:03:51 +0200] \
                 \"GET /first\" 200 5 curl192.0.2.11 - - [{time}] \
                 \"POST /x?p=SECRET\" 401 0 -"
            ))
            .unwrap();
            assert_eq!((entry.status, entry.size), (Some(200), Some(5)));
            assert_eq!(entry.user_agent, None);
            assert_eq!(entry.uri.as_deref(), Some("/first"));
            entry.redact(LogFormat::RestServer);
            assert!(!serde_json::to_string(&entry).unwrap().contains("SECRET"));

            let entry = parse_pve(&format!(
                "192.0.2.10 - root@pam [22/10/2026:14:03:51 +0200] \
                 \"GET /first HTTP/1.1\" 200 5 192.0.2.11 - - [{time}] \
                 \"POST /x?p=SECRET HTTP/1.1\" 401 0"
            ))
            .unwrap();
            assert_eq!((entry.status, entry.size), (None, None));
            assert_eq!(
                request_parts(&entry),
                (Some("GET"), Some("/first"), Some("1.1"))
            );
            assert_eq!(entry.auth_id.as_deref(), Some("root@pam"));

            if *time != RECORD_TIMES[0] {
                for (format, request) in [
                    (LogFormat::RestServer, "GET /"),
                    (LogFormat::PveHttpServer, "GET / HTTP/1.1"),
                ] {
                    assert_eq!(
                        AccessLogEntry::parse(
                            &format!("192.0.2.10 - - [{time}] \"{request}\" 200 5"),
                            format,
                        ),
                        Err(ParseError::Time),
                    );
                }
            }
        }
        // The marker can start beyond the writer's agent limit on a cut line.
        let agent = format!("{}[-] \"", "x".repeat(MAX_USER_AGENT_LENGTH + 1));
        let line = format!("192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"GET /\" 200 5 {agent}");
        assert_eq!(parse_rest(&line).unwrap().user_agent, None);
    }

    /// Parses the first record cut after each of its bytes, continued by the second.
    fn cut_lines(first: &str, second: &str) -> Vec<(usize, String)> {
        (1..=first.len())
            .filter(|&cut| first.is_char_boundary(cut))
            .map(|cut| (cut, format!("{}{second}", &first[..cut])))
            .collect()
    }

    #[test]
    fn rest_server_cut_lines() {
        let first = "::ffff:192.0.2.10 - root@pam [22/10/2026:14:03:51 +0200] \
                     \"GET /api2/json/nodes/x/status?a=1\" 200 1234 proxmox-backup-client/4.0";
        let expected = parse_rest(first).unwrap();
        for second in [
            "::ffff:192.0.2.11 - - [22/10/2026:14:03:52 +0200] \"POST /x?p=SECRET\" 401 0 -",
            "::ffff:192.0.2.11 - user@pbs [22/10/2026:14:03:52 +0200] \
             \"GET /api2/json/admin/datastore/x/snapshots?ns=SECRET\" 404 21 \
             Mozilla/5.0 (X11; Linux x86_64; rv:157.0) Gecko/20100101 Firefox/157.0",
        ] {
            let mut accepted = 0;
            for (cut, line) in cut_lines(first, second) {
                let Ok(mut entry) = parse_rest(&line) else {
                    continue;
                };
                accepted += 1;
                assert_eq!(
                    entry,
                    AccessLogEntry {
                        user_agent: None,
                        ..expected.clone()
                    },
                    "cut at {cut}"
                );
                entry.redact(LogFormat::RestServer);
                assert!(!serde_json::to_string(&entry).unwrap().contains("SECRET"));
            }
            assert!(accepted > 0);
        }
    }

    #[test]
    fn pve_http_server_request_line_with_record_start() {
        let line = |request: &str| {
            format!("::ffff:192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"{request}\" 200 89")
        };
        let parse = |request: &str| parse_pve(&line(request)).unwrap();

        let entry = parse(
            "GET /api2/json/version HTTP/1.1 192.0.2.99 - root@pam \
             [22/10/2026:14:03:51 +0200] \"DELETE /x HTTP/1.1\" 200 5",
        );
        assert_eq!(
            request_parts(&entry),
            (Some("GET"), Some("/api2/json/version"), Some("1.1"))
        );
        assert_eq!(entry.auth_id, None);
        assert_eq!((entry.status, entry.size), (None, None));
        assert!(entry.request_line.is_some());

        // a request after the start can be that of the next record
        for request in [
            "x [22/10/2026:14:03:51 +0200] \"y GET /api2/json/version HTTP/1.1",
            "[22/10/2026:14:03:51 +0200] \" GET / HTTP/1.1",
            "GET /a[22/10/2026:14:03:51 +0200] \" HTTP/1.1",
            // version digits that could continue with the next record's address
            "GET / HTTP/1.1x [22/10/2026:14:03:51 +0200] \"",
            "GET / HTTP/1.1[22/10/2026:14:03:51 +0200] \"",
        ] {
            let entry = parse(request);
            assert_eq!(request_parts(&entry), (None, None, None), "{request:?}");
            assert_eq!(entry.client, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))));
            assert_eq!(entry.time, 1792670631);
            assert_eq!((entry.status, entry.size), (None, None), "{request:?}");
            assert_eq!(entry.request_line.as_deref(), Some(request));
        }

        assert_eq!(
            parse_pve(
                "192.0.2.10 - - [22/10/2026:14:03:51 +0200] \
                 \"GET / HTTP/1.1 [22/10/2026:14:03:51 +0200] \"x\" 20 5"
            ),
            Err(ParseError::Status)
        );

        assert_eq!(
            parse_pve(
                "192.0.2.10 - - [22/10/2026:14:03:51 +0200] \
                 \"GET / HTTP/1.1 [-] \"x\" 200 +5"
            ),
            Err(ParseError::Size)
        );

        for request in [
            "GET / HTTP/2.0 [-] \"x",
            "GET user@host HTTP/1.1 [-] \"x",
            "GET /decoy HTTP/1.192.0.2.11 - - [-] \"GET /real HTTP/1.1",
        ] {
            let entry = parse(request);
            assert_eq!(request_parts(&entry), (None, None, None));
            assert_eq!((entry.status, entry.size), (None, None));
        }
        for delimiter in ['\"', ' ', '\t', '\n', '\u{b}', '\u{c}', '\r'] {
            let entry = parse(&format!("GET / HTTP/1.1{delimiter}[-] \"x"));
            assert_eq!(request_parts(&entry), (Some("GET"), Some("/"), Some("1.1")));
            assert_eq!((entry.status, entry.size), (None, None));
        }

        let entry = parse("GET / HTTP/1.1 [22/13/2026:14:03:51 +0200] x");
        assert_eq!(entry.status, Some(200));
    }

    #[test]
    fn pve_http_server_cut_lines() {
        let second = "::ffff:192.0.2.11 - - [22/10/2026:14:03:52 +0200] \
                      \"POST /api2/json/access/ticket?password=SECRET HTTP/1.1\" 401 9";
        for first in [
            "::ffff:192.0.2.10 - root@pam [22/10/2026:14:03:51 +0200] \
             \"GET /api2/json/nodes/x/status?a=1 HTTP/1.1\" 200 1234",
            "::ffff:192.0.2.10 - root@pam [22/10/2026:14:03:51 +0200] \
             \"x GET /api2/json/nodes/x/status HTTP/1.1 \" 200 5\" 501 -",
            "- - root@pam!t [22/10/2026:14:03:51 +0200] \"GET /first HTTP/1.0\" 200 -",
        ] {
            let expected = parse_pve(first).unwrap();
            let mut with_request = 0;
            for (cut, line) in cut_lines(first, second) {
                let Ok(mut entry) = parse_pve(&line) else {
                    continue;
                };
                assert_eq!(
                    (entry.time, entry.utc_offset, entry.client, &entry.auth_id),
                    (
                        expected.time,
                        expected.utc_offset,
                        expected.client,
                        &expected.auth_id
                    ),
                    "cut at {cut}"
                );
                assert_eq!((entry.status, entry.size), (None, None), "cut at {cut}");
                if entry.method.is_some() {
                    with_request += 1;
                    assert_eq!(
                        request_parts(&entry),
                        request_parts(&expected),
                        "cut at {cut}"
                    );
                }
                entry.redact(LogFormat::PveHttpServer);
                assert!(!serde_json::to_string(&entry).unwrap().contains("SECRET"));
            }
            assert!(with_request > 0);
        }
    }

    #[test]
    fn formats_are_not_interchangeable() {
        let pve = "192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"GET / HTTP/1.1\" 200 5";
        let rest = "192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"GET /\" 200 5 curl/8.14.1";
        assert_eq!(parse_rest(pve), Err(ParseError::Request));
        assert_eq!(parse_pve(rest), Err(ParseError::Request));
    }

    #[test]
    fn invalid_fields() {
        let cases = [
            ("", ParseError::Client),
            (
                "192.0.2.300 - - [22/10/2026:14:03:51 +0200] \"GET /\" 200 5",
                ParseError::Client,
            ),
            (
                "192.0.2.10 x - [22/10/2026:14:03:51 +0200] \"GET /\" 200 5",
                ParseError::Ident,
            ),
            (
                "192.0.2.10 -  [22/10/2026:14:03:51 +0200] \"GET /\" 200 5",
                ParseError::AuthId,
            ),
            (
                "192.0.2.10 - - [22/10/2026:14:03:51] \"GET /\" 200 5",
                ParseError::Time,
            ),
            ("192.0.2.10 - - [-] \"GET /\" 200 5", ParseError::Time),
            (
                "192.0.2.10 - - [22/10/2026:14:03:51 +0200] GET /\" 200 5",
                ParseError::Request,
            ),
            (
                "192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"GET\" 200 5",
                ParseError::Request,
            ),
            (
                "192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"GET / 200 5",
                ParseError::Request,
            ),
            (
                "192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"GET /\" 20 5",
                ParseError::Status,
            ),
            (
                "192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"GET /\" +20 5",
                ParseError::Status,
            ),
            (
                "192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"GET /\" 099 5",
                ParseError::Status,
            ),
            (
                "192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"GET /\" 200",
                ParseError::Size,
            ),
            (
                "192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"GET /\" 200 +5",
                ParseError::Size,
            ),
            (
                "192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"GET /\" 200 5x",
                ParseError::Size,
            ),
        ];
        for (line, error) in cases {
            assert_eq!(parse_rest(line).map(drop), Err(error), "{line:?}");
        }
    }

    #[test]
    fn redaction() {
        let redacted = |request: &str, format: LogFormat| {
            let line = match format {
                LogFormat::PveHttpServer => format!(
                    "192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"{request} HTTP/1.1 x\" 200 5"
                ),
                LogFormat::RestServer => {
                    format!("192.0.2.10 - - [22/10/2026:14:03:51 +0200] \"{request}\" 200 5 -")
                }
            };
            let mut entry = AccessLogEntry::parse(&line, format).unwrap();
            entry.redact(format);
            assert_eq!(entry.request_line, None);
            entry.uri.unwrap()
        };

        for format in [LogFormat::PveHttpServer, LogFormat::RestServer] {
            assert_eq!(redacted("GET /a/b", format), "/a/b");
            assert_eq!(
                redacted(
                    "POST /access/ticket?username=root@pam&password=s=e&cret",
                    format
                ),
                "/access/ticket?username=[REDACTED]&password=[REDACTED]&cret"
            );
            assert_eq!(
                redacted("GET /x?a=1&a=2&&b&c=", format),
                "/x?a=[REDACTED]&a=[REDACTED]&&b&c=[REDACTED]"
            );
            assert_eq!(redacted("GET /x?", format), "/x?");
        }
        assert_eq!(
            redacted(
                "GET http://root:secret@host/api2/json/x?p=1",
                LogFormat::PveHttpServer
            ),
            "http://[REDACTED]@host/api2/json/x?p=[REDACTED]"
        );
        assert_eq!(
            redacted("GET http://host/a@b", LogFormat::PveHttpServer),
            "http://host/a@b"
        );
        assert_eq!(
            redacted("GET /a://b@c/d", LogFormat::PveHttpServer),
            "/a://b@c/d"
        );
        assert_eq!(
            redacted(
                "GET //root:secret@host/api2/json/x?p=1",
                LogFormat::PveHttpServer
            ),
            "//[REDACTED]@host/api2/json/x?p=[REDACTED]"
        );
        assert_eq!(
            redacted("GET ///a@b/c", LogFormat::PveHttpServer),
            "///a@b/c"
        );
        assert_eq!(
            redacted("GET //a://b@c/d", LogFormat::PveHttpServer),
            "//a://b@c/d"
        );
        assert_eq!(
            redacted("GET /x?a=1;b=2", LogFormat::PveHttpServer),
            "/x?a=[REDACTED];b=[REDACTED]"
        );
        assert_eq!(
            redacted("GET /x?a=1;b=2", LogFormat::RestServer),
            "/x?a=[REDACTED]"
        );
    }

    #[test]
    fn ambiguous_entries_serialization() {
        for request in [
            "GET /first?own=SECRET HTTP/1.1 [-] \"GET /next?other=SECRET HTTP/1.1",
            "[-] \"GET /next?other=SECRET HTTP/1.1",
        ] {
            let mut entry = parse_pve(&format!(
                "192.0.2.10 - root@pam [22/10/2026:14:03:51 +0200] \"{request}\" 500 5"
            ))
            .unwrap();
            let raw = serde_json::to_value(&entry).unwrap();
            assert!(raw.get("status").is_none());
            assert!(raw.get("size").is_none());
            assert!(raw["request-line"].as_str().unwrap().contains("SECRET"));
            assert_eq!(
                serde_json::from_value::<AccessLogEntry>(raw.clone()).unwrap(),
                entry
            );
            #[cfg(feature = "api-types")]
            {
                use proxmox_schema::ApiType;
                AccessLogEntry::API_SCHEMA.verify_json(&raw).unwrap();
            }
            entry.redact(LogFormat::PveHttpServer);
            let redacted = serde_json::to_value(&entry).unwrap();
            assert!(redacted.get("request-line").is_none());
            assert!(!redacted.to_string().contains("SECRET"));
            #[cfg(feature = "api-types")]
            {
                use proxmox_schema::ApiType;
                AccessLogEntry::API_SCHEMA.verify_json(&redacted).unwrap();
            }
        }
    }

    #[test]
    fn serialization() {
        let entry = parse_rest(
            "::ffff:192.0.2.10 - root@pam!t [22/10/2026:14:03:51 +0200] \"GET /\" 200 5 curl/8",
        )
        .unwrap();
        let value = serde_json::to_value(&entry).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "time": 1792670631,
                "utc-offset": 7200,
                "client": "192.0.2.10",
                "auth-id": "root@pam!t",
                "method": "GET",
                "uri": "/",
                "status": 200,
                "size": 5,
                "user-agent": "curl/8",
            })
        );
        #[cfg(feature = "api-types")]
        {
            use proxmox_schema::ApiType;
            AccessLogEntry::API_SCHEMA.verify_json(&value).unwrap();
        }
        assert_eq!(
            serde_json::from_value::<AccessLogEntry>(value).unwrap(),
            entry
        );
    }
}
