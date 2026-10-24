use serde::{Deserialize, Serialize};

#[cfg(feature = "api-types")]
use proxmox_schema::api;

use crate::Gap;

/// The number of rows of each list a statistics call returns if not set otherwise.
pub const DEFAULT_STATS_TOP: u64 = 10;

/// The most rows of each list a statistics call returns.
pub const MAX_STATS_TOP: u64 = 100;

/// The most buckets of a histogram.
pub const MAX_HISTOGRAM_BUCKETS: u64 = 300;

/// The time range that statistics cover if not set otherwise, in seconds before its end.
pub const DEFAULT_STATS_RANGE: i64 = 24 * 60 * 60;

/// Tuning parameters for statistics, separate from the criteria selecting requests.
#[derive(Clone, Copy, Debug, Default)]
pub struct StatsOptions {
    /// The most rows returned per list, defaulting to [`DEFAULT_STATS_TOP`].
    pub top: Option<u64>,
    /// The histogram bucket length in seconds, chosen automatically when omitted.
    pub bucket: Option<u64>,
}

#[cfg_attr(feature = "api-types", api())]
/// Request counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Counts {
    /// The number of requests.
    pub requests: u64,
    /// The number of requests with a known client-error status, 400 to 499.
    pub client_errors: u64,
    /// The number of requests with a known server-error status, 500 or more.
    pub server_errors: u64,
    /// The number of requests without an authenticated user.
    pub unauthenticated: u64,
}

impl Counts {
    #[cfg_attr(not(feature = "query"), allow(dead_code))]
    fn add(&mut self, other: &Counts) {
        self.requests += other.requests;
        self.client_errors += other.client_errors;
        self.server_errors += other.server_errors;
        self.unauthenticated += other.unauthenticated;
    }
}

#[cfg_attr(feature = "api-types", api())]
/// The requests sharing one value, like a client address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct StatsRow {
    /// The value, missing for requests without one, like those without a user or a known status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The number of requests.
    pub requests: u64,
    /// The number of requests with a known client-error status.
    pub client_errors: u64,
    /// The number of requests with a known server-error status.
    pub server_errors: u64,
    /// The number of requests without an authenticated user.
    pub unauthenticated: u64,
    /// When the newest of the requests got logged, in seconds since the epoch.
    pub last: i64,
}

#[cfg_attr(feature = "api-types", api(
    properties: {
        rows: {
            type: Array,
            items: {
                type: StatsRow,
            },
        },
    },
))]
/// The values with the most requests.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct StatsList {
    /// The values with the most requests, most first.
    pub rows: Vec<StatsRow>,
    /// The requests of all other values.
    pub others: Counts,
    /// The number of values counted separately. Without truncation, these are all of them.
    pub tracked: u64,
    /// Whether there were more values than get counted separately, so further values only count
    /// as others. The rows are then the tracked values with the most requests, which need not be
    /// the ones with the most requests of all.
    pub truncated: bool,
}

#[cfg_attr(feature = "api-types", api(
    properties: {
        counts: {
            type: Array,
            items: {
                type: Counts,
            },
        },
    },
))]
/// The requests over time.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Histogram {
    /// The start of the first bucket, in seconds since the epoch.
    pub start: i64,
    /// The length of a bucket in seconds.
    pub bucket: u64,
    /// The requests of each bucket.
    pub counts: Vec<Counts>,
}

#[cfg_attr(feature = "api-types", api())]
/// A part of a log file that statistics counted all lines of.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CoveredRange {
    /// The name of the file.
    pub file: String,
    /// Where the part starts, as offset in the uncompressed data.
    pub start: u64,
    /// Where the part ends, as offset in the uncompressed data.
    pub end: u64,
}

#[cfg_attr(feature = "api-types", api())]
/// Why statistics did not get through all files.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StopReason {
    /// They read as much as one call may.
    ReadBudget,
    /// They parsed as much as one call may.
    ParseBudget,
    /// A compressed copy is damaged.
    Damaged,
}

#[cfg_attr(feature = "api-types", api(
    properties: {
        covered: {
            type: Array,
            items: {
                type: CoveredRange,
            },
        },
        gaps: {
            type: Array,
            items: {
                type: Gap,
            },
        },
        "user-agents": {
            type: StatsList,
            optional: true,
        },
    },
))]
/// Statistics of the requests of a log that match a filter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AccessLogStats {
    /// The start of the time range, in seconds since the epoch.
    pub since: i64,
    /// The end of the time range, in seconds since the epoch.
    pub until: i64,
    /// Whether all lines of all files got counted. Otherwise, the counts are only those of the
    /// covered parts, and more requests of the time range can be in the rest.
    pub complete: bool,
    /// Why the counting stopped before the oldest file ended.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stopped: Option<StopReason>,
    /// The parts of the files that got counted, newest first.
    pub covered: Vec<CoveredRange>,
    /// The time of the oldest request looked at, matching or not, in seconds since the epoch, as
    /// the first fields of its line tell. Requests are not strictly ordered in the log, so this
    /// does not bound the covered time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub searched_back_to: Option<i64>,
    /// The number of lines that failed to parse, of the ones parsed completely. Lines whose first
    /// fields already rule them out do not get parsed further.
    pub invalid_lines: u64,
    /// The damaged compressed copy the counting stopped at.
    #[serde(default)]
    pub gaps: Vec<Gap>,
    /// The counts of all matching requests.
    pub total: Counts,
    /// The matching requests over the time range. Request counts include unknown outcomes, while
    /// error counts include only known statuses.
    pub histogram: Histogram,
    /// The client addresses with the most requests.
    pub clients: StatsList,
    /// The users and API tokens with the most requests.
    pub auth_ids: StatsList,
    /// The path groups with the most requests. A group joins the paths that differ only in the
    /// objects they name, such as node names or IDs.
    pub path_groups: StatsList,
    /// The status codes with the most requests. Unknown statuses count under a missing key, which
    /// can be included in `others` instead of a returned row, like any value outside the top list.
    pub statuses: StatsList,
    /// The user agents with the most requests, for logs of proxmox-rest-server, which logs them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agents: Option<StatsList>,
}

#[cfg(feature = "query")]
pub(crate) use tally::Tally;

#[cfg(feature = "query")]
mod tally {
    use std::collections::HashMap;

    use super::{Counts, Histogram, StatsList, StatsRow};
    use crate::{AccessLogEntry, LogFormat, path_group};

    /// The most values counted separately per list.
    const MAX_KEYS: usize = 4096;

    /// The longest value counted separately.
    const MAX_KEY_LENGTH: usize = 1024;

    /// The bytes of values counted separately per list, which bounds the memory statistics take.
    const MAX_KEY_BYTES: usize = 2 * 1024 * 1024;

    #[derive(Clone, Default)]
    struct Row {
        counts: Counts,
        last: i64,
    }

    impl Row {
        fn add(&mut self, counts: &Counts, time: i64) {
            self.counts.add(counts);
            self.last = self.last.max(time);
        }
    }

    /// The counts of one list, by value.
    #[derive(Clone, Default)]
    struct List {
        rows: HashMap<String, Row>,
        missing: Option<Row>,
        others: Counts,
        key_bytes: usize,
        truncated: bool,
    }

    impl List {
        fn add(&mut self, key: Option<&str>, counts: &Counts, time: i64) {
            let Some(key) = key else {
                self.missing
                    .get_or_insert_with(|| Row {
                        last: time,
                        ..Default::default()
                    })
                    .add(counts, time);
                return;
            };
            if let Some(row) = self.rows.get_mut(key) {
                row.add(counts, time);
            } else if self.rows.len() < MAX_KEYS
                && key.len() <= MAX_KEY_LENGTH
                && self.key_bytes + key.len() <= MAX_KEY_BYTES
            {
                self.key_bytes += key.len();
                let mut row = Row {
                    last: time,
                    ..Default::default()
                };
                row.add(counts, time);
                self.rows.insert(key.to_string(), row);
            } else {
                self.others.add(counts);
                self.truncated = true;
            }
        }

        fn finish(self, top: usize) -> StatsList {
            let tracked = (self.rows.len() + usize::from(self.missing.is_some())) as u64;
            let mut rows: Vec<(Option<String>, Row)> = self
                .rows
                .into_iter()
                .map(|(key, row)| (Some(key), row))
                .chain(self.missing.map(|row| (None, row)))
                .collect();
            rows.sort_by(|(a_key, a), (b_key, b)| {
                b.counts
                    .requests
                    .cmp(&a.counts.requests)
                    .then_with(|| a_key.cmp(b_key))
            });
            let mut others = self.others;
            for (_, row) in rows.iter().skip(top) {
                others.add(&row.counts);
            }
            rows.truncate(top);
            StatsList {
                rows: rows
                    .into_iter()
                    .map(|(key, row)| StatsRow {
                        key,
                        requests: row.counts.requests,
                        client_errors: row.counts.client_errors,
                        server_errors: row.counts.server_errors,
                        unauthenticated: row.counts.unauthenticated,
                        last: row.last,
                    })
                    .collect(),
                others,
                tracked,
                truncated: self.truncated,
            }
        }
    }

    /// Counts the requests that match, for statistics.
    #[derive(Clone)]
    pub(crate) struct Tally {
        format: LogFormat,
        since: i64,
        bucket: i64,
        buckets: Vec<Counts>,
        total: Counts,
        clients: List,
        auth_ids: List,
        path_groups: List,
        statuses: List,
        user_agents: Option<List>,
    }

    pub(crate) struct Finished {
        pub(crate) total: Counts,
        pub(crate) histogram: Histogram,
        pub(crate) clients: StatsList,
        pub(crate) auth_ids: StatsList,
        pub(crate) path_groups: StatsList,
        pub(crate) statuses: StatsList,
        pub(crate) user_agents: Option<StatsList>,
    }

    impl Tally {
        /// A tally for requests of the range from `since` to `until`, which needs to hold at most
        /// [`super::MAX_HISTOGRAM_BUCKETS`] of `bucket`.
        pub(crate) fn new(since: i64, until: i64, bucket: u64, format: LogFormat) -> Self {
            let bucket = bucket as i64;
            let count = until.div_euclid(bucket) - since.div_euclid(bucket) + 1;
            Self {
                format,
                since,
                bucket,
                buckets: vec![Counts::default(); count as usize],
                total: Counts::default(),
                clients: List::default(),
                auth_ids: List::default(),
                path_groups: List::default(),
                statuses: List::default(),
                user_agents: (format == LogFormat::RestServer).then(List::default),
            }
        }

        /// Counts a matching entry, which is within the time range.
        pub(crate) fn add(&mut self, entry: &AccessLogEntry) {
            let counts = Counts {
                requests: 1,
                client_errors: u64::from(entry.status.is_some_and(|s| (400..500).contains(&s))),
                server_errors: u64::from(entry.status.is_some_and(|s| s >= 500)),
                unauthenticated: u64::from(entry.auth_id.is_none()),
            };
            self.total.add(&counts);
            let bucket = entry.time.div_euclid(self.bucket) - self.since.div_euclid(self.bucket);
            if let Some(bucket) = usize::try_from(bucket)
                .ok()
                .and_then(|bucket| self.buckets.get_mut(bucket))
            {
                bucket.add(&counts);
            }

            let time = entry.time;
            let client = entry.client.map(|client| client.to_string());
            self.clients.add(client.as_deref(), &counts, time);
            self.auth_ids.add(entry.auth_id.as_deref(), &counts, time);
            let group = entry.path().map(|path| path_group(path, self.format));
            self.path_groups.add(group.as_deref(), &counts, time);
            let status = entry.status.map(|status| status.to_string());
            self.statuses.add(status.as_deref(), &counts, time);
            if let Some(user_agents) = &mut self.user_agents {
                user_agents.add(entry.user_agent.as_deref(), &counts, time);
            }
        }

        pub(crate) fn finish(self, top: usize) -> Finished {
            Finished {
                total: self.total,
                histogram: Histogram {
                    start: self.since.div_euclid(self.bucket) * self.bucket,
                    bucket: self.bucket as u64,
                    counts: self.buckets,
                },
                clients: self.clients.finish(top),
                auth_ids: self.auth_ids.finish(top),
                path_groups: self.path_groups.finish(top),
                statuses: self.statuses.finish(top),
                user_agents: self.user_agents.map(|list| list.finish(top)),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::LogFormat;

        #[test]
        fn lists_keep_exact_counts_of_tracked_values() {
            let mut list = List::default();
            let one = Counts {
                requests: 1,
                ..Default::default()
            };
            for key in 0..MAX_KEYS + 10 {
                list.add(Some(&key.to_string()), &one, 1);
            }
            list.add(Some("0"), &one, 5);
            list.add(Some(&(MAX_KEYS + 1).to_string()), &one, 5);
            list.add(None, &one, 3);
            let list = list.finish(2);
            assert!(list.truncated);
            assert_eq!(list.tracked as usize, MAX_KEYS + 1);
            assert_eq!(list.rows[0].key.as_deref(), Some("0"));
            assert_eq!((list.rows[0].requests, list.rows[0].last), (2, 5));
            let counted: u64 = list.rows.iter().map(|row| row.requests).sum();
            assert_eq!(counted + list.others.requests, MAX_KEYS as u64 + 13);
        }

        #[test]
        fn histogram_buckets() {
            let entry = |time: &str, status: u16| {
                AccessLogEntry::parse(
                    &format!("192.0.2.1 - - [{time} +0000] \"GET / HTTP/1.1\" {status} 0"),
                    LogFormat::PveHttpServer,
                )
                .unwrap()
            };
            let first = entry("22/10/2026:10:00:30", 200);
            let mut tally =
                Tally::new(first.time - 30, first.time + 150, 60, LogFormat::RestServer);
            tally.add(&first);
            tally.add(&entry("22/10/2026:10:02:59", 404));
            tally.add(&entry("22/10/2026:10:03:00", 503));
            let finished = tally.finish(10);
            let histogram = finished.histogram;
            assert_eq!(histogram.start, first.time - 30);
            let requests: Vec<u64> = histogram.counts.iter().map(|c| c.requests).collect();
            assert_eq!(requests, [1, 0, 1, 1]);
            assert_eq!(histogram.counts[2].client_errors, 1);
            assert_eq!(histogram.counts[3].server_errors, 1);
            assert_eq!(finished.total.unauthenticated, 3);
        }

        #[test]
        fn unknown_status() {
            let entry = AccessLogEntry::parse(
                "192.0.2.1 - - [22/10/2026:10:00:30 +0000] \
                 \"GET / HTTP/1.1 192.0.2.2 - - [22/10/2026:10:00:31 +0000] \"GET /x HTTP/1.1\" 500 0",
                LogFormat::PveHttpServer,
            )
            .unwrap();
            let mut tally = Tally::new(entry.time, entry.time, 60, LogFormat::PveHttpServer);
            tally.add(&entry);
            let finished = tally.finish(10);
            assert_eq!(
                (finished.total.requests, finished.total.server_errors),
                (1, 0)
            );
            assert_eq!(finished.statuses.rows[0].key, None);
            assert_eq!(finished.path_groups.rows[0].key.as_deref(), Some("/"));
            assert_eq!(finished.histogram.counts[0], finished.total);
            assert_eq!(finished.total.client_errors, 0);
        }

        #[test]
        fn mixed_statuses_and_others() {
            let mut entries = Vec::new();
            for (time, status) in [
                ("00:30", 200),
                ("00:31", 200),
                ("00:32", 200),
                ("01:00", 404),
                ("02:00", 503),
            ] {
                entries.push(
                    AccessLogEntry::parse(
                        &format!(
                            "192.0.2.1 - alice@pve [22/10/2026:10:{time} +0000] \
                         \"GET / HTTP/1.1\" {status} 5"
                        ),
                        LogFormat::PveHttpServer,
                    )
                    .unwrap(),
                );
            }
            entries.push(
                AccessLogEntry::parse(
                    "192.0.2.1 - alice@pve [22/10/2026:10:03:00 +0000] \
                 \"GET / HTTP/1.1 [-] \"POST /other HTTP/1.1\" 500 0",
                    LogFormat::PveHttpServer,
                )
                .unwrap(),
            );
            let mut tally = Tally::new(
                entries[0].time - 30,
                entries[5].time,
                60,
                LogFormat::PveHttpServer,
            );
            for entry in &entries {
                tally.add(entry);
            }
            let limited = tally.clone().finish(1);
            let full = tally.finish(10);
            assert_eq!(
                full.total,
                Counts {
                    requests: 6,
                    client_errors: 1,
                    server_errors: 1,
                    unauthenticated: 0,
                }
            );
            assert_eq!(full.clients.rows[0].requests, 6);
            assert_eq!(full.auth_ids.rows[0].requests, 6);
            assert_eq!(full.path_groups.rows[0].requests, 6);
            assert_eq!(full.auth_ids.rows[0].key.as_deref(), Some("alice@pve"));
            let mut sum = Counts::default();
            for counts in &full.histogram.counts {
                sum.add(counts);
            }
            assert_eq!(sum, full.total);
            assert_eq!(
                full.histogram.counts[3],
                Counts {
                    requests: 1,
                    ..Default::default()
                }
            );
            let unknown = full
                .statuses
                .rows
                .iter()
                .find(|row| row.key.is_none())
                .unwrap();
            assert_eq!(unknown.requests, 1);
            assert_eq!((unknown.client_errors, unknown.server_errors), (0, 0));
            assert!(serde_json::to_value(unknown).unwrap().get("key").is_none());
            assert_eq!(limited.statuses.rows[0].key.as_deref(), Some("200"));
            assert_eq!(limited.statuses.rows[0].requests, 3);
            assert_eq!(
                limited.statuses.others,
                Counts {
                    requests: 3,
                    client_errors: 1,
                    server_errors: 1,
                    unauthenticated: 0,
                }
            );
            assert_eq!(limited.total, full.total);
        }

        #[test]
        fn user_agent_with_record_start() {
            let entry = AccessLogEntry::parse(
                "192.0.2.1 - - [22/10/2026:10:00:30 +0000] \
                 \"GET /\" 200 5 curl192.0.2.2 - - [-] \"POST /x?p=SECRET\" 401 0 -",
                LogFormat::RestServer,
            )
            .unwrap();
            let mut tally = Tally::new(entry.time, entry.time, 60, LogFormat::RestServer);
            tally.add(&entry);
            let finished = tally.finish(10);
            assert_eq!(finished.total.requests, 1);
            assert_eq!(finished.total.client_errors, 0);
            let agents = finished.user_agents.unwrap();
            assert_eq!(agents.rows[0].key, None);
            assert!(!serde_json::to_string(&agents).unwrap().contains("SECRET"));
        }
    }
}
