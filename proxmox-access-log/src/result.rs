use serde::{Deserialize, Serialize};

#[cfg(feature = "api-types")]
use proxmox_schema::{IntegerSchema, Schema, StringSchema, api};

use crate::AccessLogEntry;

/// The longest cursor a query returns or accepts.
pub const MAX_CURSOR_LENGTH: usize = 128;

/// The number of entries a page holds at most if the query sets no limit.
pub const DEFAULT_LIMIT: u64 = 500;

/// The highest limit a query can set, which bounds the size of a response.
pub const MAX_LIMIT: u64 = 1000;

#[cfg(feature = "api-types")]
/// The schema of the limit of a query.
pub const LIMIT_SCHEMA: Schema = IntegerSchema::new("The maximum number of entries to return.")
    .minimum(1)
    .maximum(MAX_LIMIT as i64)
    .default(DEFAULT_LIMIT as i64)
    .schema();

#[cfg(feature = "api-types")]
/// The schema of a next cursor returned by a query, to continue with older entries.
pub const CURSOR_SCHEMA: Schema = StringSchema::new(
    "Continue with the entries logged before this position, the next cursor of the previous page.",
)
.min_length(1)
.max_length(MAX_CURSOR_LENGTH)
.schema();

#[cfg(feature = "api-types")]
/// The schema of a head cursor returned by a query, to get the entries logged after it.
pub const HEAD_CURSOR_SCHEMA: Schema = StringSchema::new(
    "Only the entries logged after this position, the head cursor of an earlier page.",
)
.min_length(1)
.max_length(MAX_CURSOR_LENGTH)
.schema();

#[cfg_attr(feature = "api-types", api())]
/// Why a query skipped a part of a log file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GapReason {
    /// Reaching the part needs decompressing more of a compressed copy than one query reads.
    TooLarge,
    /// The compressed copy is damaged.
    Damaged,
}

#[cfg_attr(feature = "api-types", api())]
/// A part of a log file a query skipped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Gap {
    /// The name of the file.
    pub file: String,

    /// Why the part was skipped.
    pub reason: GapReason,

    /// Where the skipped part starts, as offset in the uncompressed data.
    pub start: u64,

    /// Where the skipped part ends, missing if at the end of a compressed copy of unknown size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<u64>,
}

#[cfg_attr(feature = "api-types", api(
    properties: {
        entries: {
            type: Array,
            items: {
                type: AccessLogEntry,
            },
        },
        "next-cursor": {
            optional: true,
        },
        "head-cursor": {
            optional: true,
        },
        gaps: {
            type: Array,
            items: {
                type: Gap,
            },
        },
    },
))]
/// One page of the entries of a log that match a filter.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct QueryResult {
    /// The matching entries, in reverse order of logging: from the end of the log on, then the
    /// rotated copies from the newest on. Timestamps do not need to decrease strictly, as servers
    /// write entries late at times and rotated copies can overlap.
    pub entries: Vec<AccessLogEntry>,

    /// Where the next page continues, missing if no older entries are left to look at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,

    /// Where the log ended when this page started reading it, to get the entries logged since.
    /// Missing on pages continuing at a cursor, or if the log has no complete line yet or ends in
    /// an unfinished overlong one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_cursor: Option<String>,

    /// The parts of the log this page skipped, as they could not be read.
    #[serde(default)]
    pub gaps: Vec<Gap>,

    /// Whether this page and the ones before it covered the whole log, without any gap. For entries
    /// logged after a head cursor, whether this page holds all of them.
    pub complete: bool,

    /// The time of the oldest entry this page looked at, matching or not. As entries are not
    /// strictly ordered, older entries can still follow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub searched_back_to: Option<i64>,

    /// The number of lines this page looked at that failed to parse.
    pub invalid_lines: u64,
}
