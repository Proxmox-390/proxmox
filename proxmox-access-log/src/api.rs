use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Error, format_err};
use tokio::sync::Semaphore;

use proxmox_router::{RpcEnvironment, http_bail, http_err};
use proxmox_schema::api;
use proxmox_schema::api_types::NODE_SCHEMA;

use crate::{
    AccessLogFilter, AccessLogStats, CURSOR_SCHEMA, HEAD_CURSOR_SCHEMA, InvalidRequest,
    LIMIT_SCHEMA, LogFormat, MAX_STATS_TOP, QueryResult, StatsOptions,
};

static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// The scans of the log that run at once in a process, for pages and statistics together. A scan
/// can read through hundreds of MiB, and the product's own work needs the disk and the blocking
/// threads too.
const MAX_SCANS: usize = 2;
static SCANS: Semaphore = Semaphore::const_new(MAX_SCANS);

/// Set the access log, written by proxmox-rest-server, that the API methods read.
///
/// The methods come without an access permission, so only the superuser can call them unless the
/// product sets one with [`ApiMethod::access`](proxmox_router::ApiMethod::access).
pub fn init_access_log_api<P: AsRef<Path>>(path: P) -> Result<(), Error> {
    LOG_PATH
        .set(path.as_ref().to_owned())
        .map_err(|_| format_err!("cannot set the access log path twice"))
}

fn log_path() -> Result<&'static Path, Error> {
    match LOG_PATH.get() {
        Some(path) => Ok(path),
        None => http_bail!(INTERNAL_SERVER_ERROR, "the access log path is not set"),
    }
}

#[api(
    input: {
        properties: {
            node: {
                schema: NODE_SCHEMA,
            },
            filter: {
                type: AccessLogFilter,
                flatten: true,
            },
            limit: {
                schema: LIMIT_SCHEMA,
                optional: true,
            },
            cursor: {
                schema: CURSOR_SCHEMA,
                optional: true,
            },
            after: {
                schema: HEAD_CURSOR_SCHEMA,
                optional: true,
            },
        },
    },
    returns: {
        type: QueryResult,
    },
)]
/// Read a page of the API access log, including its rotated copies, newest requests first.
///
/// A page ends once enough requests matched or after reading 512 MiB of log data, also without any
/// match, and the next page continues at its `next-cursor`. To follow the log, `after` takes the
/// `head-cursor` of an earlier page instead of a `cursor`. The values of query parameters are
/// redacted for all but root@pam. Protected calls get logged once, by the privileged API daemon.
pub async fn get_access_log(
    filter: AccessLogFilter,
    limit: Option<u64>,
    cursor: Option<String>,
    after: Option<String>,
    rpcenv: &mut dyn RpcEnvironment,
) -> Result<QueryResult, Error> {
    if after.is_some() && cursor.is_some() {
        http_bail!(
            BAD_REQUEST,
            "parameter 'after' cannot be combined with 'cursor'"
        );
    }

    // Query strings can contain passwords; root@pam can read the unredacted file.
    let redact = rpcenv.get_auth_id().as_deref() != Some("root@pam");

    let path = log_path()?;
    let format = LogFormat::RestServer;
    let mut result = scan(move || match after {
        Some(head) => crate::query_newer(path, format, &filter, limit, &head),
        None => crate::query(path, format, &filter, limit, cursor.as_deref()),
    })
    .await?;

    if redact {
        for entry in &mut result.entries {
            entry.redact(format);
        }
    }

    Ok(result)
}

/// Runs a scan on a blocking thread, as reading the rotated copies means decompressing them, or
/// fails with 503 while too many run already, rather than queueing up.
async fn scan<T, F>(scan: F) -> Result<T, Error>
where
    F: FnOnce() -> Result<T, Error> + Send + 'static,
    T: Send + 'static,
{
    let Ok(permit) = SCANS.try_acquire() else {
        http_bail!(
            SERVICE_UNAVAILABLE,
            "too many requests to the access log at once, try again later"
        );
    };
    tokio::task::spawn_blocking(move || {
        // a client that gives up does not stop the scan, which keeps the permit until it ends
        let _permit = permit;
        scan()
    })
    .await
    .map_err(|err| http_err!(INTERNAL_SERVER_ERROR, "{err}"))?
    .map_err(api_error)
}

fn api_error(err: Error) -> Error {
    if err.is::<InvalidRequest>() {
        http_err!(BAD_REQUEST, "{err}")
    } else {
        http_err!(INTERNAL_SERVER_ERROR, "{err}")
    }
}

#[api(
    input: {
        properties: {
            node: {
                schema: NODE_SCHEMA,
            },
            filter: {
                type: AccessLogFilter,
                flatten: true,
            },
            top: {
                description: "The number of values with the most requests to list, 10 if not \
                    set.",
                type: Integer,
                minimum: 1,
                maximum: MAX_STATS_TOP as i64,
                optional: true,
            },
            bucket: {
                description: "The length of a histogram bucket in seconds, chosen for at most 300 \
                    buckets if not set.",
                type: Integer,
                minimum: 1,
                optional: true,
            },
        },
    },
    returns: {
        type: AccessLogStats,
    },
)]
/// Count the requests of the API access log, including its rotated copies, in a time range.
///
/// The range defaults to the last day. As the log is not ordered by time, the counting reads
/// through the files like a page of the access log does, as much as one page at most, and tells
/// which parts of the files it covered.
pub async fn get_access_log_stats(
    filter: AccessLogFilter,
    top: Option<u64>,
    bucket: Option<u64>,
) -> Result<AccessLogStats, Error> {
    let path = log_path()?;
    scan(move || {
        crate::stats(
            path,
            LogFormat::RestServer,
            &filter,
            StatsOptions { top, bucket },
        )
    })
    .await
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use proxmox_router::HttpError;

    use super::*;

    fn status(err: Error) -> u16 {
        err.downcast_ref::<HttpError>().unwrap().code.as_u16()
    }

    #[test]
    fn scans_beyond_the_limit_are_refused_until_one_ends() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        let all = SCANS.try_acquire_many(MAX_SCANS as u32).unwrap();
        let refused = runtime.block_on(scan(|| -> Result<(), Error> {
            panic!("a refused scan must not run")
        }));
        assert_eq!(status(refused.unwrap_err()), 503);
        drop(all);
        runtime.block_on(scan(|| Ok(()))).unwrap();

        let (started, has_started) = mpsc::channel();
        let (release, released) = mpsc::channel::<()>();
        let task = runtime.spawn(scan(move || {
            started.send(()).unwrap();
            let _ = released.recv();
            Ok(())
        }));
        runtime.block_on(async {
            while has_started.try_recv().is_err() {
                tokio::task::yield_now().await;
            }
        });
        // the client gave up, but the scan still runs
        task.abort();
        let _ = runtime.block_on(task);
        assert_eq!(SCANS.available_permits(), MAX_SCANS - 1);

        drop(release);
        let deadline = Instant::now() + Duration::from_secs(10);
        while SCANS.available_permits() < MAX_SCANS {
            assert!(Instant::now() < deadline, "the ended scan kept its permit");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
