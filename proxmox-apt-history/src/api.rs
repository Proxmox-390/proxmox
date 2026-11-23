//! API methods for listing the history of the system and getting the terminal output of its
//! transactions and the changelog entries for their package changes, for mounting them in the APT
//! API of a node.
//!
//! The products set the permissions with [`ApiMethod::access`](proxmox_router::ApiMethod::access),
//! until then only the superuser has access.

use anyhow::Error;
use tokio::sync::Semaphore;

use proxmox_http_error::{http_bail, http_err};
use proxmox_schema::api;
use proxmox_schema::api_types::NODE_SCHEMA;

use crate::{HistoryEntry, HistoryListOptions, TermLogFormat, TransactionChangelog};

/// How many requests read the logs at once. One can hold the terminal output of a transaction
/// twice, raw and cleaned, which is limited to 64 MiB each.
const MAX_READS: usize = 4;
static READS: Semaphore = Semaphore::const_new(MAX_READS);

#[api(
    // hardened systems can restrict access to the rotated APT logs or their directory
    protected: true,
    input: {
        properties: {
            node: {
                schema: NODE_SCHEMA,
            },
            options: {
                type: HistoryListOptions,
                flatten: true,
            },
        },
    },
    returns: {
        description: "Past APT transactions, newest first.",
        type: Array,
        items: {
            type: HistoryEntry,
        },
    },
)]
/// List past APT transactions and their package changes, newest first.
pub async fn list_history(options: HistoryListOptions) -> Result<Vec<HistoryEntry>, Error> {
    blocking(move || crate::list_history(&options).map_err(read_error)).await
}

#[api(
    // the APT terminal log is only readable for root and the adm group
    protected: true,
    input: {
        properties: {
            node: {
                schema: NODE_SCHEMA,
            },
            "start-time": {
                description: "Start time of the transaction, as listed in the APT history.",
            },
            "start-index": {
                description: "Start index of the transaction, as listed in the APT history.",
                optional: true,
                default: 0,
            },
            format: {
                type: TermLogFormat,
                optional: true,
            },
        },
    },
    returns: {
        description: "The terminal output.",
        type: String,
    },
)]
/// Get the terminal output of a past APT transaction.
pub async fn get_term_log(
    start_time: i64,
    start_index: Option<u32>,
    format: Option<TermLogFormat>,
) -> Result<String, Error> {
    let start_index = start_index.unwrap_or_default();
    let format = format.unwrap_or_default();
    blocking(move || {
        crate::get_term_log(start_time, start_index, format)
            .map_err(read_error)?
            .ok_or_else(|| {
                http_err!(
                    NOT_FOUND,
                    "no terminal output found for the APT transaction started at {start_time} with \
                index {start_index}"
                )
            })
    })
    .await
}

/// Runs reading the logs on a thread for blocking tasks, as it can take a while for big logs,
/// which must not block the async runtime, or fails with 503 while too many run already, rather
/// than queueing up.
async fn blocking<T: Send + 'static>(
    read: impl FnOnce() -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    limited(&READS, read).await
}

async fn limited<T: Send + 'static>(
    permits: &'static Semaphore,
    read: impl FnOnce() -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    let Ok(permit) = permits.try_acquire() else {
        http_bail!(
            SERVICE_UNAVAILABLE,
            "too many requests to the APT history at once, try again later"
        );
    };
    tokio::task::spawn_blocking(move || {
        // a client that gives up does not stop the reading, which keeps the permit until it ends
        let _permit = permit;
        read()
    })
    .await
    .map_err(|err| http_err!(INTERNAL_SERVER_ERROR, "reading the APT logs failed - {err}"))?
}

/// Failing to read the logs is an error of the server, not of the request.
fn read_error(err: crate::Error) -> Error {
    http_err!(INTERNAL_SERVER_ERROR, "{err}")
}

#[api(
    // hardened systems can restrict access to the rotated APT logs or their directory
    protected: true,
    input: {
        properties: {
            node: {
                schema: NODE_SCHEMA,
            },
            "start-time": {
                description: "Start time of the transaction, as listed in the APT history.",
            },
            "start-index": {
                description: "Start index of the transaction, as listed in the APT history.",
                optional: true,
                default: 0,
            },
        },
    },
    returns: {
        description: "The changelog entries, grouped by source package, upgrades first, then \
            downgrades, installs and other changes, each sorted by name.",
        type: Array,
        items: {
            type: TransactionChangelog,
        },
    },
)]
/// Get the changelog entries for the package changes of a past APT transaction, from the changelogs
/// of the installed packages.
pub async fn get_transaction_changelogs(
    start_time: i64,
    start_index: Option<u32>,
) -> Result<Vec<TransactionChangelog>, Error> {
    let start_index = start_index.unwrap_or_default();
    blocking(move || {
        crate::get_transaction_changelogs(start_time, start_index)
            .map_err(read_error)?
            .ok_or_else(|| {
                http_err!(
                    NOT_FOUND,
                    "no APT transaction found that started at {start_time} with index {start_index}"
                )
            })
    })
    .await
}

#[cfg(test)]
mod tests {
    use proxmox_router::{ApiMethod, Permission};

    use super::*;

    #[test]
    fn superuser_only_by_default() {
        for method in [
            &API_METHOD_LIST_HISTORY,
            &API_METHOD_GET_TERM_LOG,
            &API_METHOD_GET_TRANSACTION_CHANGELOGS,
        ] {
            assert!(matches!(method.access.permission, Permission::Superuser));
            assert!(method.protected);
        }
    }

    #[test]
    fn reads_beyond_the_limit_are_refused() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        // a semaphore of its own, as taking those of all requests could fail other tests
        static PERMITS: Semaphore = Semaphore::const_new(MAX_READS);
        let all = PERMITS.try_acquire_many(MAX_READS as u32).unwrap();
        let refused = runtime.block_on(limited(&PERMITS, || -> Result<(), Error> {
            panic!("a refused read must not run")
        }));
        let err = refused.unwrap_err();
        let err = err.downcast_ref::<proxmox_http_error::HttpError>().unwrap();
        assert_eq!(
            err.code,
            proxmox_http_error::StatusCode::SERVICE_UNAVAILABLE
        );
        drop(all);
        runtime.block_on(limited(&PERMITS, || Ok(()))).unwrap();
    }

    #[test]
    fn unreadable_logs_are_server_errors() {
        let err = read_error(crate::Error::Io(
            std::io::ErrorKind::PermissionDenied.into(),
        ));
        let err = err.downcast_ref::<proxmox_http_error::HttpError>().unwrap();
        assert_eq!(
            err.code,
            proxmox_http_error::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    fn parse_query(method: &'static ApiMethod, query: &[(&str, &str)]) -> Result<(), String> {
        let query: Vec<_> = query
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        match method.parameters.parse_parameter_strings(&query, true) {
            Ok(_) => Ok(()),
            Err(err) => Err(err.to_string()),
        }
    }

    #[test]
    fn query_parameters() {
        let node = ("node", "localhost");
        parse_query(&API_METHOD_LIST_HISTORY, &[node]).expect("listing everything");
        parse_query(
            &API_METHOD_LIST_HISTORY,
            &[
                node,
                ("since", "1"),
                ("until", "2"),
                ("package", "a"),
                ("limit", "3"),
            ],
        )
        .expect("listing with all options");
        parse_query(&API_METHOD_LIST_HISTORY, &[node, ("limit", "0")]).expect_err("zero limit");

        let start = ("start-time", "1792617759");
        parse_query(&API_METHOD_GET_TERM_LOG, &[node, start]).expect("only the start time");
        parse_query(
            &API_METHOD_GET_TERM_LOG,
            &[node, start, ("start-index", "1"), ("format", "styled")],
        )
        .expect("all parameters");
        parse_query(&API_METHOD_GET_TERM_LOG, &[node]).expect_err("missing start time");
        parse_query(&API_METHOD_GET_TERM_LOG, &[node, start, ("format", "html")])
            .expect_err("unknown format");
        parse_query(
            &API_METHOD_GET_TERM_LOG,
            &[node, start, ("start-index", "-1")],
        )
        .expect_err("negative start index");

        parse_query(&API_METHOD_GET_TRANSACTION_CHANGELOGS, &[node, start])
            .expect("only the start time");
        parse_query(
            &API_METHOD_GET_TRANSACTION_CHANGELOGS,
            &[node, start, ("start-index", "2")],
        )
        .expect("all parameters");
        parse_query(&API_METHOD_GET_TRANSACTION_CHANGELOGS, &[node])
            .expect_err("missing start time");
    }
}
