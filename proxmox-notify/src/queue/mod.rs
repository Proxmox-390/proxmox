//! File-based notification queue and accompanying worker task.

#[cfg(any(feature = "queue-submitter", feature = "queue-worker"))]
use std::path::Path;

#[cfg(any(feature = "queue-submitter", feature = "queue-worker"))]
use crate::Error;

#[cfg(feature = "queue-submitter")]
mod submitter;
#[cfg(feature = "queue-submitter")]
pub use submitter::QueueSubmitter;

#[cfg(feature = "queue-worker")]
mod consumer;
#[cfg(feature = "queue-worker")]
pub use consumer::QueueConsumer;

#[cfg(feature = "queue-worker")]
mod worker;
#[cfg(feature = "queue-worker")]
pub use worker::{QueueWorker, QueueWorkerBuilder};

/// Maximum size of a queued notification file.
///
/// Well above what legitimate producers submit, e.g. forwarded mails or backup logs limited to
/// 1 MiB, but bounds the memory a bogus file written directly to the queue can consume.
const MAX_NOTIFICATION_SIZE: u64 = 16 * 1024 * 1024;

#[cfg(any(feature = "queue-submitter", feature = "queue-worker"))]
fn fsync_queue_dir(queue_dir: &Path) -> Result<(), Error> {
    std::fs::File::open(queue_dir)
        .and_then(|dir| dir.sync_all())
        .map_err(|err| Error::queue_with_source("fsync of queue directory failed", err))
}
