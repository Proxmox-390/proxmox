//! File-based notification queue and accompanying worker task.
//!
//! The queue directory is shared between the worker, running as root, and every process that may
//! submit notifications, including unprivileged ones. It should be owned by root, belong to the
//! group of the unprivileged submitters and have mode `3770`. Submitted files are not writable by
//! the group, and the sticky bit allows only the owner of an entry to remove or rename it, so
//! submitters cannot modify or remove each other's notifications. The setgid bit keeps the files
//! in the directory's group. Parent directories must not be writable by submitters either, as
//! that would allow them to replace the queue directory. The worker warns at startup about a queue
//! directory that deviates from this, and about parent directories writable by others than their
//! owner. A parent directory owned by a submitting user is not flagged, as products may keep the
//! queue in the state directory of their unprivileged daemon, which submits most notifications
//! anyway.

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
