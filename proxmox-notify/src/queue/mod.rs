use std::path::Path;

use crate::Error;

mod submitter;
pub use submitter::QueueSubmitter;

/// Maximum size of a queued notification file.
///
/// Well above what legitimate producers submit, e.g. forwarded mails or backup logs limited to
/// 1 MiB, but bounds the memory a bogus file written directly to the queue can consume.
const MAX_NOTIFICATION_SIZE: u64 = 16 * 1024 * 1024;

fn fsync_queue_dir(queue_dir: &Path) -> Result<(), Error> {
    std::fs::File::open(queue_dir)
        .and_then(|dir| dir.sync_all())
        .map_err(|err| Error::queue_with_source("fsync of queue directory failed", err))
}
