//! Submission of notifications to the queue.

use std::path::PathBuf;

use nix::sys::stat::Mode;
use proxmox_sys::fs::CreateOptions;

use crate::{Error, Notification};

use super::MAX_NOTIFICATION_SIZE;

/// Writes notifications to the queue directory.
///
/// Queued files are owned by the submitting process and readable, but not writable, by the group.
/// See the [module documentation](super) for the setup of the queue directory.
pub struct QueueSubmitter {
    queue_dir: PathBuf,
}

impl QueueSubmitter {
    /// Create a new submitter for the queue directory `base_dir`.
    pub fn new<P: Into<PathBuf>>(base_dir: P) -> Self {
        Self {
            queue_dir: base_dir.into(),
        }
    }

    /// Add a notification to the queue.
    ///
    /// The file is written atomically and the queue directory is synced before returning.
    pub fn submit(&self, notification: &Notification) -> Result<(), Error> {
        let filename = format!("notification-{}", notification.id());
        let path = self.queue_dir.join(filename);

        let bytes = serde_json::to_vec(notification).map_err(|err| {
            Error::other_with_source(
                format!("failed to serialize notification {}", notification.id()),
                err,
            )
        })?;

        let serialized_size = bytes.len();
        if serialized_size as u64 > MAX_NOTIFICATION_SIZE {
            return Err(Error::invalid_notification(format!(
                "serialized notification too large ({serialized_size} > {MAX_NOTIFICATION_SIZE} bytes)"
            )));
        }

        let create_options = CreateOptions::new().perm(Mode::from_bits_truncate(0o640));

        proxmox_sys::fs::replace_file(&path, &bytes, create_options, true).map_err(|err| {
            Error::queue_with_source(
                format!(
                    "failed to store serialized notification {}",
                    notification.id()
                ),
                err,
            )
        })?;

        super::fsync_queue_dir(&self.queue_dir)?;

        tracing::info!(
            "submitted notification {} to notification queue",
            notification.id()
        );

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use proxmox_uuid::Uuid;
    use serde_json::json;
    use tempfile::tempdir;

    use crate::notification::Content;

    use super::*;

    /// Build a notification that serializes to exactly `size` bytes.
    fn notification_with_size(size: u64) -> Notification {
        let mut notification = Notification::template_builder("foo", json!({ "pad": "" }))
            .build()
            .unwrap();

        let base_size = serde_json::to_vec(&notification).unwrap().len() as u64;
        let Content::Template { data, .. } = &mut notification.content else {
            unreachable!();
        };
        data["pad"] = "a".repeat((size - base_size) as usize).into();

        assert_eq!(
            serde_json::to_vec(&notification).unwrap().len() as u64,
            size
        );

        notification
    }

    #[test]
    fn test_submit_multiple() {
        let base_dir = tempdir().unwrap();
        let submitter = QueueSubmitter::new(base_dir.path());

        let notifications: Vec<_> = (0..3)
            .map(|_| Notification::template_builder("foo", ()).build().unwrap())
            .collect();

        for notification in &notifications {
            submitter.submit(notification).unwrap();
        }

        let entries: Vec<_> = std::fs::read_dir(base_dir.path())
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect();
        assert_eq!(entries.len(), notifications.len());

        for entry in entries {
            let filename = entry.file_name().into_string().unwrap();
            let id: Uuid = filename
                .strip_prefix("notification-")
                .unwrap()
                .parse()
                .unwrap();

            let submitted = notifications.iter().find(|n| n.id() == &id).unwrap();

            let content = std::fs::read(entry.path()).unwrap();
            let queued: Notification = serde_json::from_slice(&content).unwrap();
            assert_eq!(&queued, submitted);
        }
    }

    #[test]
    fn test_submit_file_mode() {
        use std::os::unix::fs::PermissionsExt;

        let base_dir = tempdir().unwrap();
        let submitter = QueueSubmitter::new(base_dir.path());

        let notification = Notification::template_builder("foo", ()).build().unwrap();
        submitter.submit(&notification).unwrap();

        let path = base_dir
            .path()
            .join(format!("notification-{}", notification.id()));
        let mode = std::fs::metadata(path).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o640);
    }

    #[test]
    fn test_submit_missing_queue_dir() {
        let base_dir = tempdir().unwrap();
        let submitter = QueueSubmitter::new(base_dir.path().join("missing"));

        let notification = Notification::template_builder("foo", ()).build().unwrap();
        assert!(submitter.submit(&notification).is_err());
    }

    #[test]
    fn test_submit_max_size() {
        let base_dir = tempdir().unwrap();
        let submitter = QueueSubmitter::new(base_dir.path());

        let notification = notification_with_size(MAX_NOTIFICATION_SIZE);
        submitter.submit(&notification).unwrap();

        let path = base_dir
            .path()
            .join(format!("notification-{}", notification.id()));
        assert_eq!(
            std::fs::metadata(path).unwrap().len(),
            MAX_NOTIFICATION_SIZE
        );
    }

    #[test]
    fn test_submit_oversized() {
        let base_dir = tempdir().unwrap();
        let submitter = QueueSubmitter::new(base_dir.path());

        let notification = notification_with_size(MAX_NOTIFICATION_SIZE + 1);
        assert!(submitter.submit(&notification).is_err());

        assert_eq!(std::fs::read_dir(base_dir.path()).unwrap().count(), 0);
    }
}
