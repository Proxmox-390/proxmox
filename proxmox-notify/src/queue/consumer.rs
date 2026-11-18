//! Consumer side of the notification queue.

use std::fs::{File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{Error, Notification};

use super::MAX_NOTIFICATION_SIZE;

use proxmox_uuid::Uuid;

/// Reads and manages queued notifications in the queue directory.
///
/// All state changes are done by renaming or removing the notification files, followed by an fsync
/// of the queue directory.
pub struct QueueConsumer {
    queue_dir: PathBuf,
}

impl QueueConsumer {
    /// Create a new consumer for the queue directory `base_dir`.
    pub fn new<P: Into<PathBuf>>(base_dir: P) -> Self {
        Self {
            queue_dir: base_dir.into(),
        }
    }

    /// Describe how the queue directory deviates from the expected setup.
    ///
    /// See the [module documentation](super) for the expected setup.
    pub(crate) fn setup_problems(&self) -> Result<Vec<String>, Error> {
        let euid = nix::unistd::geteuid().as_raw();

        let metadata = std::fs::metadata(&self.queue_dir)
            .map_err(|err| Error::queue_with_source("could not stat queue directory", err))?;
        let mut problems = queue_dir_problems(&self.queue_dir, &metadata, euid);

        for parent in self.queue_dir.ancestors().skip(1) {
            if let Ok(metadata) = std::fs::metadata(parent) {
                problems.extend(parent_dir_problem(parent, &metadata));
            }
        }

        Ok(problems)
    }

    /// Try to acquire an exclusive lock on the queue directory without blocking.
    ///
    /// The lock is held until the returned guard is dropped. Returns `None` if the lock is
    /// currently held by someone else.
    pub fn try_lock(&self) -> Result<Option<QueueLockGuard>, Error> {
        let mut dir = File::open(&self.queue_dir).map_err(|err| {
            Error::queue_with_source("could not open queue directory for locking", err)
        })?;

        match proxmox_sys::fs::lock_file(&mut dir, true, Some(Duration::ZERO)) {
            Ok(()) => Ok(Some(QueueLockGuard { _dir: dir })),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(err) => Err(Error::queue_with_source(
                "could not lock queue directory",
                err,
            )),
        }
    }

    /// Claim a notification for sending by incrementing its attempt counter.
    ///
    /// Returns the updated handle, which must be used for further operations.
    pub fn claim(&self, queued: QueuedNotification) -> Result<QueuedNotification, Error> {
        let claimed = queued.with_attempt(queued.attempt() + 1);

        let old_path = self.queue_dir.join(queued.filename());
        let new_path = self.queue_dir.join(claimed.filename());

        std::fs::rename(old_path, new_path).map_err(|err| {
            Error::queue_with_source("could not rename notification file when claiming it", err)
        })?;

        super::fsync_queue_dir(&self.queue_dir)?;

        Ok(claimed)
    }

    /// Put a claimed notification back into the queue by decrementing its attempt counter.
    ///
    /// Used when sending failed without notifying any target, so that the attempt does not count
    /// towards the retry limit. Returns the updated handle.
    pub fn requeue(&self, queued: QueuedNotification) -> Result<QueuedNotification, Error> {
        let requeued = queued.with_attempt(queued.attempt().saturating_sub(1));

        let old_path = self.queue_dir.join(queued.filename());
        let new_path = self.queue_dir.join(requeued.filename());

        std::fs::rename(old_path, new_path).map_err(|err| {
            Error::queue_with_source("could not rename notification file when requeuing it", err)
        })?;

        super::fsync_queue_dir(&self.queue_dir)?;

        Ok(requeued)
    }

    /// Remove a notification from the queue.
    pub fn resolve(&self, queued: QueuedNotification) -> Result<(), Error> {
        let path = self.queue_dir.join(queued.filename());

        std::fs::remove_file(path)
            .map_err(|err| Error::queue_with_source("could not remove notification file", err))?;

        super::fsync_queue_dir(&self.queue_dir)?;

        Ok(())
    }

    /// Mark a notification as broken by appending `.broken` to its file name.
    ///
    /// Broken notifications are ignored by [`QueueConsumer::queued_notifications`], but kept for
    /// later inspection.
    pub fn mark_broken(&self, queued: QueuedNotification) -> Result<(), Error> {
        let old_name = queued.filename();
        let old_path = self.queue_dir.join(old_name);
        let new_name = format!("{old_name}.broken");
        let new_path = self.queue_dir.join(new_name);

        std::fs::rename(old_path, new_path).map_err(|err| {
            Error::queue_with_source(
                "could not rename notification file when marking it as broken",
                err,
            )
        })?;

        super::fsync_queue_dir(&self.queue_dir)?;

        Ok(())
    }

    /// Return all queued notifications, oldest submission first.
    ///
    /// Files that are not valid queued notifications are skipped.
    pub fn queued_notifications(&self) -> Result<Vec<QueuedNotification>, Error> {
        let read_dir = std::fs::read_dir(&self.queue_dir).map_err(|err| {
            Error::queue_with_source("could not read notification queue directory", err)
        })?;

        let mut queued = Vec::new();

        for entry in read_dir.flatten() {
            let filename = entry.file_name();
            let name = filename.to_string_lossy();

            let Some(notification) = QueuedNotification::parse(&name) else {
                continue;
            };

            // Renaming a file does not touch its mtime, so it reflects when the notification was
            // submitted, regardless of how often it has been claimed or requeued since. Entries
            // whose metadata cannot be read have most likely been removed concurrently.
            if let Ok(mtime) = entry.metadata().and_then(|metadata| metadata.modified()) {
                queued.push((mtime, notification));
            }
        }

        queued.sort_by_key(|(mtime, _)| *mtime);

        Ok(queued
            .into_iter()
            .map(|(_, notification)| notification)
            .collect())
    }

    /// Read and deserialize the contents of a queued notification.
    ///
    /// Fails if the file is a symlink, not a regular file, larger than [`MAX_NOTIFICATION_SIZE`], or
    /// does not contain a valid notification.
    pub fn read_notification(&self, queued: &QueuedNotification) -> Result<Notification, Error> {
        let path = self.queue_dir.join(queued.filename());

        // Anybody allowed to submit can write to the queue directory directly, so neither follow
        // symlinks nor block on opening a FIFO. The file type is checked on the opened file, as
        // checking the path beforehand would race with the file being replaced.
        let file = File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|err| match err.raw_os_error() {
                // A symlink, or a socket or device that cannot be opened, will never be readable.
                Some(libc::ELOOP | libc::ENXIO) => {
                    Error::invalid_queued_notification_with_source("not a regular file", err)
                }
                _ => Error::queue_with_source("could not open queued notification", err),
            })?;

        let metadata = file
            .metadata()
            .map_err(|err| Error::queue_with_source("could not stat queued notification", err))?;

        if !metadata.file_type().is_file() {
            return Err(Error::invalid_queued_notification("not a regular file"));
        }

        let mut buf = Vec::new();
        // Read one additional byte to detect whether the file exceeds the limit.
        file.take(MAX_NOTIFICATION_SIZE + 1)
            .read_to_end(&mut buf)
            .map_err(|err| Error::queue_with_source("could not read queued notification", err))?;

        if buf.len() as u64 > MAX_NOTIFICATION_SIZE {
            return Err(Error::invalid_queued_notification(format!(
                "exceeds maximum size of {MAX_NOTIFICATION_SIZE} bytes"
            )));
        }

        let notification: Notification = serde_json::from_slice(&buf).map_err(|err| {
            Error::invalid_queued_notification_with_source("could not deserialize JSON", err)
        })?;

        notification.validate().map_err(|err| {
            Error::invalid_queued_notification_with_source("notification failed validation", err)
        })?;

        Ok(notification)
    }
}

fn queue_dir_problems(dir: &Path, metadata: &Metadata, euid: u32) -> Vec<String> {
    let dir = dir.display();
    let mode = metadata.mode();
    let mut problems = Vec::new();

    if metadata.uid() != euid {
        problems.push(format!(
            "{dir} is not owned by the user processing the queue"
        ));
    }

    if mode & 0o002 != 0 {
        problems.push(format!("{dir} is writable by everybody"));
    }

    if mode & 0o020 != 0 && mode & 0o1000 == 0 {
        problems.push(format!(
            "{dir} is writable by its group but lacks the sticky bit, so submitters can remove \
            each other's notifications"
        ));
    }

    problems
}

fn parent_dir_problem(dir: &Path, metadata: &Metadata) -> Option<String> {
    let mode = metadata.mode();

    if mode & 0o022 != 0 && mode & 0o1000 == 0 {
        Some(format!(
            "parent directory {} is writable by others than its owner, who can replace the queue \
            directory",
            dir.display()
        ))
    } else {
        None
    }
}

/// Exclusive lock on the queue directory, released on drop.
pub struct QueueLockGuard {
    _dir: File,
}

/// A notification in the queue directory, identified by its file name.
///
/// The file name encodes the whole queue state of a notification. A freshly submitted notification
/// is stored as `notification-<uuid>`. Claiming it for sending renames it to
/// `notification-<uuid>.attempt-<n>`.
///
/// The parser accepts some variations of these names, such as an uppercase UUID or a counter with
/// leading zeros. The actual file name is therefore kept as found, so that it can always be
/// accessed, and only renames write the canonical form.
pub struct QueuedNotification {
    id: Uuid,
    attempt: Option<u32>,
    filename: String,
}

impl QueuedNotification {
    fn parse(filename: &str) -> Option<Self> {
        if let Some(s) = filename.strip_prefix("notification-") {
            let (uuid, attempt) = if let Some((uuid_str, attempt_str)) = s.split_once('.') {
                let uuid = uuid_str.parse::<Uuid>().ok()?;
                let attempt = attempt_str.strip_prefix("attempt-")?.parse::<u32>().ok()?;

                (uuid, Some(attempt))
            } else {
                let uuid = s.parse::<Uuid>().ok()?;

                (uuid, None)
            };

            Some(Self {
                id: uuid,
                attempt,
                filename: filename.to_string(),
            })
        } else {
            None
        }
    }

    /// Return the same notification with the given attempt counter and the canonical file name
    /// for it.
    fn with_attempt(&self, attempt: u32) -> Self {
        Self {
            id: self.id.clone(),
            attempt: Some(attempt),
            filename: format!("notification-{}.attempt-{attempt}", self.id),
        }
    }

    /// Return the filename of this queued notification.
    fn filename(&self) -> &str {
        &self.filename
    }

    /// Return the attempt counter.
    pub fn attempt(&self) -> u32 {
        self.attempt.unwrap_or(0)
    }

    /// Return the ID of the notification.
    ///
    /// The ID is only derived from the filename of the notification, not from
    /// the contents.
    pub fn id(&self) -> &Uuid {
        &self.id
    }
}

#[cfg(all(test, feature = "queue-submitter"))]
mod test {
    use std::time::{Duration, SystemTime};

    use tempfile::tempdir;

    use crate::queue::QueueSubmitter;

    use super::*;

    #[test]
    fn test_enqueue() {
        let base_dir = tempdir().unwrap();

        let consumer = QueueConsumer::new(base_dir.path());
        let queued = consumer.queued_notifications().unwrap();
        assert!(queued.is_empty());

        let submitter = QueueSubmitter::new(base_dir.path());
        let notification = Notification::template_builder("foo", ()).build().unwrap();

        submitter.submit(&notification).unwrap();

        let mut queued = consumer.queued_notifications().unwrap();
        assert_eq!(queued.len(), 1);

        let n = queued.pop().unwrap();

        assert_eq!(n.attempt(), 0);
        let n = consumer.claim(n).unwrap();

        assert_eq!(notification, consumer.read_notification(&n).unwrap());

        consumer.resolve(n).unwrap();

        let queued = consumer.queued_notifications().unwrap();
        assert!(queued.is_empty());
    }

    #[test]
    fn test_requeue() {
        let base_dir = tempdir().unwrap();

        let consumer = QueueConsumer::new(base_dir.path());

        let submitter = QueueSubmitter::new(base_dir.path());
        let notification = Notification::template_builder("foo", ()).build().unwrap();

        submitter.submit(&notification).unwrap();

        let mut queued = consumer.queued_notifications().unwrap();
        assert_eq!(queued.len(), 1);

        let n = queued.pop().unwrap();

        let n = consumer.claim(n).unwrap();
        let n = consumer.requeue(n).unwrap();

        let queued = consumer.queued_notifications().unwrap();
        assert_eq!(queued[0].attempt(), 0);

        // Requeueing again must cap the attempt counter at 0
        consumer.requeue(n).unwrap();
        let queued = consumer.queued_notifications().unwrap();
        assert_eq!(queued[0].attempt(), 0);
    }

    #[test]
    fn test_attempt_counter() {
        let base_dir = tempdir().unwrap();

        let consumer = QueueConsumer::new(base_dir.path());

        let submitter = QueueSubmitter::new(base_dir.path());
        let notification = Notification::template_builder("foo", ()).build().unwrap();

        submitter.submit(&notification).unwrap();

        let mut queued = consumer.queued_notifications().unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].attempt(), 0);
        consumer.claim(queued.pop().unwrap()).unwrap();

        let mut queued = consumer.queued_notifications().unwrap();
        assert_eq!(queued[0].attempt(), 1);
        let _ = consumer.claim(queued.pop().unwrap()).unwrap();

        let queued = consumer.queued_notifications().unwrap();
        assert_eq!(queued[0].attempt(), 2);
    }

    #[test]
    fn test_sorted_by_mtime() {
        let base_dir = tempdir().unwrap();

        let consumer = QueueConsumer::new(base_dir.path());
        let submitter = QueueSubmitter::new(base_dir.path());

        let notifications: Vec<_> = (0..5)
            .map(|_| Notification::template_builder("foo", ()).build().unwrap())
            .collect();

        let now = SystemTime::now();

        // Submit in order, but make earlier submissions appear newer
        for (i, notification) in notifications.iter().enumerate() {
            submitter.submit(notification).unwrap();

            let path = base_dir
                .path()
                .join(format!("notification-{}", notification.id()));
            let file = std::fs::File::options().write(true).open(path).unwrap();
            file.set_modified(now - Duration::from_secs(i as u64 * 60))
                .unwrap();
        }

        let queued = consumer.queued_notifications().unwrap();
        let queued_ids: Vec<_> = queued.iter().map(|n| n.id().clone()).collect();
        let expected_ids: Vec<_> = notifications.iter().rev().map(|n| n.id().clone()).collect();

        assert_eq!(queued_ids, expected_ids);

        // Claiming renames the file, which must not affect the order
        let oldest = queued.into_iter().next().unwrap();
        consumer.claim(oldest).unwrap();

        let queued = consumer.queued_notifications().unwrap();
        let queued_ids: Vec<_> = queued.iter().map(|n| n.id().clone()).collect();

        assert_eq!(queued_ids, expected_ids);
    }

    #[test]
    fn test_non_canonical_filenames() {
        let base_dir = tempdir().unwrap();

        let consumer = QueueConsumer::new(base_dir.path());

        let notification = Notification::template_builder("foo", ()).build().unwrap();
        let contents = serde_json::to_vec(&notification).unwrap();

        // Uppercase UUID without an attempt counter, and a counter with a leading zero.
        let uppercase_id = Uuid::generate();
        let padded_id = Uuid::generate();
        let filenames = [
            format!("notification-{}", uppercase_id.to_string().to_uppercase()),
            format!("notification-{padded_id}.attempt-01"),
        ];
        for filename in &filenames {
            std::fs::write(base_dir.path().join(filename), &contents).unwrap();
        }

        let queued = consumer.queued_notifications().unwrap();
        assert_eq!(queued.len(), 2);

        for n in queued {
            assert_eq!(consumer.read_notification(&n).unwrap(), notification);

            let n = consumer.claim(n).unwrap();
            assert_eq!(consumer.read_notification(&n).unwrap(), notification);

            let n = consumer.requeue(n).unwrap();
            consumer.resolve(n).unwrap();
        }

        assert!(consumer.queued_notifications().unwrap().is_empty());
        assert_eq!(std::fs::read_dir(base_dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn test_setup_problems() {
        use std::os::unix::fs::PermissionsExt;

        let base_dir = tempdir().unwrap();
        let path = base_dir.path();
        let euid = nix::unistd::geteuid().as_raw();

        let problems = |mode| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
            let metadata = std::fs::metadata(path).unwrap();
            (
                queue_dir_problems(path, &metadata, euid).len(),
                parent_dir_problem(path, &metadata).is_some(),
            )
        };

        assert_eq!(problems(0o3770), (0, false));
        assert_eq!(problems(0o1700), (0, false));
        assert_eq!(problems(0o0755), (0, false));
        assert_eq!(problems(0o0770), (1, true));
        assert_eq!(problems(0o0777), (2, true));
        assert_eq!(problems(0o1777), (1, false));

        // Not owned by the worker's user.
        problems(0o3770);
        let metadata = std::fs::metadata(path).unwrap();
        assert_eq!(queue_dir_problems(path, &metadata, euid + 1).len(), 1);

        // The checks of the actual parent directories depend on the test environment.
        assert!(QueueConsumer::new(path).setup_problems().is_ok());
    }

    fn single_queued(consumer: &QueueConsumer) -> QueuedNotification {
        let mut queued = consumer.queued_notifications().unwrap();
        assert_eq!(queued.len(), 1);
        queued.pop().unwrap()
    }

    #[test]
    fn test_ignore_other_files() {
        let base_dir = tempdir().unwrap();
        let consumer = QueueConsumer::new(base_dir.path());

        let id = Uuid::generate();
        let names = [
            // left over by an interrupted submission
            format!("notification-{id}.tmp_AbC123"),
            format!("notification-{id}.attempt-1.broken"),
            format!("notification-{id}.attempt-x"),
            format!("notification-{id}.json"),
            format!("{id}.json"),
        ];
        for name in names {
            std::fs::write(base_dir.path().join(name), b"{}").unwrap();
        }

        assert!(consumer.queued_notifications().unwrap().is_empty());
    }

    #[test]
    fn test_read_symlink() {
        let base_dir = tempdir().unwrap();
        let other_dir = tempdir().unwrap();

        let consumer = QueueConsumer::new(base_dir.path());

        let notification = Notification::template_builder("foo", ()).build().unwrap();
        let target = other_dir.path().join("target");
        std::fs::write(&target, serde_json::to_vec(&notification).unwrap()).unwrap();

        let link = base_dir
            .path()
            .join(format!("notification-{}", notification.id()));
        std::os::unix::fs::symlink(&target, link).unwrap();

        let n = single_queued(&consumer);
        assert!(matches!(
            consumer.read_notification(&n),
            Err(Error::InvalidQueuedNotification { .. })
        ));
    }

    #[test]
    fn test_read_fifo() {
        let base_dir = tempdir().unwrap();

        let consumer = QueueConsumer::new(base_dir.path());

        let path = base_dir
            .path()
            .join(format!("notification-{}", Uuid::generate()));
        nix::unistd::mkfifo(
            &path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();

        // Without a writer, a blocking open would hang here.
        let n = single_queued(&consumer);
        assert!(matches!(
            consumer.read_notification(&n),
            Err(Error::InvalidQueuedNotification { .. })
        ));
    }

    #[test]
    fn test_read_invalid_template_name() {
        let base_dir = tempdir().unwrap();

        let consumer = QueueConsumer::new(base_dir.path());

        let notification = Notification::template_builder("foo", ()).build().unwrap();
        let mut contents = serde_json::to_value(&notification).unwrap();
        contents["content"]["template"]["template-name"] = "../foo".into();

        let path = base_dir
            .path()
            .join(format!("notification-{}", notification.id()));
        std::fs::write(&path, serde_json::to_vec(&contents).unwrap()).unwrap();

        let n = single_queued(&consumer);
        assert!(matches!(
            consumer.read_notification(&n),
            Err(Error::InvalidQueuedNotification { .. })
        ));
    }

    #[test]
    fn test_read_oversized() {
        let base_dir = tempdir().unwrap();

        let consumer = QueueConsumer::new(base_dir.path());

        let notification = Notification::template_builder("foo", ()).build().unwrap();
        let path = base_dir
            .path()
            .join(format!("notification-{}", notification.id()));

        // Trailing whitespace keeps the contents valid JSON, so only the size limit can reject it.
        let mut contents = serde_json::to_vec(&notification).unwrap();
        contents.resize(MAX_NOTIFICATION_SIZE as usize, b' ');
        std::fs::write(&path, &contents).unwrap();

        let n = single_queued(&consumer);
        assert_eq!(consumer.read_notification(&n).unwrap(), notification);

        contents.push(b' ');
        std::fs::write(&path, &contents).unwrap();

        assert!(consumer.read_notification(&n).is_err());
    }
}
