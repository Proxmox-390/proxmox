//! Worker task that sends queued notifications.

use std::sync::Arc;
use std::time::Duration;

use proxmox_uuid::Uuid;

use crate::{Context, Error};

use crate::queue::consumer::{QueueConsumer, QueueLockGuard, QueuedNotification};

const DEFAULT_INTERVAL: Duration = Duration::from_secs(5);

/// Time the queue may stay locked by somebody else before a warning is logged.
const LOCKED_WARN_THRESHOLD: Duration = Duration::from_secs(5 * 60);

/// Builder for the [`QueueWorker`] type.
///
/// Construct this via [`QueueWorker::builder`] and
/// finalize via [`QueueWorkerBuilder::build`].
pub struct QueueWorkerBuilder {
    context: Context,
    queue: Arc<QueueConsumer>,

    interval: Option<Duration>,
    retry_attempts: Option<u32>,
}

impl QueueWorkerBuilder {
    /// Set the interval at which the queue directory shall be polled
    /// for new notifications.
    ///
    /// If not set, the interval defaults to 5 seconds.
    pub fn interval(mut self, interval: Duration) -> Self {
        self.interval = Some(interval);
        self
    }

    /// Number of retry attempts before dropping the notification entirely.
    ///
    /// This is not for retries after failing to deliver a notification
    /// to one or more targets individually, but for when the worker
    /// got interrupted during sending before removing the notification
    /// from the queue.
    ///
    /// If set to e.g. 2, then sending a notification would be retried *twice*
    /// after the first attempt, so in total three attempts.
    ///
    /// If not set, no retries are performed.
    pub fn retry_attempts(mut self, attempts: u32) -> Self {
        self.retry_attempts = Some(attempts);
        self
    }

    /// Build the final [`QueueWorker`].
    ///
    /// All optional fields that were not initialized are set to
    /// their defaults.
    pub fn build(self) -> QueueWorker {
        QueueWorker {
            context: self.context,
            queue: self.queue,
            polling_backoff: PollingBackoff::new(self.interval.unwrap_or(DEFAULT_INTERVAL)),
            locked_for: Duration::ZERO,
            retry_attempts: self.retry_attempts.unwrap_or(0),

            #[cfg(test)]
            history: Vec::new(),
        }
    }
}

/// Worker task that sends queued notifications.
///
/// The worker periodically polls the notification queue, claims each queued notification, sends it
/// according to the current notification configuration and removes it from the queue afterwards.
/// On startup, notifications that were still in flight when the previous worker stopped are sent
/// again, unless they have already reached the attempt limit, in which case they are dropped.
pub struct QueueWorker {
    context: Context,
    queue: Arc<QueueConsumer>,
    polling_backoff: PollingBackoff,
    retry_attempts: u32,
    /// Polling intervals summed up over the consecutive cycles skipped due to a locked queue.
    locked_for: Duration,

    #[cfg(test)]
    history: Vec<HistoryEntry>,
}

impl QueueWorker {
    /// Create the builder to instantiate this worker task.
    pub fn builder(context: Context, consumer: QueueConsumer) -> QueueWorkerBuilder {
        QueueWorkerBuilder {
            context,
            queue: Arc::new(consumer),
            interval: None,
            retry_attempts: None,
        }
    }

    /// Run the worker.
    ///
    /// The queue is polled at the defined interval (see [`QueueWorkerBuilder::interval`]).
    ///
    /// This function does not return.
    pub async fn run(mut self) -> ! {
        self.warn_about_queue_setup().await;

        loop {
            self.process_queued_notifications().await;
            self.wait().await;
        }
    }

    async fn process_queued_notifications(&mut self) {
        // Hold the queue lock for the whole cycle, so that no other consumer of the same queue
        // directory claims, requeues or resolves notifications concurrently.
        let lock_guard = match self.lock_queue().await {
            Ok(Some(guard)) => {
                if self.locked_for >= LOCKED_WARN_THRESHOLD {
                    tracing::info!("notification queue is not locked anymore, processing it again");
                }
                self.locked_for = Duration::ZERO;
                Arc::new(guard)
            }
            Ok(None) => {
                let warned = self.locked_for >= LOCKED_WARN_THRESHOLD;
                self.locked_for = self
                    .locked_for
                    .saturating_add(self.polling_backoff.active_interval());

                if !warned && self.locked_for >= LOCKED_WARN_THRESHOLD {
                    tracing::warn!(
                        "notification queue has been locked by another process for at least {} \
                        minutes, queued notifications are not sent until it is released",
                        LOCKED_WARN_THRESHOLD.as_secs() / 60,
                    );
                } else {
                    tracing::debug!(
                        "queue directory is locked by another consumer, skipping cycle"
                    );
                }
                return;
            }
            Err(err) => {
                tracing::error!("failed to lock queue: {err}");
                self.polling_backoff.increment_error_count();
                return;
            }
        };

        let mut any_error = false;

        let queued_notifications = self
            .queued_notifications()
            .await
            .inspect_err(|err| {
                tracing::error!("failed to read queue: {err}");
                any_error = true
            })
            .unwrap_or_default();

        for queued_notification in queued_notifications {
            let id = queued_notification.id().clone();
            let queue = Arc::clone(&self.queue);
            let context = self.context.clone();
            let max_retries = self.retry_attempts;
            // The blocking task keeps running if this future is dropped, e.g. on daemon shutdown.
            // Keep the queue locked until it finishes, so that no other worker can pick up the
            // same notification while it is still being sent.
            let lock_guard = Arc::clone(&lock_guard);

            let res = tokio::task::spawn_blocking(move || {
                let _lock_guard = lock_guard;
                let current_attempt = queued_notification.attempt();
                let id = queued_notification.id().clone();

                if current_attempt > max_retries {
                    tracing::warn!("dropping notification {id} after attempt {current_attempt}");
                    queue.resolve(queued_notification)?;

                    return Ok(HistoryEntry {
                        status: HistoryStatus::Dropped,
                        id,
                    });
                }

                // In most cases, we handle at most one notification in each cycle. If there are
                // multiple to handle, it makes sense to re-read the config after each one, in case
                // sending of one notification ran into long SMTP/HTTP timeouts.
                let config = context
                    .read_config()
                    .map_err(Error::config_deserialization)?;

                // The notification is claimed *after* the configuration was read, to ensure
                // that a temporarily broken notification config does *not* lead to notifications
                // being dropped because they have exceeded the maximum number of retries.
                let queued_notification = queue.claim(queued_notification)?;

                let notification = match queue.read_notification(&queued_notification) {
                    Ok(notification) => notification,
                    Err(err) => {
                        if matches!(err, Error::InvalidQueuedNotification { .. }) {
                            tracing::error!("marking notification as broken: {err}");
                            // If the notification itself is bad, we move it aside and don't
                            // process it again.
                            queue.mark_broken(queued_notification)?;
                        } else {
                            // Nothing was sent, so this must not count as an attempt.
                            queue.requeue(queued_notification)?;
                        }
                        return Err(err);
                    }
                };

                tracing::info!("handling notification {}", queued_notification.id());

                match crate::send(&context, &config, &notification) {
                    Ok(_receipt) => {
                        queue.resolve(queued_notification)?;

                        Ok(HistoryEntry {
                            id,
                            status: HistoryStatus::Sent,
                        })
                    }
                    Err(err) => {
                        // An error here means that the notification for sure was
                        // not sent to anyone, because sending failed at some point
                        // *before* a single target was notified.
                        //
                        // The notification itself is fine, so we keep it around by
                        // putting it back into the queue.
                        // The returned error leads to the backoff error count being
                        // increased, triggering the backoff mechanism to avoid spamming
                        // logs every couple seconds.
                        queue.requeue(queued_notification)?;

                        Err(err)
                    }
                }
            })
            .await;

            match res {
                Ok(Ok(_history_entry)) => {
                    #[cfg(test)]
                    self.history.push(_history_entry);
                }
                Ok(Err(err)) => {
                    tracing::error!(
                        "notification worker failed to handle notification {id}: {err}"
                    );
                    any_error = true;

                    if matches!(err, Error::ConfigDeserialization(_)) {
                        // There is no point in processing the remaining queue if the config
                        // does not parse, let's just retry at the next cycle.
                        break;
                    }
                }
                Err(err) => {
                    tracing::error!(
                        "failed to join task in notification worker for notification {id}: {err}"
                    );
                    any_error = true;
                }
            }
        }

        if any_error {
            self.polling_backoff.increment_error_count();
        } else {
            self.polling_backoff.reset_error_count();
        }
    }

    async fn warn_about_queue_setup(&self) {
        let queue = Arc::clone(&self.queue);

        match tokio::task::spawn_blocking(move || queue.setup_problems()).await {
            Ok(Ok(problems)) => {
                for problem in problems {
                    tracing::warn!("insecure notification queue setup: {problem}");
                }
            }
            Ok(Err(err)) => tracing::warn!("could not check notification queue setup: {err}"),
            Err(err) => tracing::warn!("could not check notification queue setup: {err}"),
        }
    }

    async fn lock_queue(&self) -> Result<Option<QueueLockGuard>, Error> {
        let queue = Arc::clone(&self.queue);
        tokio::task::spawn_blocking(move || queue.try_lock())
            .await
            .map_err(|err| Error::other_with_source("could not join tokio task", err))?
    }

    async fn queued_notifications(&self) -> Result<Vec<QueuedNotification>, Error> {
        let queue = Arc::clone(&self.queue);
        tokio::task::spawn_blocking(move || queue.queued_notifications())
            .await
            .map_err(|err| Error::other_with_source("could not join tokio task", err))?
    }

    async fn wait(&self) {
        tokio::time::sleep(self.polling_backoff.active_interval()).await;
    }
}

#[derive(Debug, PartialEq)]
enum HistoryStatus {
    Sent,
    Dropped,
}

#[derive(Debug, PartialEq)]
// Added for better testability, once the notification history is implemented,
// this would be extended and moved to api_types.
struct HistoryEntry {
    id: Uuid,
    status: HistoryStatus,
}

/// Number of consecutive erroneous cycles after which the polling interval is raised.
const BACKOFF_THRESHOLD: u64 = 10;
/// Factor by which the polling interval is raised while backing off.
const BACKOFF_FACTOR: u32 = 10;

struct PollingBackoff {
    default_interval: Duration,
    error_count: u64,
}

impl PollingBackoff {
    fn new(interval: Duration) -> Self {
        Self {
            default_interval: interval,
            error_count: 0,
        }
    }

    fn is_backing_off(&self) -> bool {
        self.error_count > BACKOFF_THRESHOLD
    }

    fn increment_error_count(&mut self) {
        let was_backing_off = self.is_backing_off();
        self.error_count = self.error_count.saturating_add(1);

        if !was_backing_off && self.is_backing_off() {
            tracing::info!(
                "notification worker encountered several errors in succession, raising polling interval to {:?}",
                self.active_interval()
            );
        }
    }

    fn reset_error_count(&mut self) {
        let was_backing_off = self.is_backing_off();
        self.error_count = 0;

        if was_backing_off {
            tracing::info!(
                "notification worker resetting queue polling interval to default of {:?}",
                self.default_interval
            );
        }
    }

    fn active_interval(&self) -> Duration {
        if self.is_backing_off() {
            self.default_interval.saturating_mul(BACKOFF_FACTOR)
        } else {
            self.default_interval
        }
    }
}

#[cfg(all(test, feature = "queue-submitter"))]
mod test {
    use std::cell::Cell;
    use std::time::SystemTime;

    use tempfile::{TempDir, tempdir};

    use crate::Notification;
    use crate::context::test::TestContext;
    use crate::queue::QueueSubmitter;

    use super::*;

    struct WorkerTestSetup {
        dir: TempDir,
        consumer: QueueConsumer,
        submitter: QueueSubmitter,
        submitted: Cell<u64>,
    }

    impl WorkerTestSetup {
        fn new() -> Self {
            let dir = tempdir().unwrap();

            Self {
                consumer: QueueConsumer::new(dir.path()),
                submitter: QueueSubmitter::new(dir.path()),
                submitted: Cell::new(0),
                dir,
            }
        }

        fn submit_notification(&self) -> Uuid {
            let notification = Notification::template_builder("foo", ()).build().unwrap();
            self.submitter.submit(&notification).unwrap();

            // Notifications submitted in quick succession may share the same mtime, so give each one
            // a distinct one to have them handled in submission order.
            let count = self.submitted.get();
            self.submitted.set(count + 1);

            let path = self
                .dir
                .path()
                .join(format!("notification-{}", notification.id()));
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(count))
                .unwrap();

            notification.id().clone()
        }

        /// Claim all queued notifications without resolving them, like a worker that got
        /// interrupted while sending.
        fn claim_all(&self) {
            for queued in self.consumer.queued_notifications().unwrap() {
                self.consumer.claim(queued).unwrap();
            }
        }

        fn attempts(&self) -> Vec<u32> {
            self.consumer
                .queued_notifications()
                .unwrap()
                .iter()
                .map(QueuedNotification::attempt)
                .collect()
        }

        fn create_worker(
            &self,
            config_readable: bool,
            retries_before_drop: Option<u32>,
        ) -> QueueWorker {
            // With the default empty config, sending succeeds without reaching any target.
            let context = Context::new(TestContext {
                fail_read_config: !config_readable,
            });
            let mut builder = QueueWorker::builder(context, QueueConsumer::new(self.dir.path()));

            if let Some(attempts) = retries_before_drop {
                builder = builder.retry_attempts(attempts);
            }

            builder.build()
        }
    }

    fn run_single_cycle(worker: &mut QueueWorker) {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(worker.process_queued_notifications());
    }

    #[test]
    fn test_send_with_defaults() {
        let setup = WorkerTestSetup::new();
        let ids = [setup.submit_notification(), setup.submit_notification()];

        let mut worker = setup.create_worker(true, None);
        run_single_cycle(&mut worker);

        assert!(setup.attempts().is_empty());
        // Queued notifications are handled oldest first.
        assert_eq!(
            worker.history,
            ids.map(|id| HistoryEntry {
                id,
                status: HistoryStatus::Sent,
            })
        );
        assert_eq!(worker.polling_backoff.error_count, 0);
    }

    #[test]
    fn test_skip_cycle_while_locked() {
        let setup = WorkerTestSetup::new();
        let id = setup.submit_notification();

        let mut worker = setup.create_worker(true, None);

        let guard = setup.consumer.try_lock().unwrap().unwrap();
        run_single_cycle(&mut worker);

        // Another consumer holds the lock, so the notification must not be touched.
        assert_eq!(setup.attempts(), [0]);
        assert!(worker.history.is_empty());
        assert_eq!(worker.polling_backoff.error_count, 0);

        while worker.locked_for < LOCKED_WARN_THRESHOLD {
            run_single_cycle(&mut worker);
        }
        assert_eq!(worker.locked_for, LOCKED_WARN_THRESHOLD);
        assert_eq!(setup.attempts(), [0]);

        drop(guard);
        run_single_cycle(&mut worker);

        assert_eq!(worker.locked_for, Duration::ZERO);
        assert!(setup.attempts().is_empty());
        assert_eq!(
            worker.history,
            [HistoryEntry {
                id,
                status: HistoryStatus::Sent,
            }]
        );
    }

    #[test]
    fn test_config_error_keeps_notification() {
        let setup = WorkerTestSetup::new();
        let id = setup.submit_notification();

        let mut worker = setup.create_worker(false, None);
        run_single_cycle(&mut worker);

        // A config error must not count as an interrupted send.
        assert_eq!(setup.attempts(), [0]);
        assert!(worker.history.is_empty());
        assert_eq!(worker.polling_backoff.error_count, 1);

        // Once the config can be read again, the notification is sent.
        let mut worker = setup.create_worker(true, None);
        run_single_cycle(&mut worker);

        assert!(setup.attempts().is_empty());
        assert_eq!(
            worker.history,
            [HistoryEntry {
                id,
                status: HistoryStatus::Sent,
            }]
        );
    }

    #[test]
    fn test_recover_interrupted_send() {
        let setup = WorkerTestSetup::new();
        let id = setup.submit_notification();
        setup.claim_all();
        assert_eq!(setup.attempts(), [1]);

        let mut worker = setup.create_worker(true, Some(1));
        run_single_cycle(&mut worker);

        assert!(setup.attempts().is_empty());
        assert_eq!(
            worker.history,
            [HistoryEntry {
                id,
                status: HistoryStatus::Sent,
            }]
        );
        assert_eq!(worker.polling_backoff.error_count, 0);
    }

    #[test]
    fn test_drop_after_recovery_attempts() {
        let setup = WorkerTestSetup::new();
        let id = setup.submit_notification();
        setup.claim_all();
        setup.claim_all();
        assert_eq!(setup.attempts(), [2]);

        let mut worker = setup.create_worker(true, Some(1));
        run_single_cycle(&mut worker);

        assert!(setup.attempts().is_empty());
        assert_eq!(
            worker.history,
            [HistoryEntry {
                id,
                status: HistoryStatus::Dropped,
            }]
        );
    }

    #[test]
    fn test_default_drops_interrupted_send() {
        let setup = WorkerTestSetup::new();
        let id = setup.submit_notification();
        setup.claim_all();

        let mut worker = setup.create_worker(true, None);
        run_single_cycle(&mut worker);

        assert!(setup.attempts().is_empty());
        assert_eq!(
            worker.history,
            [HistoryEntry {
                id,
                status: HistoryStatus::Dropped,
            }]
        );
    }

    #[test]
    fn test_unreadable_notification_marked_broken() {
        let setup = WorkerTestSetup::new();
        let valid_id = setup.submit_notification();

        let broken_id = Uuid::generate();
        std::fs::write(
            setup.dir.path().join(format!("notification-{broken_id}")),
            b"not json",
        )
        .unwrap();

        let mut worker = setup.create_worker(true, None);
        run_single_cycle(&mut worker);

        // The broken notification is moved aside and does not keep the other one from being sent.
        assert!(setup.attempts().is_empty());
        assert_eq!(
            worker.history,
            [HistoryEntry {
                id: valid_id,
                status: HistoryStatus::Sent,
            }]
        );
        assert!(
            setup
                .dir
                .path()
                .join(format!("notification-{broken_id}.attempt-1.broken"))
                .exists()
        );

        // A broken notification is not picked up again.
        run_single_cycle(&mut worker);

        assert_eq!(worker.history.len(), 1);
    }

    #[test]
    fn test_invalid_notification_marked_broken() {
        let setup = WorkerTestSetup::new();

        let notification = Notification::template_builder("foo", ()).build().unwrap();
        let mut contents = serde_json::to_value(&notification).unwrap();
        contents["content"]["template"]["template-name"] = "../foo".into();
        std::fs::write(
            setup
                .dir
                .path()
                .join(format!("notification-{}", notification.id())),
            serde_json::to_vec(&contents).unwrap(),
        )
        .unwrap();

        let mut worker = setup.create_worker(true, None);
        run_single_cycle(&mut worker);

        assert!(setup.attempts().is_empty());
        assert!(worker.history.is_empty());
        assert!(
            setup
                .dir
                .path()
                .join(format!(
                    "notification-{}.attempt-1.broken",
                    notification.id()
                ))
                .exists()
        );
    }

    #[test]
    fn test_interval_backoff() {
        let interval = Duration::from_secs(1);
        let mut backoff = PollingBackoff::new(interval);

        for _ in 0..10 {
            backoff.increment_error_count();
        }
        assert_eq!(backoff.active_interval(), interval);

        backoff.increment_error_count();
        assert_eq!(backoff.active_interval(), interval * 10);

        backoff.reset_error_count();
        assert_eq!(backoff.active_interval(), interval);

        // Backoff must trigger again after another series of errors.
        for _ in 0..11 {
            backoff.increment_error_count();
        }
        assert_eq!(backoff.active_interval(), interval * 10);
    }

    #[test]
    fn test_interval_backoff_saturates() {
        let mut backoff = PollingBackoff::new(Duration::MAX);

        for _ in 0..11 {
            backoff.increment_error_count();
        }
        assert_eq!(backoff.active_interval(), Duration::MAX);
    }
}
