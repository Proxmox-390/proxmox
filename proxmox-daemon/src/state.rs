use std::future::Future;
use std::pin::pin;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use anyhow::{Error, bail};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;

static SHUTDOWN_LISTENERS: OnceLock<watch::Sender<bool>> = OnceLock::new();
// Whichever of a reload and a shutdown request came first decides for good whether the daemon
// reloads, so that a service can rely on what it saw when its shutdown began.
static RELOAD_OR_STOP: AtomicU8 = AtomicU8::new(UNDECIDED);
const UNDECIDED: u8 = 0;
const RELOAD: u8 = 1;
const STOP: u8 = 2;
// Set by a shutdown signal also after a reload request, to pass the stop on to the new server.
static STOP_LATCHED: AtomicBool = AtomicBool::new(false);
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Request a reload.
///
/// Unless a shutdown was requested first, this sets the reload flag and subsequently calls
/// [`request_shutdown()`].
pub fn request_reload() {
    if RELOAD_OR_STOP
        .compare_exchange(UNDECIDED, RELOAD, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        request_shutdown();
    }
}

/// Returns true if a reload has been requested either via a signal or a call to
/// [`request_reload()`] before any shutdown request. Once true, this stays true.
pub fn is_reload_requested() -> bool {
    RELOAD_OR_STOP.load(Ordering::Acquire) == RELOAD
}

// Records a shutdown signal, or a stop passed on by the reload that started this process. Only
// uses lock-free atomics, so a signal handler can call it.
pub(crate) fn latch_stop() {
    STOP_LATCHED.store(true, Ordering::Release);
    let _ = RELOAD_OR_STOP.compare_exchange(UNDECIDED, STOP, Ordering::AcqRel, Ordering::Acquire);
}

/// Whether a stop was latched, also after a reload request.
pub(crate) fn is_stop_latched() -> bool {
    STOP_LATCHED.load(Ordering::Acquire)
}

/// Request a shutdown.
///
/// This sets both the shutdown flag and triggers [`shutdown_future()`] to finish. Unless a reload
/// was requested before, this also rules out a reload for good.
pub fn request_shutdown() {
    log::info!("request_shutdown");

    let _ = RELOAD_OR_STOP.compare_exchange(UNDECIDED, STOP, Ordering::AcqRel, Ordering::Acquire);

    if !SHUTDOWN_REQUESTED.swap(true, Ordering::Release) {
        // Unlike send(), this also keeps the value without a receiver, for any shutdown_future()
        // that only subscribes later.
        shutdown_listeners().send_replace(true);
    }
}

/// Returns true if a shutdown has been requested either via a signal or a call to
/// [`request_shutdown()`].
pub fn is_shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::Acquire)
}

fn shutdown_listeners() -> &'static watch::Sender<bool> {
    SHUTDOWN_LISTENERS.get_or_init(|| watch::channel(false).0)
}

/// This future finishes once a shutdown has been requested either via a signal or a call to
/// [`request_shutdown()`].
pub async fn shutdown_future() {
    let _ = shutdown_listeners().subscribe().wait_for(|&v| v).await;
}

/// Pin and select().
async fn pin_select<A, B>(a: A, b: B)
where
    A: Future<Output = ()> + Send + 'static,
    B: Future<Output = ()> + Send + 'static,
{
    let a = pin!(a);
    let b = pin!(b);
    futures::future::select(a, b).await;
}

/// Creates a task which listens for a `SIGINT` or `SIGTERM` and then calls [`request_shutdown()`].
/// A signal before any *reload* request rules out a reload for good. One during a reload is
/// passed on to the new server, which then stops right after it started.
pub fn shutdown_signal_task() -> Result<impl Future<Output = ()> + Send + 'static, Error> {
    let interrupt = shutdown_on_signal(libc::SIGINT, "SIGINT")?;
    let terminate = shutdown_on_signal(libc::SIGTERM, "SIGTERM")?;

    Ok(async move {
        futures::future::join(interrupt, terminate).await;
    })
}

fn shutdown_on_signal(
    signum: libc::c_int,
    name: &'static str,
) -> Result<impl Future<Output = ()> + Send + 'static, Error> {
    let mut stream = signal(SignalKind::from_raw(signum))?;
    latch_stop_on(signum)?;

    Ok(async move {
        while stream.recv().await.is_some() {
            log::info!("got shutdown request ({name})");
            request_shutdown();
        }
    })
}

// Latches the stop right in the signal handler. A reload waits for the service manager in
// blocking calls, which the signal interrupts if it arrives in the same thread, and then decides
// what to tell the new server, possibly before the signal task ran.
fn latch_stop_on(signal: libc::c_int) -> Result<(), Error> {
    // SAFETY: latch_stop() only uses lock-free atomics, which is async-signal-safe.
    unsafe { signal_hook_registry::register(signal, latch_stop)? };
    Ok(())
}

/// Spawn a [`shutdown_signal_task()`] which is automatically aborted with the provided
/// `abort_future`.
pub fn catch_shutdown_signal<F>(abort_future: F) -> Result<(), Error>
where
    F: Future<Output = ()> + Send + 'static,
{
    log::info!("catching shutdown signal");
    tokio::spawn(pin_select(shutdown_signal_task()?, abort_future));
    Ok(())
}

/// Creates a task which listens for a `SIGHUP` and then calls [`request_reload()`].
pub fn reload_signal_task() -> Result<impl Future<Output = ()> + Send + 'static, Error> {
    let mut stream = signal(SignalKind::hangup())?;

    Ok(async move {
        while stream.recv().await.is_some() {
            log::info!("got reload request (SIGHUP)");
            request_reload();
        }
    })
}

/// Spawn a [`reload_signal_task()`] which is automatically aborted with the provided
/// `abort_future`.
pub fn catch_reload_signal<F>(abort_future: F) -> Result<(), Error>
where
    F: Future<Output = ()> + Send + 'static,
{
    log::info!("catching reload signal");
    tokio::spawn(pin_select(reload_signal_task()?, abort_future));
    Ok(())
}

/// Raise an error if there was a shutdown request.
pub fn fail_on_shutdown() -> Result<(), Error> {
    if is_shutdown_requested() {
        bail!("Server shutdown requested - aborting task");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use futures::FutureExt;

    #[test]
    fn shutdown_requested_before_anyone_waits_is_seen() {
        super::request_shutdown();
        assert!(super::shutdown_future().now_or_never().is_some());
    }
}
