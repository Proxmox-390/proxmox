//! Raises signals at its own process and changes process-wide daemon state, so this must stay the
//! only test in its binary.

use std::time::Duration;

use proxmox_daemon::{catch_shutdown_signal, is_reload_requested, request_reload, shutdown_future};

const TIMEOUT: Duration = Duration::from_secs(10);

fn raise(signal: libc::c_int) {
    let res = unsafe { libc::raise(signal) };
    assert_eq!(res, 0, "failed to raise {signal}");
}

#[tokio::test]
async fn sigterm_requests_a_shutdown_and_rules_out_a_later_reload() {
    // The handlers are installed once this returns, so SIGTERM does not take its default action
    // and terminate the test process.
    catch_shutdown_signal(std::future::pending()).unwrap();

    raise(libc::SIGTERM);
    tokio::time::timeout(TIMEOUT, shutdown_future())
        .await
        .expect("SIGTERM did not request a shutdown");

    request_reload();
    assert!(!is_reload_requested(), "reload requested after SIGTERM");
}
