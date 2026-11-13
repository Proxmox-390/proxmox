//! Raises signals at its own process and changes process-wide daemon state, so this must stay the
//! only test in its binary.

use std::time::Duration;

use proxmox_daemon::{
    catch_reload_signal, catch_shutdown_signal, is_reload_requested, request_reload,
    shutdown_future,
};

const TIMEOUT: Duration = Duration::from_secs(10);

fn raise(signal: libc::c_int) {
    let res = unsafe { libc::raise(signal) };
    assert_eq!(res, 0, "failed to raise {signal}");
}

#[tokio::test]
async fn sigint_before_a_reload_request_rules_out_the_reload() {
    // The handlers are installed once these return, so no signal takes its default action and
    // terminates the test process.
    catch_shutdown_signal(std::future::pending()).unwrap();
    catch_reload_signal(std::future::pending()).unwrap();

    raise(libc::SIGINT);
    tokio::time::timeout(TIMEOUT, shutdown_future())
        .await
        .expect("SIGINT did not request a shutdown");

    request_reload();
    assert!(!is_reload_requested(), "reload requested after SIGINT");
    raise(libc::SIGHUP);
    // Its handler has no other visible effect to wait for.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !is_reload_requested(),
        "reload requested by SIGHUP after SIGINT"
    );
}
