//! Raises signals at its own process and changes process-wide daemon state, so this must stay the
//! only test in its binary.

use std::time::Duration;

use proxmox_daemon::{catch_reload_signal, catch_shutdown_signal, is_reload_requested};

const TIMEOUT: Duration = Duration::from_secs(10);

fn raise(signal: libc::c_int) {
    let res = unsafe { libc::raise(signal) };
    assert_eq!(res, 0, "failed to raise {signal}");
}

#[tokio::test]
async fn reload_request_stays_in_effect_on_a_later_sigint() {
    // The handlers are installed once these return, so no signal takes its default action and
    // terminates the test process.
    catch_shutdown_signal(std::future::pending()).unwrap();
    catch_reload_signal(std::future::pending()).unwrap();

    raise(libc::SIGHUP);
    let requested = async {
        while !is_reload_requested() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(TIMEOUT, requested)
        .await
        .expect("SIGHUP did not request a reload");

    raise(libc::SIGINT);
    // Right after its handler ran, and once its task had time to run.
    assert!(is_reload_requested(), "SIGINT called off the reload");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(is_reload_requested(), "SIGINT called off the reload");
}
