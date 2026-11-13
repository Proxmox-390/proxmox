//! Changes process-wide daemon state, so this must stay the only test in its binary.

use proxmox_daemon::{is_reload_requested, request_reload, request_shutdown};

#[test]
fn shutdown_request_before_a_reload_request_rules_out_the_reload() {
    request_shutdown();
    request_reload();
    assert!(
        !is_reload_requested(),
        "reload requested after a shutdown request"
    );
}
