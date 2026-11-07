use std::io::Write;
use std::path::Path;

use serde_json::json;

use proxmox_access_log::{
    API_METHOD_GET_ACCESS_LOG, API_METHOD_GET_ACCESS_LOG_STATS, init_access_log_api,
};

mod common;
use common::{call, entries, status};

fn line(minute: u32, user: &str) -> String {
    format!(
        "::ffff:192.0.2.10 - {user} [22/10/2026:00:{minute:02}:00 +0000] \"GET /api2/json/{minute}\" \
         200 5 -\n"
    )
}

// The path is global to the process, so this runs as one test in its own binary.
#[test]
fn path_setup_and_following() {
    let page = &API_METHOD_GET_ACCESS_LOG;
    assert_eq!(status(call(page, json!({}), "root@pam")), 500);
    let stats = &API_METHOD_GET_ACCESS_LOG_STATS;
    assert_eq!(status(call(stats, json!({}), "root@pam")), 500);

    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("access-log-api-path");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("access.log");
    std::fs::write(&log, line(1, "root@pam")).unwrap();
    init_access_log_api(&log).unwrap();
    assert!(init_access_log_api(dir.join("other.log")).is_err());

    let first = call(page, json!({}), "root@pam").unwrap();
    let head = first["head-cursor"].as_str().unwrap();
    let mut file = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
    for (minute, user) in [(2, "admin@pbs"), (3, "root@pam"), (4, "root@pam")] {
        file.write_all(line(minute, user).as_bytes()).unwrap();
    }
    let newer = call(page, json!({ "after": head }), "root@pam").unwrap();
    assert_eq!(entries(&newer), 3);
    let newer = call(page, json!({ "after": head, "limit": 1 }), "root@pam").unwrap();
    assert_eq!(entries(&newer), 1);
    let filter = json!({ "after": head, "auth-id": "admin@pbs" });
    let newer = call(page, filter, "root@pam").unwrap();
    assert_eq!(entries(&newer), 1);

    // a log that cannot be read is no client error
    std::fs::remove_file(&log).unwrap();
    std::fs::create_dir(&log).unwrap();
    assert_eq!(status(call(page, json!({}), "root@pam")), 500);
}
