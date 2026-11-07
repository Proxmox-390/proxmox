use std::path::Path;
use std::sync::Once;

use anyhow::Error;
use serde_json::{Value, json};

use proxmox_access_log::{
    API_METHOD_GET_ACCESS_LOG, API_METHOD_GET_ACCESS_LOG_STATS, MAX_STATS_TOP, init_access_log_api,
};
use proxmox_router::{ApiMethod, Permission};

mod common;
use common::{entries, status};

/// 2026-10-22 00:00:00 UTC
const BASE_TIME: i64 = 1792627200;

const LOG: &str = "\
::ffff:192.0.2.10 - root@pam [22/10/2026:00:01:00 +0000] \"GET /api2/json/a?password=secret\" 200 5 -
::ffff:192.0.2.11 - admin@pbs [22/10/2026:00:02:00 +0000] \"GET /api2/json/b\" 403 5 -
";

fn call(method: &'static ApiMethod, params: Value, auth_id: &str) -> Result<Value, Error> {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("access-log-api");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("access.log"), LOG).unwrap();
        init_access_log_api(dir.join("access.log")).unwrap();
    });
    common::call(method, params, auth_id)
}

fn uris(page: &Value) -> Vec<&str> {
    let entries = page["entries"].as_array().unwrap();
    entries.iter().map(|e| e["uri"].as_str().unwrap()).collect()
}

#[test]
fn query_values_only_for_root_pam() {
    let page = call(&API_METHOD_GET_ACCESS_LOG, json!({}), "root@pam").unwrap();
    assert_eq!(
        uris(&page),
        ["/api2/json/b", "/api2/json/a?password=secret"]
    );

    for auth_id in ["admin@pbs", "root@pam!token", "root@pbs"] {
        let page = call(&API_METHOD_GET_ACCESS_LOG, json!({}), auth_id).unwrap();
        let uris = uris(&page);
        assert_eq!(uris.len(), 2);
        assert!(!uris[1].contains("secret"), "{auth_id}: {}", uris[1]);
    }
}

#[test]
fn paging_and_filters() {
    let page = call(
        &API_METHOD_GET_ACCESS_LOG,
        json!({ "limit": 1 }),
        "root@pam",
    )
    .unwrap();
    assert_eq!(uris(&page), ["/api2/json/b"]);
    let cursor = page["next-cursor"].as_str().unwrap();
    let head = page["head-cursor"].as_str().unwrap();

    let next = json!({ "cursor": cursor });
    let page = call(&API_METHOD_GET_ACCESS_LOG, next, "root@pam").unwrap();
    assert_eq!(uris(&page), ["/api2/json/a?password=secret"]);

    let filter = json!({ "auth-id": "admin@pbs" });
    let page = call(&API_METHOD_GET_ACCESS_LOG, filter, "root@pam").unwrap();
    assert_eq!(uris(&page), ["/api2/json/b"]);

    let following = json!({ "after": head });
    let page = call(&API_METHOD_GET_ACCESS_LOG, following, "root@pam").unwrap();
    assert_eq!(entries(&page), 0);

    let both = json!({ "cursor": cursor, "after": head });
    assert_eq!(
        status(call(&API_METHOD_GET_ACCESS_LOG, both, "root@pam")),
        400
    );
}

#[test]
fn request_errors() {
    let cursor = json!({ "cursor": "bad" });
    assert_eq!(
        status(call(&API_METHOD_GET_ACCESS_LOG, cursor, "root@pam")),
        400
    );
    let after = json!({ "after": "bad" });
    assert_eq!(
        status(call(&API_METHOD_GET_ACCESS_LOG, after, "root@pam")),
        400
    );

    let range = json!({ "since": 1, "until": 0 });
    assert_eq!(
        status(call(&API_METHOD_GET_ACCESS_LOG_STATS, range, "root@pam")),
        400
    );
}

#[test]
fn statistics() {
    let range = json!({ "since": BASE_TIME, "until": BASE_TIME + 3600 });
    let stats = call(&API_METHOD_GET_ACCESS_LOG_STATS, range, "admin@pbs").unwrap();
    assert_eq!(stats["total"]["requests"], 2);
    assert_eq!(stats["total"]["client-errors"], 1);
    assert_eq!(stats["auth-ids"]["rows"].as_array().unwrap().len(), 2);

    let options = json!({ "since": BASE_TIME, "until": BASE_TIME + 3600, "top": 1, "bucket": 600 });
    let stats = call(&API_METHOD_GET_ACCESS_LOG_STATS, options, "admin@pbs").unwrap();
    assert_eq!(stats["auth-ids"]["rows"].as_array().unwrap().len(), 1);
    assert_eq!(stats["histogram"]["bucket"], 600);

    let filter = json!({ "since": BASE_TIME, "until": BASE_TIME + 3600, "min-status": 400 });
    let stats = call(&API_METHOD_GET_ACCESS_LOG_STATS, filter, "admin@pbs").unwrap();
    assert_eq!(stats["total"]["requests"], 1);
}

#[test]
fn parameter_schemas() {
    let parse = |method: &ApiMethod, params: &[(&str, &str)]| {
        let params: Vec<(String, String)> = params
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        method.parameters.parse_parameter_strings(&params, true)
    };

    let node = ("node", "localhost");
    let page = parse(&API_METHOD_GET_ACCESS_LOG, &[node, ("limit", "1")]).unwrap();
    assert_eq!(page["limit"], 1);
    assert!(parse(&API_METHOD_GET_ACCESS_LOG, &[("limit", "1")]).is_err());

    let stats = &API_METHOD_GET_ACCESS_LOG_STATS;
    let max_top = MAX_STATS_TOP.to_string();
    let over_top = (MAX_STATS_TOP + 1).to_string();
    assert!(parse(stats, &[node]).is_ok());
    assert!(parse(stats, &[node, ("limit", "1")]).is_err());
    assert!(parse(stats, &[node, ("top", "0")]).is_err());
    assert!(parse(stats, &[node, ("top", &max_top)]).is_ok());
    assert!(parse(stats, &[node, ("top", &over_top)]).is_err());
    assert!(parse(stats, &[node, ("bucket", "0")]).is_err());
}

#[test]
fn superuser_only_without_product_permission() {
    for method in [&API_METHOD_GET_ACCESS_LOG, &API_METHOD_GET_ACCESS_LOG_STATS] {
        assert!(matches!(method.access.permission, Permission::Superuser));
        assert!(!method.protected);
    }
}
