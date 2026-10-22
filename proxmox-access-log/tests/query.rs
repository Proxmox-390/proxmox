use std::io::Write;
use std::path::{Path, PathBuf};

use proxmox_access_log::{
    AccessLogFilter, InvalidRequest, LogFormat, QueryResult, log_files, query,
};

/// 2026-10-22 00:00:00 UTC
const BASE_TIME: i64 = 1792627200;

fn line(minute: i64) -> String {
    format!(
        "::ffff:192.0.2.10 - root@pam!t [22/10/2026:00:{minute:02}:00 +0000] \
         \"GET /api2/json/nodes/{minute}\" 200 5 -\n"
    )
}

fn lines(minutes: impl IntoIterator<Item = i64>) -> String {
    minutes.into_iter().map(line).collect()
}

fn gzip(data: &str) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data.as_bytes()).unwrap();
    encoder.finish().unwrap()
}

/// Creates a log rotated three times, holding one entry per minute from 1 to 11 and an invalid
/// line in two of its files, besides unrelated files with similar names.
fn rotated_log(test: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("access-log-query-{test}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let write = |name: &str, data: &[u8]| std::fs::write(dir.join(name), data).unwrap();
    write("access.log", lines(10..=11).as_bytes());
    write("access.log.1", (lines(7..=9) + "invalid\n").as_bytes());
    write("access.log.2", lines(4..=6).as_bytes());
    // an incomplete copy, as it exists while logrotate compresses the file
    write("access.log.2.gz", &gzip(&line(4)[..20]));
    write(
        "access.log.3.zst",
        &zstd::encode_all(("invalid\n".to_string() + &lines(1..=3)).as_bytes(), 0).unwrap(),
    );
    for unrelated in [
        "access.log.old",
        "access.log.1.bak",
        "access.log.0",
        "access.log.01",
        "access.logx",
        "other.log",
    ] {
        write(unrelated, line(0).as_bytes());
    }

    dir.join("access.log")
}

fn minutes(result: &QueryResult) -> Vec<i64> {
    result
        .entries
        .iter()
        .map(|entry| (entry.time - BASE_TIME) / 60)
        .collect()
}

fn query_log(path: &Path, filter: AccessLogFilter, limit: Option<u64>) -> QueryResult {
    query(path, LogFormat::RestServer, &filter, limit, None).unwrap()
}

#[test]
fn rotated_files() {
    let path = rotated_log("files");
    let names: Vec<_> = log_files(&path)
        .unwrap()
        .into_iter()
        .map(|file| file.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        [
            "access.log",
            "access.log.1",
            "access.log.2",
            "access.log.3.zst"
        ]
    );
}

#[test]
fn log_order() {
    let path = rotated_log("log-order");

    let result = query_log(&path, AccessLogFilter::default(), None);
    assert_eq!(minutes(&result), (1..=11).rev().collect::<Vec<_>>());
    assert!(result.complete);
    assert_eq!(result.next_cursor, None);
    assert_eq!(result.searched_back_to, Some(BASE_TIME + 60));
    assert_eq!(result.invalid_lines, 2);
    assert_eq!(
        result.entries[0].uri.as_deref(),
        Some("/api2/json/nodes/11")
    );

    let filter = AccessLogFilter::default();
    let result = query_log(&path, filter.clone(), Some(4));
    assert_eq!(minutes(&result), [11, 10, 9, 8]);
    assert!(!result.complete);
    assert_eq!(result.searched_back_to, Some(BASE_TIME + 8 * 60));
    assert_eq!(result.invalid_lines, 1);

    let cursor = result.next_cursor.unwrap();
    let result = query(
        &path,
        LogFormat::RestServer,
        &filter,
        Some(4),
        Some(&cursor),
    )
    .unwrap();
    assert_eq!(minutes(&result), [7, 6, 5, 4]);
    let cursor = result.next_cursor.unwrap();
    let result = query(
        &path,
        LogFormat::RestServer,
        &filter,
        Some(4),
        Some(&cursor),
    )
    .unwrap();
    assert_eq!(minutes(&result), [3, 2, 1]);
    assert_eq!(result.invalid_lines, 1);
    assert!(result.complete);
    assert_eq!(result.next_cursor, None);

    let other = rotated_log("log-order-other");
    for (name, content) in [
        ("log", lines([30, 31])),
        ("log.1", lines([20, 21])),
        ("log.2", lines([15, 16])),
    ] {
        std::fs::write(other.with_extension(name), content).unwrap();
    }
    std::fs::remove_file(other.with_extension("log.3.zst")).unwrap();
    let error = query(
        &other,
        LogFormat::RestServer,
        &filter,
        Some(4),
        Some(&cursor),
    )
    .unwrap_err();
    assert!(error.to_string().contains("rotated away"), "{error}");
    assert!(error.is::<InvalidRequest>());
}

#[test]
fn time_range() {
    let path = rotated_log("time-range");

    let result = query_log(
        &path,
        AccessLogFilter {
            since: Some(BASE_TIME + 5 * 60),
            until: Some(BASE_TIME + 9 * 60),
            ..Default::default()
        },
        None,
    );
    assert_eq!(minutes(&result), [9, 8, 7, 6, 5]);
    assert!(result.complete);
    assert_eq!(result.invalid_lines, 2);
    assert_eq!(result.searched_back_to, Some(BASE_TIME + 60));
}

#[test]
fn overlapping_files() {
    let path = rotated_log("overlapping");
    let dir = path.parent().unwrap();
    // an older copy written to after rotation, like by a daemon that missed reopening the log
    std::fs::write(dir.join("access.log.2"), lines([4, 5, 6, 12])).unwrap();

    let result = query_log(&path, AccessLogFilter::default(), None);
    assert_eq!(minutes(&result), [11, 10, 9, 8, 7, 12, 6, 5, 4, 3, 2, 1]);
    assert!(result.complete);
}

#[test]
fn filtered() {
    let path = rotated_log("filtered");
    let result = query_log(
        &path,
        AccessLogFilter {
            auth_id: Some("root@pam".to_string()),
            path: Some("/nodes/1".to_string()),
            ..Default::default()
        },
        None,
    );
    assert_eq!(minutes(&result), [11, 10, 1]);
}

#[test]
fn limit_range() {
    let path = rotated_log("limit-range");
    let filter = AccessLogFilter::default();
    for limit in [0, proxmox_access_log::MAX_LIMIT + 1] {
        let error = query(&path, LogFormat::RestServer, &filter, Some(limit), None).unwrap_err();
        assert!(error.is::<InvalidRequest>(), "{limit}");
    }
}

#[test]
fn relative_path() {
    let path = rotated_log("relative-path");
    let names = |path: &Path| -> Vec<PathBuf> {
        log_files(path)
            .unwrap()
            .into_iter()
            .map(|file| PathBuf::from(file.file_name().unwrap()))
            .collect()
    };
    let expected = names(&path);

    std::env::set_current_dir(path.parent().unwrap()).unwrap();
    assert_eq!(names(Path::new("access.log")), expected);
}

#[test]
fn special_files_refused() {
    use std::os::unix::ffi::OsStrExt;

    let path = rotated_log("special");
    let copy = path.with_extension("log.4");
    let query_error = || {
        let error = query(
            &path,
            LogFormat::RestServer,
            &AccessLogFilter::default(),
            None,
            None,
        )
        .unwrap_err();
        assert!(!error.is::<InvalidRequest>(), "{error}");
        error.to_string()
    };

    // also a dangling one, which must not look like a file vanishing in a rotation
    for target in ["/etc/hostname", "/nonexistent"] {
        std::os::unix::fs::symlink(target, &copy).unwrap();
        let error = query_error();
        assert!(error.contains("access.log.4"), "{error}");
        std::fs::remove_file(&copy).unwrap();
    }

    // opening a FIFO would block until someone writes to it
    let fifo = std::ffi::CString::new(copy.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let error = query_error();
    assert!(error.contains("not a regular file"), "{error}");
}

#[test]
fn missing_log() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("access-log-query-missing");
    let result = query_log(&dir.join("access.log"), AccessLogFilter::default(), None);
    assert_eq!(
        result,
        QueryResult {
            complete: true,
            ..Default::default()
        }
    );
}
