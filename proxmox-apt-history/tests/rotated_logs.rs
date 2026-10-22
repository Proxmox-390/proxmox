#![cfg(not(target_arch = "wasm32"))]

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::write::GzEncoder;

use proxmox_apt_history::{HistoryParser, open_log_file, rotated_log_files};

fn test_dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create test directory");
    dir
}

fn entry(date: &str, package: &str) -> String {
    format!("\nStart-Date: {date}\nInstall: {package}:amd64 (1.0)\nEnd-Date: {date}\n")
}

fn write_plain(path: &Path, content: &str) {
    std::fs::write(path, content).expect("write test log");
}

fn write_gz(path: &Path, content: &str) {
    let mut encoder = GzEncoder::new(
        File::create(path).expect("create test log"),
        Compression::default(),
    );
    encoder
        .write_all(content.as_bytes())
        .expect("write test log");
    encoder.finish().expect("finish test log");
}

#[test]
fn read_rotated_history_logs() {
    let dir = test_dir("read_rotated_history_logs");

    write_plain(
        &dir.join("history.log"),
        &entry("2026-10-03  10:00:00", "c"),
    );
    write_plain(
        &dir.join("history.log.1"),
        &entry("2026-09-03  10:00:00", "b"),
    );
    write_gz(
        &dir.join("history.log.2.gz"),
        &entry("2026-08-03  10:00:00", "a"),
    );
    write_gz(
        &dir.join("history.log.10.gz"),
        &entry("2025-12-03  10:00:00", "old"),
    );
    // logrotate compressing `.1` while it gets listed
    write_gz(&dir.join("history.log.1.gz"), "");
    write_plain(&dir.join("history.log.old"), "");
    write_plain(&dir.join("history.log.0"), "");
    write_plain(&dir.join("term.log"), "");

    let files = rotated_log_files(&dir, "history.log").expect("list log files");
    let names: Vec<_> = files
        .iter()
        .map(|path| path.file_name().unwrap().to_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "history.log",
            "history.log.1",
            "history.log.2.gz",
            "history.log.10.gz"
        ]
    );

    let packages: Vec<_> = files
        .iter()
        .flat_map(|path| HistoryParser::new(open_log_file(path).expect("open log file")))
        .map(|entry| entry.expect("valid entry").packages[0].package.clone())
        .collect();
    assert_eq!(packages, ["c", "b", "a", "old"]);
}

#[test]
fn missing_log_directory() {
    let dir = test_dir("missing_log_directory").join("does-not-exist");
    let files = rotated_log_files(&dir, "history.log").expect("list log files");
    assert!(files.is_empty());
}

#[test]
fn dateext_rotated_logs() {
    let dir = test_dir("dateext_rotated_logs");

    for name in [
        "history.log",
        "history.log-20260901.gz",
        "history.log-20261001",
        "history.log-20260801.gz",
        "history.log-latest",
    ] {
        write_plain(&dir.join(name), "");
    }

    let files = rotated_log_files(&dir, "history.log").expect("list log files");
    let names: Vec<_> = files
        .iter()
        .map(|path| path.file_name().unwrap().to_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "history.log",
            "history.log-20261001",
            "history.log-20260901.gz",
            "history.log-20260801.gz"
        ]
    );
}
