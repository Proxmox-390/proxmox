use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use proxmox_deb_changelog::{
    ChangelogEntry, VersionRange, parse_changelog, read_installed_changelog,
};

use crate::changelogs::{ReadError, group_changelogs};
use crate::{PackageAction, PackageChange, TransactionChangelog};

// as for decompressed installed changelogs
const MAX_CHANGELOG_SIZE: u64 = 16 * 1024 * 1024;
const MAX_DOWNLOADS: usize = 6;
// below the 30 second timeout for proxied API requests, so that the result still arrives
const TIMEOUT: Duration = Duration::from_secs(25);
const TIMED_OUT: &str = "Changelog download timed out";
const NOT_STARTED: &str =
    "Changelog download did not start - the time limit for all downloads was reached";

type Entries = Result<Vec<ChangelogEntry>, String>;

/// Downloads the changelogs for pending package changes, grouped and ordered like
/// [`crate::get_transaction_changelogs`]. Upgrades show entries between the installed and candidate
/// version, installs only the newest entry up to the candidate version. The action follows from
/// the versions, as APT also offers a lower candidate version if it is pinned with a priority
/// above 1000. Such downgrades show the entries they revert, from the installed changelog. Download
/// failures are returned in the affected groups, without preventing other changelogs from being
/// shown.
///
/// APT resolves the changelog locations in one invocation. Changelogs sharing a URI are downloaded
/// once, with at most six downloads in parallel, using the proxy and authentication configuration
/// of APT. If resolution is incomplete, packages are fetched separately so failures remain per
/// package. Downloads that do not finish within 25 seconds in total fail and those not started by
/// then are skipped, so that the result stays within the timeout of proxied API requests.
pub fn get_update_changelogs(changes: Vec<PackageChange>) -> Vec<TransactionChangelog> {
    let deadline = Instant::now() + TIMEOUT;
    download_changelogs(
        changes,
        deadline,
        |packages| resolve_locations(packages, deadline),
        |package| apt_changelog(&[package.to_string()], false, deadline).map(|output| output.0),
        |package| match read_installed_changelog(package) {
            Err(proxmox_deb_changelog::Error::NotFound(_)) => Ok(None),
            result => result.map(Some).map_err(|err| err.to_string()),
        },
    )
}

/// Where APT downloads the changelog of a package from, and the source package it names.
struct Location {
    uri: String,
    source: Option<String>,
}

fn pending_change(mut change: PackageChange) -> PackageChange {
    change.old_version = change.old_version.filter(|version| !version.is_empty());
    change.action = match (&change.old_version, &change.new_version) {
        (Some(old), Some(new)) => match VersionRange::new(Some(new), None) {
            Ok(range) if range.contains(old) => PackageAction::Downgrade,
            _ => PackageAction::Upgrade,
        },
        (None, Some(_)) => PackageAction::Install,
        _ => change.action,
    };
    change
}

fn package_spec(change: &PackageChange) -> Result<String, String> {
    let valid_name = |name: &str| {
        name.len() >= 2
            && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+-.".contains(c))
    };
    if !valid_name(&change.package) {
        return Err(format!("Invalid package name '{}'", change.package));
    }
    let mut package = change.package.clone();
    if let Some(arch) = &change.arch {
        if arch.is_empty() || !arch.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!("Invalid package architecture '{arch}'"));
        }
        package.push(':');
        package.push_str(arch);
    }
    let version = change
        .new_version
        .as_deref()
        .ok_or("Missing candidate version")?;
    VersionRange::new(None, Some(version)).map_err(|err| err.to_string())?;
    Ok(format!("{package}={version}"))
}

fn download_changelogs(
    changes: Vec<PackageChange>,
    deadline: Instant,
    resolve: impl FnOnce(&[String]) -> Result<Vec<Location>, String>,
    fetch: impl Fn(&str) -> Result<String, String> + Sync,
    mut read_installed: impl FnMut(&str) -> Result<Option<Vec<ChangelogEntry>>, String>,
) -> Vec<TransactionChangelog> {
    let changes: Vec<_> = changes.into_iter().map(pending_change).collect();
    let mut packages = Vec::new();
    for change in &changes {
        if change.action != PackageAction::Downgrade
            && change.changelog_range().is_some()
            && let Ok(package) = package_spec(change)
            && !packages.contains(&package)
        {
            packages.push(package);
        }
    }
    // APT omits unresolved packages from --print-uris output. Only associate by position if every
    // package resolved, otherwise fetch separately to avoid showing another source's log.
    let locations = if packages.is_empty() {
        Vec::new()
    } else {
        resolve(&packages)
            .ok()
            .filter(|locations| locations.len() == packages.len())
            .unwrap_or_else(|| {
                packages
                    .iter()
                    .map(|package| Location {
                        uri: package.clone(),
                        source: None,
                    })
                    .collect()
            })
    };
    let mut jobs: Vec<(&Location, Vec<&str>)> = Vec::new();
    for (package, location) in packages.iter().zip(&locations) {
        match jobs.iter_mut().find(|(other, _)| other.uri == location.uri) {
            Some((_, packages)) => packages.push(package),
            None => jobs.push((location, vec![package])),
        }
    }
    let downloaded = download_all(&jobs, deadline, &fetch);
    let job_of: HashMap<&str, usize> = jobs
        .iter()
        .enumerate()
        .flat_map(|(index, (_, packages))| packages.iter().map(move |package| (*package, index)))
        .collect();

    group_changelogs(changes, |change| {
        if change.action == PackageAction::Downgrade {
            // the entries to revert are only in the changelog of the installed version
            return Ok(read_installed(&change.package)?.map(Cow::Owned));
        }
        let package = package_spec(change)?;
        let Some(&index) = job_of.get(package.as_str()) else {
            return Ok(None);
        };
        match &downloaded[index] {
            Ok(entries) => Ok(Some(Cow::Borrowed(entries.as_slice()))),
            Err(message) => Err(ReadError {
                source: jobs[index].0.source.clone(),
                message: message.clone(),
            }),
        }
    })
}

/// Downloads the changelogs of the jobs, each for the first of its packages, and returns them in
/// the order of the jobs.
fn download_all(
    jobs: &[(&Location, Vec<&str>)],
    deadline: Instant,
    fetch: &(impl Fn(&str) -> Result<String, String> + Sync),
) -> Vec<Entries> {
    let workers = MAX_DOWNLOADS.min(jobs.len());
    let mut downloaded: Vec<(usize, Entries)> = thread::scope(|scope| {
        let handles: Vec<_> = {
            let _blocked = SignalsBlocked::new();
            (0..workers)
                .map(|worker| {
                    scope.spawn(move || {
                        (worker..jobs.len())
                            .step_by(workers)
                            .map(|index| (index, download(jobs[index].1[0], deadline, fetch)))
                            .collect::<Vec<_>>()
                    })
                })
                .collect()
        };
        handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect()
    });
    downloaded.sort_by_key(|(index, _)| *index);
    downloaded.into_iter().map(|(_, entries)| entries).collect()
}

fn download(
    package: &str,
    deadline: Instant,
    fetch: &impl Fn(&str) -> Result<String, String>,
) -> Entries {
    if Instant::now() >= deadline {
        return Err(NOT_STARTED.to_string());
    }
    let text = fetch(package)?;
    if text.len() as u64 > MAX_CHANGELOG_SIZE {
        return Err("Downloaded changelog is too large".to_string());
    }
    let entries = parse_changelog(&text);
    if entries.is_empty() {
        return Err("Downloaded changelog has no entries".to_string());
    }
    Ok(entries)
}

fn resolve_locations(packages: &[String], deadline: Instant) -> Result<Vec<Location>, String> {
    let (text, success) = apt_changelog(packages, true, deadline)?;
    if !success {
        return Err("could not resolve all changelog locations".to_string());
    }
    text.lines()
        .filter(|line| !line.is_empty())
        .map(parse_location)
        .collect()
}

/// Parses a line of `apt-get changelog --print-uris`, the quoted URI and the name of the file to
/// download to, the source package name with a ".changelog" suffix.
fn parse_location(line: &str) -> Result<Location, String> {
    let (uri, file) = line
        .strip_prefix('\'')
        .and_then(|line| line.split_once("' "))
        .ok_or_else(|| "invalid changelog location from APT".to_string())?;
    Ok(Location {
        uri: uri.to_string(),
        source: file.strip_suffix(".changelog").map(str::to_string),
    })
}

/// Blocks all signals of the calling thread until dropped. Threads spawned meanwhile inherit the
/// mask, so signals get delivered to the thread that called into this crate. An embedding
/// interpreter like Perl can only run its signal handlers there, and crashes if one runs in another
/// thread, for example on SIGCHLD from the downloads. Spawned processes start with an empty mask
/// again.
struct SignalsBlocked(libc::sigset_t);

impl SignalsBlocked {
    fn new() -> Self {
        let mut all = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        let mut previous = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: `sigfillset` initializes the set, and `pthread_sigmask` stores the previous mask
        // of the calling thread, as it cannot fail with these valid arguments.
        unsafe {
            libc::sigfillset(all.as_mut_ptr());
            libc::pthread_sigmask(libc::SIG_BLOCK, all.as_ptr(), previous.as_mut_ptr());
            Self(previous.assume_init())
        }
    }
}

impl Drop for SignalsBlocked {
    fn drop(&mut self) {
        // SAFETY: restores the mask that `new` saved, in the same thread, as the guard is a local.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut()) };
    }
}

fn read_output(reader: impl Read, limit: u64) -> Result<String, String> {
    let mut bytes = Vec::new();
    reader
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| err.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("APT changelog output is too large".to_string());
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Turns the error output of `apt-get changelog` into a short message for admins, without the URL
/// and address details. APT reports the HTTP status after the URL, or for a missing changelog in
/// parentheses after the version.
fn download_error(error: &str, exit_code: Option<i32>) -> String {
    let detail = error
        .lines()
        .find_map(|line| line.strip_prefix("E: Failed to fetch "))
        .and_then(|line| line.split_once(char::is_whitespace))
        .map(|(_, detail)| detail.trim());
    let Some(detail) = detail else {
        return match exit_code {
            Some(code) => format!("Changelog download failed (APT exit code {code})"),
            None => "Changelog download interrupted".to_string(),
        };
    };
    // APT wraps the reasons of changelog downloads in parentheses after the version, also for
    // other failures than a missing changelog
    let (wrapped, detail) = match detail.strip_prefix("Changelog unavailable for ") {
        Some(rest) => (
            true,
            rest.split_once('(')
                .map_or("", |(_, detail)| detail.strip_suffix(')').unwrap_or(detail)),
        ),
        None => (false, detail),
    };
    let status = detail
        .split_whitespace()
        .next()
        .filter(|code| code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()));
    let lower = detail.to_ascii_lowercase();
    match status {
        Some("404") => "Changelog not available from the repository (HTTP 404)".to_string(),
        Some(code) => format!("Changelog download failed (HTTP {code})"),
        None if wrapped && detail.trim().is_empty() => {
            "Changelog not available from the repository".to_string()
        }
        _ if lower.contains("timed out") => TIMED_OUT.to_string(),
        _ if lower.contains("resolving") => {
            "Changelog download failed - could not resolve the repository host".to_string()
        }
        _ if lower.contains("certificate verification failed") => {
            "Changelog download failed - the repository certificate is not trusted".to_string()
        }
        _ => "Changelog download failed".to_string(),
    }
}

fn apt_changelog(
    packages: &[String],
    print_uris: bool,
    deadline: Instant,
) -> Result<(String, bool), String> {
    let mut command = Command::new("apt-get");
    command.args(["changelog", "-qq"]);
    if print_uris {
        command.arg("--print-uris");
    }
    command.args(["--"]).args(packages);
    command
        .env("LC_ALL", "C")
        .env("APT_LISTCHANGES_FRONTEND", "none");
    let (status, output, error) = run(command, deadline)?;
    if !status.success() && !print_uris {
        return Err(download_error(&error, status.code()));
    }
    Ok((output, status.success()))
}

/// Runs the command in its own process group until it exits or the deadline passes, then kills
/// what is left of the group, and returns the exit status, the output and the error output.
fn run(mut command: Command, deadline: Instant) -> Result<(ExitStatus, String, String), String> {
    let mut child = command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("Could not start apt-get changelog - {err}"))?;
    let pid = child.id() as libc::pid_t;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    thread::scope(|scope| {
        let (stdout, stderr) = {
            let _blocked = SignalsBlocked::new();
            (
                scope.spawn(|| read_output(stdout, MAX_CHANGELOG_SIZE)),
                scope.spawn(|| read_output(stderr, 64 * 1024)),
            )
        };
        let exited = loop {
            match has_exited(pid) {
                Ok(false) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                result => break result,
            }
        };
        if exited.is_ok() {
            // SAFETY: the child is not reaped yet, so the process group it leads, as it got spawned
            // with `process_group(0)`, still exists. Also kills APT's acquisition helpers, which
            // could keep the output pipes open after APT exited.
            unsafe { libc::kill(-pid, libc::SIGKILL) };
        }
        let status = child.wait();
        let output = stdout.join().unwrap();
        let error = stderr.join().unwrap();
        match exited {
            Ok(true) => (),
            Ok(false) => return Err(TIMED_OUT.to_string()),
            Err(err) => return Err(format!("Could not wait for apt-get changelog - {err}")),
        }
        let status =
            status.map_err(|err| format!("Could not wait for apt-get changelog - {err}"))?;
        Ok((status, output?, error?))
    })
}

/// Whether the child exited, without reaping it, so that its process ID and group stay reserved.
fn has_exited(pid: libc::pid_t) -> io::Result<bool> {
    // SAFETY: an all-zero `siginfo_t` is valid and `waitid` only writes to it. With `WNOWAIT` the
    // child stays to be reaped by `Child::wait`, with `WNOHANG` `si_pid` stays zero until it exits.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let flags = libc::WEXITED | libc::WNOHANG | libc::WNOWAIT;
        if libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, flags) < 0 {
            let err = io::Error::last_os_error();
            return match err.kind() {
                io::ErrorKind::Interrupted => Ok(false),
                _ => Err(err),
            };
        }
        Ok(info.si_pid() != 0)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn change(package: &str, old: Option<&str>) -> PackageChange {
        PackageChange {
            package: package.to_string(),
            action: PackageAction::Upgrade,
            arch: None,
            old_version: old.map(str::to_string),
            new_version: Some("3".to_string()),
            automatic: false,
        }
    }

    fn text(source: &str) -> String {
        ["3", "2", "1"]
            .into_iter()
            .map(|version| {
                format!("{source} ({version}) stable; urgency=medium\n\n  * Changes.\n\n")
            })
            .collect()
    }

    fn locations(sources: &[&str]) -> Vec<Location> {
        sources
            .iter()
            .map(|source| Location {
                uri: format!("https://example.invalid/{source}"),
                source: Some(source.to_string()),
            })
            .collect()
    }

    fn later() -> Instant {
        Instant::now() + TIMEOUT
    }

    fn no_installed(_: &str) -> Result<Option<Vec<ChangelogEntry>>, String> {
        panic!("only downgrades read the installed changelog")
    }

    #[test]
    fn deduplicate_and_order() {
        let fetched = Mutex::new(Vec::new());
        let groups = download_changelogs(
            vec![
                change("zulu", Some("1")),
                change("foo-bin", Some("1")),
                change("foo-doc", Some("1")),
                change("foo-new", None),
                change("alpha", Some("2")),
                change("broken", Some("1")),
            ],
            later(),
            |packages| {
                assert_eq!(packages.len(), 6);
                Ok(locations(&["zulu", "foo", "foo", "foo", "alpha", "broken"]))
            },
            |package| {
                fetched.lock().unwrap().push(package.to_string());
                match package {
                    "broken=3" => Err("download failed".to_string()),
                    "foo-bin=3" => Ok(text("foo")),
                    _ => Ok(text(package.split_once('=').unwrap().0)),
                }
            },
            no_installed,
        );
        assert_eq!(fetched.lock().unwrap().len(), 4);
        assert_eq!(
            groups
                .iter()
                .map(|group| group.source.as_deref())
                .collect::<Vec<_>>(),
            [
                Some("alpha"),
                Some("broken"),
                Some("foo"),
                Some("zulu"),
                Some("foo")
            ]
        );
        assert_eq!(groups[1].error.as_deref(), Some("download failed"));
        assert_eq!(groups[2].packages.len(), 2);
        assert_eq!(
            groups[2]
                .entries
                .iter()
                .map(|entry| entry.version.as_str())
                .collect::<Vec<_>>(),
            ["3", "2"]
        );
        assert_eq!(groups[0].entries.len(), 1);
        assert_eq!(groups[4].entries.len(), 1);
    }

    #[test]
    fn group_errors_of_the_same_source() {
        let groups = download_changelogs(
            vec![
                change("libbar1", Some("1")),
                change("bar-utils", Some("1")),
                change("other", Some("1")),
            ],
            later(),
            |_| Ok(locations(&["bar", "bar", "other"])),
            |_| Err("Changelog download failed".to_string()),
            no_installed,
        );
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].source.as_deref(), Some("bar"));
        assert_eq!(groups[0].packages.len(), 2);
        assert_eq!(groups[1].source.as_deref(), Some("other"));
    }

    #[test]
    fn downgrades_show_the_reverted_entries_of_the_installed_changelog() {
        let mut pinned = change("pinned", Some("3"));
        pinned.new_version = Some("1".to_string());
        let groups = download_changelogs(
            vec![pinned],
            later(),
            |_| panic!("downgrades need no download"),
            |_| panic!("downgrades need no download"),
            |package| {
                assert_eq!(package, "pinned");
                Ok(Some(parse_changelog(&text("pinned"))))
            },
        );
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].packages[0].action, PackageAction::Downgrade);
        assert_eq!(
            groups[0]
                .entries
                .iter()
                .map(|entry| entry.version.as_str())
                .collect::<Vec<_>>(),
            ["3", "2"]
        );
    }

    #[test]
    fn actions_follow_from_the_versions() {
        let mut install = change("new", Some(""));
        install.action = PackageAction::Upgrade;
        let mut zero = change("zero", Some("0"));
        zero.action = PackageAction::Install;
        let actions: Vec<_> = [install, zero, change("up", Some("2"))]
            .into_iter()
            .map(|change| pending_change(change).action)
            .collect();
        use PackageAction::*;
        assert_eq!(actions, [Install, Upgrade, Upgrade]);
    }

    #[test]
    fn bound_parallel_downloads() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let groups = download_changelogs(
            (0..18).map(|i| change(&format!("pkg{i}"), None)).collect(),
            later(),
            |packages| {
                Ok(packages
                    .iter()
                    .map(|package| Location {
                        uri: package.clone(),
                        source: None,
                    })
                    .collect())
            },
            |_| {
                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(count, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(10));
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(text("source"))
            },
            no_installed,
        );
        assert_eq!(groups[0].packages.len(), 18);
        assert!((2..=MAX_DOWNLOADS).contains(&peak.load(Ordering::SeqCst)));
    }

    #[test]
    fn downloads_stop_at_the_deadline() {
        let groups = download_changelogs(
            vec![change("late", Some("1"))],
            Instant::now(),
            |_| Ok(locations(&["late"])),
            |_| panic!("no download may start after the deadline"),
            no_installed,
        );
        assert_eq!(groups[0].error.as_deref(), Some(NOT_STARTED));
        assert_eq!(groups[0].source.as_deref(), Some("late"));
    }

    #[test]
    fn keep_versions_and_architectures_separate() {
        let mut second = change("binary", Some("1"));
        second.arch = Some("arm64".to_string());
        second.new_version = Some("2".to_string());
        let groups = download_changelogs(
            vec![change("binary", Some("1")), second],
            later(),
            |packages| {
                assert_eq!(packages, ["binary=3", "binary:arm64=2"]);
                Ok(locations(&["source", "source-arm64"]))
            },
            |_| Ok(text("source")),
            no_installed,
        );
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].entries.len(), 2);
        assert_eq!(groups[1].entries.len(), 1);
    }

    #[test]
    fn incomplete_resolution_does_not_misassociate_changelogs() {
        for resolution in [Err("unavailable".to_string()), Ok(locations(&["uri"]))] {
            let groups = download_changelogs(
                vec![change("missing", None), change("valid", Some("1"))],
                later(),
                |_| resolution,
                |package| match package {
                    "valid=3" => Ok(text("valid")),
                    _ => Err("not available".to_string()),
                },
                no_installed,
            );
            assert_eq!(groups[0].source.as_deref(), Some("valid"));
            assert_eq!(groups[1].error.as_deref(), Some("not available"));
        }
    }

    #[test]
    fn reject_invalid_and_oversized_input() {
        let groups = download_changelogs(
            vec![
                change("../invalid", None),
                change("empty", None),
                change("large", None),
            ],
            later(),
            |packages| {
                Ok(locations(
                    &packages.iter().map(String::as_str).collect::<Vec<_>>(),
                ))
            },
            |package| {
                Ok(if package == "large=3" {
                    "x".repeat(MAX_CHANGELOG_SIZE as usize + 1)
                } else {
                    String::new()
                })
            },
            no_installed,
        );
        assert!(groups.iter().all(|group| group.error.is_some()));
        assert!(read_output(&b"12345"[..], 4).is_err());
        assert_eq!(read_output(&b"1234"[..], 4).unwrap(), "1234");
    }

    #[test]
    fn parse_apt_locations() {
        let location = parse_location(
            "'https://metadata.ftp-master.debian.org/changelogs/main/a/apt/apt_3.0.4_changelog' apt.changelog",
        )
        .unwrap();
        assert!(location.uri.ends_with("apt_3.0.4_changelog"));
        assert_eq!(location.source.as_deref(), Some("apt"));
        assert!(parse_location("https://example.invalid/changelog").is_err());
    }

    #[test]
    fn spawned_threads_inherit_blocked_signals() {
        fn blocked(signal: libc::c_int) -> bool {
            let mut mask = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
            // SAFETY: only queries the mask of the calling thread.
            unsafe {
                libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), mask.as_mut_ptr());
                libc::sigismember(mask.as_ptr(), signal) == 1
            }
        }
        let before = blocked(libc::SIGCHLD);
        let spawned = {
            let _blocked = SignalsBlocked::new();
            thread::spawn(|| blocked(libc::SIGCHLD))
        };
        assert!(spawned.join().unwrap());
        assert_eq!(blocked(libc::SIGCHLD), before);
    }

    #[test]
    fn helpers_cannot_keep_the_output_open() {
        let start = Instant::now();
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 30 & echo done"]);
        let (status, output, _) = run(command, Instant::now() + Duration::from_secs(10)).unwrap();
        assert!(status.success());
        assert_eq!(output, "done\n");
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn commands_stop_at_the_deadline() {
        let start = Instant::now();
        let mut command = Command::new("sleep");
        command.arg("30");
        let result = run(command, Instant::now() + Duration::from_millis(200));
        assert_eq!(result.unwrap_err(), TIMED_OUT);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    #[ignore = "downloads a changelog from the configured APT repositories"]
    fn real_download() {
        let version = Command::new("dpkg-query")
            .args(["-W", "-f=${Version}", "bash"])
            .output()
            .unwrap();
        assert!(version.status.success());
        let mut package = change("bash", None);
        package.new_version = Some(String::from_utf8(version.stdout).unwrap());
        let groups = get_update_changelogs(vec![package]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].error, None, "{groups:?}");
        assert_eq!(groups[0].source.as_deref(), Some("bash"));
        assert_eq!(groups[0].entries.len(), 1);
    }

    #[test]
    fn readable_download_errors() {
        for (error, expected) in [
            (
                "E: Failed to fetch https://metadata.ftp-master.debian.org/changelogs/main/n/nss/nss_3.110-1+deb13u5_changelog  Changelog unavailable for nss=2:3.110-1+deb13u5 (404  Not Found [IP: 146.75.122.132 443])",
                "Changelog not available from the repository (HTTP 404)",
            ),
            (
                "E: Failed to fetch https://enterprise.proxmox.com/changelog  401  Unauthorized [IP: 51.91.38.34 443]",
                "Changelog download failed (HTTP 401)",
            ),
            (
                "E: Failed to fetch https://example.invalid/changelog  503  Service Unavailable [IP: 192.0.2.1 443]",
                "Changelog download failed (HTTP 503)",
            ),
            (
                "E: Failed to fetch https://example.invalid/changelog  Temporary failure resolving 'example.invalid'",
                "Changelog download failed - could not resolve the repository host",
            ),
            (
                "E: Failed to fetch https://example.invalid/changelog  Could not connect to example.invalid:443 (192.0.2.1), connection timed out",
                "Changelog download timed out",
            ),
            (
                "E: Failed to fetch https://example.invalid/changelog  Certificate verification failed: The certificate is NOT trusted. [IP: 192.0.2.1 443]",
                "Changelog download failed - the repository certificate is not trusted",
            ),
            (
                "E: Failed to fetch changelog:/foo  Changelog unavailable for foo=1",
                "Changelog not available from the repository",
            ),
            (
                "E: Failed to fetch https://example.invalid/changelog  Changelog unavailable for \
                 foo=1 (401  Unauthorized [IP: 192.0.2.1 443])",
                "Changelog download failed (HTTP 401)",
            ),
            (
                "unexpected output\nwith private details",
                "Changelog download failed (APT exit code 100)",
            ),
            ("", "Changelog download failed (APT exit code 100)"),
        ] {
            assert_eq!(download_error(error, Some(100)), expected);
        }
        assert_eq!(download_error("", None), "Changelog download interrupted");
    }

    #[test]
    fn empty_updates_do_not_invoke_apt() {
        assert!(
            download_changelogs(
                Vec::new(),
                later(),
                |_| panic!(),
                |_| panic!(),
                no_installed
            )
            .is_empty()
        );
    }
}
