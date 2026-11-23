use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::Serialize;

use proxmox_deb_changelog::{
    ChangelogEntry, VersionRange, parse_changelog, read_installed_changelog,
};

use crate::changelogs::{ReadError, group_changelogs};
use crate::{PackageAction, PackageChange, TransactionChangelog};

// as for decompressed installed changelogs
const MAX_CHANGELOG_SIZE: u64 = 16 * 1024 * 1024;
// below the 30 second timeout for proxied API requests, so that the result still arrives
const TIMEOUT: Duration = Duration::from_secs(25);
const PREFETCH_TIMEOUT: Duration = Duration::from_secs(10 * 60);
// bounds the downloads a run keeps in /tmp, often a tmpfs, and the memory to read them
const MAX_BATCH: usize = 32;
// what the downloads of a run may take in /tmp, as APT does not limit the size of a changelog
const MAX_ROUND_SIZE: u64 = 4 * MAX_CHANGELOG_SIZE;
const TOO_LARGE: &str = "Downloaded changelog is too large";
const RECENT_USE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const TIMED_OUT: &str = "Changelog download timed out";
const NOT_STARTED: &str = "Changelog download did not start before the time limit - load the changelogs again to continue";
const NOT_IN_LISTS: &str = "Package version not found in the package lists - refresh the updates";
const NOT_AVAILABLE: &str = "Changelog not available from the repository";

type Entries = Result<Vec<ChangelogEntry>, String>;

/// Downloads the changelogs for pending package changes, grouped and ordered like
/// [`crate::get_transaction_changelogs`]. Upgrades show entries between the installed and candidate
/// version, installs only the newest entry up to the candidate version. The action follows from
/// the versions, as APT also offers a lower candidate version if it is pinned with a priority
/// above 1000. Such downgrades show the entries they revert, from the installed changelog. Download
/// failures are returned in the affected groups, without preventing other changelogs from being
/// shown.
///
/// APT resolves the changelog locations and downloads all changelogs not in `cache_dir` in one run,
/// which reuses the connections to each repository and applies the proxy and authentication
/// configuration of APT. Changelogs sharing a URI are downloaded once. Downloads that do not finish
/// within 25 seconds in total fail and those not started by then are skipped, so that the result
/// stays within the timeout of proxied API requests. As the changelog of a version does not change,
/// downloaded ones are kept in `cache_dir`, so that a following request continues where this one
/// stopped. It starts the downloads that did not finish in time last, so that a large changelog on
/// a slow link does not hold up the others. The cache only keeps the changelogs of the pending
/// updates of the latest request.
pub fn get_update_changelogs(
    changes: Vec<PackageChange>,
    cache_dir: &Path,
) -> Vec<TransactionChangelog> {
    let deadline = Instant::now() + TIMEOUT;
    let cache = Cache::open(cache_dir);
    if let Some(cache) = &cache {
        cache.mark_used();
    }
    download_changelogs(
        changes,
        deadline,
        cache.as_ref(),
        |packages| resolve_locations(packages, deadline),
        |jobs| apt_download(jobs, deadline),
        |package| match read_installed_changelog(package) {
            Err(proxmox_deb_changelog::Error::NotFound(_)) => Ok(None),
            result => result.map(Some).map_err(|err| err.to_string()),
        },
    )
}

/// What [`prefetch_update_changelogs`] did.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct PrefetchSummary {
    /// How many changelogs got downloaded into the cache.
    pub downloaded: usize,
    /// How many changelogs could not be downloaded or stored, apart from those that the repository
    /// does not provide.
    pub failed: usize,
    /// Why the first of them failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Downloads the changelogs of pending package changes into `cache_dir` ahead of a request by
/// [`get_update_changelogs`], for example after refreshing the package lists, so that a request
/// can answer from the cache. Only does so if the changelogs of pending updates were requested
/// within the last 30 days, otherwise it empties the cache, to not download changelogs that nobody
/// looks at. Returns `None` if it did not run.
pub fn prefetch_update_changelogs(
    changes: Vec<PackageChange>,
    cache_dir: &Path,
) -> Result<Option<PrefetchSummary>, String> {
    let deadline = Instant::now() + PREFETCH_TIMEOUT;
    let cache = Cache::open(cache_dir)
        .ok_or_else(|| format!("Could not open the changelog cache {cache_dir:?}"))?;
    if !cache.used_recently() {
        cache.prune(&HashSet::new());
        return Ok(None);
    }
    Ok(Some(prefetch(
        changes,
        deadline,
        &cache,
        |packages| resolve_locations(packages, deadline),
        |jobs| apt_download(jobs, deadline),
    )))
}

fn prefetch(
    changes: Vec<PackageChange>,
    deadline: Instant,
    cache: &Cache,
    resolve: impl FnOnce(&[String]) -> Vec<Result<Location, String>>,
    download: impl FnMut(&[&Job]) -> Vec<Download>,
) -> PrefetchSummary {
    let packages = download_packages(&pending_changes(changes));
    let fetched = fetch_changelogs(&packages, deadline, Some(cache), resolve, download);
    let mut summary = PrefetchSummary {
        downloaded: fetched.stored,
        ..Default::default()
    };
    let errors = fetched.job_of.values().filter_map(|job| job.as_ref().err());
    let errors = errors.chain(
        fetched
            .entries
            .iter()
            .filter_map(|entries| entries.as_ref().err()),
    );
    for error in errors.filter(|error| !error.starts_with(NOT_AVAILABLE)) {
        summary.failed += 1;
        summary.error.get_or_insert_with(|| error.clone());
    }
    let unstored = fetched.downloaded - fetched.stored;
    if unstored > 0 {
        summary.failed += unstored;
        summary
            .error
            .get_or_insert_with(|| "Could not store a changelog in the cache".to_string());
    }
    summary
}

/// Where APT downloads the changelog of a package from, and the file it names it, the source
/// package name with a ".changelog" suffix.
#[derive(Clone, Debug, PartialEq)]
struct Location {
    uri: String,
    file: String,
}

impl Location {
    fn source(&self) -> Option<&str> {
        self.file.strip_suffix(".changelog")
    }
}

/// A changelog to download, for the first of the packages sharing its location.
#[derive(Debug)]
struct Job {
    location: Location,
    package: String,
}

/// How the download of a changelog in a round ended.
#[derive(Debug)]
enum Download {
    Done(String),
    Failed(String),
    /// Stopped as another download of the round got too large, to try again in the next round.
    Retry,
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

fn pending_changes(changes: Vec<PackageChange>) -> Vec<PackageChange> {
    changes.into_iter().map(pending_change).collect()
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

/// The packages whose changelog needs a download, as `name[:arch]=version`.
fn download_packages(changes: &[PackageChange]) -> Vec<String> {
    let mut packages = Vec::new();
    for change in changes {
        if change.action != PackageAction::Downgrade
            && change.changelog_range().is_some()
            && let Ok(package) = package_spec(change)
            && !packages.contains(&package)
        {
            packages.push(package);
        }
    }
    packages
}

fn download_changelogs(
    changes: Vec<PackageChange>,
    deadline: Instant,
    cache: Option<&Cache>,
    resolve: impl FnOnce(&[String]) -> Vec<Result<Location, String>>,
    download: impl FnMut(&[&Job]) -> Vec<Download>,
    mut read_installed: impl FnMut(&str) -> Result<Option<Vec<ChangelogEntry>>, String>,
) -> Vec<TransactionChangelog> {
    let changes = pending_changes(changes);
    let packages = download_packages(&changes);
    let fetched = fetch_changelogs(&packages, deadline, cache, resolve, download);

    group_changelogs(changes, |change| {
        if change.action == PackageAction::Downgrade {
            // the entries to revert are only in the changelog of the installed version
            return Ok(read_installed(&change.package)?.map(Cow::Owned));
        }
        let package = package_spec(change)?;
        let index = match fetched.job_of.get(&package) {
            None => return Ok(None),
            Some(Err(message)) => return Err(ReadError::from(message.clone())),
            Some(Ok(index)) => *index,
        };
        match &fetched.entries[index] {
            Ok(entries) => Ok(Some(Cow::Borrowed(entries.as_slice()))),
            Err(message) => Err(ReadError {
                source: fetched.jobs[index].location.source().map(str::to_string),
                message: message.clone(),
            }),
        }
    })
}

/// The changelogs of the jobs, in their order, and for each package its job or why it has none.
struct Fetched {
    jobs: Vec<Job>,
    job_of: HashMap<String, Result<usize, String>>,
    entries: Vec<Entries>,
    downloaded: usize,
    stored: usize,
}

/// Resolves the changelog locations of the packages and takes the changelogs from the cache, or
/// downloads them in rounds of limited size in which each file name occurs once, as APT names the
/// downloads after the source package. Updates the cache to hold exactly the changelogs of these
/// packages, if the locations of all of them could be resolved.
fn fetch_changelogs(
    packages: &[String],
    deadline: Instant,
    cache: Option<&Cache>,
    resolve: impl FnOnce(&[String]) -> Vec<Result<Location, String>>,
    mut download: impl FnMut(&[&Job]) -> Vec<Download>,
) -> Fetched {
    let locations = if packages.is_empty() {
        Vec::new()
    } else {
        resolve(packages)
    };
    // after a failed resolution, like at the time limit, the cache may still hold the changelogs
    // that the next request needs
    let resolved = locations.iter().all(|location| match location {
        Ok(_) => true,
        Err(err) => err == NOT_IN_LISTS || err.starts_with(NOT_AVAILABLE),
    });
    let mut jobs: Vec<Job> = Vec::new();
    let mut job_of = HashMap::new();
    for (package, location) in packages.iter().zip(locations) {
        let index = location.map(|location| {
            jobs.iter()
                .position(|job| job.location.uri == location.uri)
                .unwrap_or_else(|| {
                    jobs.push(Job {
                        location,
                        package: package.clone(),
                    });
                    jobs.len() - 1
                })
        });
        job_of.insert(package.clone(), index);
    }

    let mut entries: Vec<Option<Entries>> = jobs
        .iter()
        .map(|job| {
            let text = cache?.get(&job.location.uri)?;
            parse_download(Ok(text)).ok().map(Ok)
        })
        .collect();
    let mut missing: Vec<usize> = (0..jobs.len()).filter(|&i| entries[i].is_none()).collect();
    // downloads that did not finish in time before go last, so that they do not hold up others on
    // the same connection, the one that did so most recently at the end
    if let Some(cache) = cache {
        missing.sort_by_key(|&index| cache.slow_since(&jobs[index].location.uri));
    }
    let mut downloaded = 0;
    let mut stored = 0;
    while !missing.is_empty() {
        if Instant::now() >= deadline {
            for index in missing {
                entries[index] = Some(Err(NOT_STARTED.to_string()));
            }
            break;
        }
        let mut files = HashSet::new();
        let (mut round, mut rest): (Vec<usize>, Vec<usize>) = missing
            .iter()
            .partition(|&&index| files.insert(jobs[index].location.file.as_str()));
        if round.len() > MAX_BATCH {
            rest.splice(0..0, round.drain(MAX_BATCH..));
        }
        let round_jobs: Vec<&Job> = round.iter().map(|&index| &jobs[index]).collect();
        let mut results = download(&round_jobs).into_iter();
        let mut retry = Vec::new();
        for index in round {
            let result = results
                .next()
                .unwrap_or_else(|| Download::Failed("Changelog download failed".to_string()));
            let parsed = match result {
                Download::Done(text) => parse_download(Ok(&text)).inspect(|_| {
                    downloaded += 1;
                    if cache.is_some_and(|cache| cache.put(&jobs[index].location.uri, &text)) {
                        stored += 1;
                    }
                }),
                Download::Failed(err) => {
                    if err == TIMED_OUT
                        && let Some(cache) = cache
                    {
                        cache.mark_slow(&jobs[index].location.uri);
                    }
                    Err(err)
                }
                Download::Retry => {
                    retry.push(index);
                    continue;
                }
            };
            entries[index] = Some(parsed);
        }
        retry.append(&mut rest);
        missing = retry;
    }
    if let Some(cache) = cache
        && resolved
    {
        cache.prune(&jobs.iter().map(|job| job.location.uri.as_str()).collect());
    }
    Fetched {
        jobs,
        job_of,
        entries: entries.into_iter().map(Option::unwrap).collect(),
        downloaded,
        stored,
    }
}

fn parse_download(text: Result<impl AsRef<str>, String>) -> Entries {
    let text = text?;
    if text.as_ref().len() as u64 > MAX_CHANGELOG_SIZE {
        return Err(TOO_LARGE.to_string());
    }
    let entries = parse_changelog(text.as_ref());
    if entries.is_empty() {
        return Err("Downloaded changelog has no entries".to_string());
    }
    Ok(entries)
}

/// Resolves the changelog locations of all packages with one APT invocation. APT reports the
/// packages it cannot resolve separately and leaves them out of the locations, so these get
/// associated by position only if every failure names its package. Otherwise each package is
/// resolved on its own, to never show the changelog of another source.
fn resolve_locations(packages: &[String], deadline: Instant) -> Vec<Result<Location, String>> {
    let output = match apt_get(&["changelog", "--print-uris", "-qq"], packages, deadline) {
        Ok(output) if output.status.is_some() => output,
        Ok(_) => return vec![Err(NOT_STARTED.to_string()); packages.len()],
        Err(err) => return vec![Err(err); packages.len()],
    };
    associate_locations(packages, &output.stdout, &output.stderr).unwrap_or_else(|| {
        packages
            .iter()
            .map(|package| {
                if Instant::now() >= deadline {
                    return Err(NOT_STARTED.to_string());
                }
                let output = apt_get(
                    &["changelog", "--print-uris", "-qq"],
                    std::slice::from_ref(package),
                    deadline,
                )?;
                resolved_location(package, &output)
            })
            .collect()
    })
}

/// The location of a package resolved on its own, or why there is none. Failures that name no
/// package, like a broken APT configuration, are no definite answer about the package.
fn resolved_location(package: &String, output: &Output) -> Result<Location, String> {
    let associated = associate_locations(
        std::slice::from_ref(package),
        &output.stdout,
        &output.stderr,
    );
    match (output.status, associated) {
        (None, _) => Err(TIMED_OUT.to_string()),
        (Some(status), Some(mut locations)) if status.success() || locations[0].is_err() => {
            locations.remove(0)
        }
        _ => {
            let error = output
                .stderr
                .lines()
                .find_map(|line| line.strip_prefix("E: "));
            Err(match error {
                Some(error) => format!("Could not resolve the changelog location - {error}"),
                None => "Could not resolve the changelog location".to_string(),
            })
        }
    }
}

/// Associates the output of `apt-get changelog --print-uris` with the packages, if every package
/// either has a location or an error naming it.
fn associate_locations(
    packages: &[String],
    output: &str,
    error: &str,
) -> Option<Vec<Result<Location, String>>> {
    let locations: Vec<Location> = output
        .lines()
        .filter(|line| !line.is_empty())
        .map(parse_location)
        .collect::<Result<_, _>>()
        .ok()?;
    // APT leaves out the native architecture in its messages, so a name without one matches the
    // package of any architecture, if only one does
    let find = |name: &str, version: Option<&str>| {
        let mut found = packages.iter().enumerate().filter(|(_, package)| {
            let (spec, spec_version) = package.split_once('=').unwrap_or((package, ""));
            let base = spec.split_once(':').map_or(spec, |(base, _)| base);
            (spec == name || base == name) && version.is_none_or(|version| version == spec_version)
        });
        let (index, _) = found.next()?;
        found.next().is_none().then_some(index)
    };
    let mut failed = HashMap::new();
    for line in error.lines() {
        let Some(message) = line.strip_prefix("E: ") else {
            continue;
        };
        let (package, error) = if let Some(name) = message.strip_prefix("Unable to locate package ")
        {
            (find(name, None), NOT_IN_LISTS)
        } else if let Some(spec) = message.strip_prefix("Changelog unavailable for ") {
            // the repository names no changelog location, like most of those of third parties;
            // for downloads, APT appends the reason after a space, which versions do not contain
            let spec = spec.split_once(' ').map_or(spec, |(spec, _)| spec);
            let (name, version) = spec.split_once('=')?;
            (find(name, Some(version)), NOT_AVAILABLE)
        } else {
            let (version, name) = message
                .strip_prefix("Version '")?
                .strip_suffix("' was not found")?
                .split_once("' for '")?;
            (find(name, Some(version)), NOT_IN_LISTS)
        };
        failed.insert(package?, error);
    }
    if locations.len() + failed.len() != packages.len() {
        return None;
    }
    let mut locations = locations.into_iter();
    Some(
        (0..packages.len())
            .map(|index| match failed.get(&index) {
                Some(error) => Err(error.to_string()),
                None => Ok(locations.next().unwrap()),
            })
            .collect(),
    )
}

/// Parses a line of `apt-get changelog --print-uris`, the quoted URI and the name of the file to
/// download to.
fn parse_location(line: &str) -> Result<Location, String> {
    let (uri, file) = line
        .strip_prefix('\'')
        .and_then(|line| line.split_once("' "))
        .filter(|(_, file)| {
            file.ends_with(".changelog") && !file.starts_with('.') && !file.contains('/')
        })
        .ok_or_else(|| "invalid changelog location from APT".to_string())?;
    Ok(Location {
        uri: uri.to_string(),
        file: file.to_string(),
    })
}

/// Downloads the changelogs of the jobs, whose file names must differ, with one APT run into a
/// private directory, and returns them in the order of the jobs. Stops the run if a changelog or
/// all together get too large, and leaves the downloads of the run that did not cause it to retry.
fn apt_download(jobs: &[&Job], deadline: Instant) -> Vec<Download> {
    let failed = |message: String| {
        jobs.iter()
            .map(|_| Download::Failed(message.clone()))
            .collect()
    };
    let work = match WorkDir::new() {
        Ok(work) => work,
        Err(err) => return failed(format!("Could not create a download directory - {err}")),
    };
    let packages: Vec<String> = jobs.iter().map(|job| job.package.clone()).collect();
    let mut culprit = None;
    let output = match apt_get_in(
        &["changelog", "--download-only", "-q"],
        &packages,
        deadline,
        Some(&work),
        || {
            let (total, largest) = download_size(&work.path);
            let too_large = total > MAX_ROUND_SIZE
                || largest
                    .as_ref()
                    .is_some_and(|(size, _)| *size > MAX_CHANGELOG_SIZE);
            if too_large {
                culprit = largest.map(|(_, name)| name);
            }
            too_large
        },
    ) {
        Ok(output) => output,
        Err(err) => return failed(err),
    };
    let report = DownloadReport::parse(&output.stdout, &output.stderr);
    let culprit_job = culprit.filter(|name| jobs.iter().any(|job| job.location.file == *name));
    jobs.iter()
        .map(
            |job| match read_download(&work.path.join(&job.location.file)) {
                Ok(Some(text)) => Download::Done(text),
                Ok(None) if output.stopped => match &culprit_job {
                    Some(name) if *name == job.location.file => {
                        Download::Failed(TOO_LARGE.to_string())
                    }
                    Some(_) => Download::Retry,
                    None => Download::Failed(
                        "Changelog downloads stopped as they got too large".to_string(),
                    ),
                },
                Ok(None) => Download::Failed(report.failure(&job.location, output.status)),
                Err(err) => Download::Failed(err),
            },
        )
        .collect()
}

/// The total size of the regular files below the directory, and the largest of them by name,
/// without following symbolic links, to watch the downloads of APT, which keeps unfinished ones in
/// directories within its temporary directory.
fn download_size(dir: &Path) -> (u64, Option<(u64, String)>) {
    fn walk(dir: &Path, depth: u32, total: &mut u64, largest: &mut Option<(u64, String)>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_dir() && depth > 0 {
                walk(&entry.path(), depth - 1, total, largest);
            } else if meta.is_file() {
                *total += meta.len();
                if largest.as_ref().is_none_or(|(size, _)| meta.len() > *size) {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    *largest = Some((meta.len(), name));
                }
            }
        }
    }
    let mut total = 0;
    let mut largest = None;
    walk(dir, 2, &mut total, &mut largest);
    (total, largest)
}

/// Reads a downloaded changelog, `None` if it is missing. Does not follow symbolic links, as APT
/// moves the files there from a directory of its sandbox user.
fn read_download(path: &Path) -> Result<Option<String>, String> {
    let failed = |err| format!("Could not read the downloaded changelog - {err}");
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(failed(err)),
    };
    let meta = file.metadata().map_err(failed)?;
    if !meta.is_file() {
        return Err("Downloaded changelog is not a regular file".to_string());
    }
    if meta.len() > MAX_CHANGELOG_SIZE {
        return Err(TOO_LARGE.to_string());
    }
    let mut bytes = Vec::new();
    file.take(MAX_CHANGELOG_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(failed)?;
    if bytes.len() as u64 > MAX_CHANGELOG_SIZE {
        return Err(TOO_LARGE.to_string());
    }
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

/// A private directory below /tmp, removed when dropped. APT downloads into its temporary
/// directory and moves the files into the working directory, which needs both on the same file
/// system, so the temporary directory of APT is placed inside, writable for its sandbox user.
struct WorkDir {
    path: PathBuf,
}

impl WorkDir {
    fn new() -> io::Result<Self> {
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = PathBuf::from(format!(
            "/tmp/proxmox-apt-history-{}-{nanos}-{}",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::DirBuilder::new().mode(0o711).create(&path)?;
        let work = Self { path };
        let tmp = work.tmp();
        fs::DirBuilder::new().mode(0o700).create(&tmp)?;
        if let Some(uid) = apt_sandbox_uid() {
            // without it APT falls back to /tmp, which works as well, but leaves its directories
            // behind if the download gets stopped
            let _ = std::os::unix::fs::chown(&tmp, Some(uid), None);
        }
        Ok(work)
    }

    fn tmp(&self) -> PathBuf {
        self.path.join("tmp")
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn apt_sandbox_uid() -> Option<libc::uid_t> {
    let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0 as libc::c_char; 4096];
    // SAFETY: the buffers are valid for the given sizes and `getpwnam_r` only writes the entry,
    // pointing into `buffer`, which is only used while it lives.
    unsafe {
        let rc = libc::getpwnam_r(
            c"_apt".as_ptr(),
            entry.as_mut_ptr(),
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut result,
        );
        (rc == 0 && !result.is_null()).then(|| (*result).pw_uid)
    }
}

/// What APT reported about the changelogs of one download run: the source packages whose download
/// started, the repositories that answered, and the reasons of failures by source and by URI.
#[derive(Default)]
struct DownloadReport {
    started: HashSet<String>,
    answered: HashSet<String>,
    by_source: HashMap<String, String>,
    by_uri: HashMap<String, String>,
}

impl DownloadReport {
    /// Parses the status lines of APT, like `Get:1 https://host bash 5.2.37-2 Changelog [116 kB]`
    /// or `Err:2 https://host curl 8.14.1-2 Changelog` followed by the indented reason, and its
    /// errors, like `E: Failed to fetch https://host/curl_changelog  404  Not Found`.
    fn parse(output: &str, error: &str) -> Self {
        let mut report = Self::default();
        let mut lines = output.lines().peekable();
        while let Some(line) = lines.next() {
            let mut fields = line.split_whitespace();
            let (Some(status), Some(repository), Some(source)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            let Some((kind, _)) = status.split_once(':') else {
                continue;
            };
            if !matches!(kind, "Get" | "Ign" | "Err") {
                continue;
            }
            report.started.insert(source.to_string());
            // failures and retries can also come from connections that did not succeed
            if kind == "Get" {
                report.answered.insert(format!("{repository}/"));
            }
            if kind == "Err"
                && let Some(reason) = lines.next_if(|line| line.starts_with("  "))
            {
                report
                    .by_source
                    .insert(source.to_string(), reason.trim().to_string());
            }
        }
        for line in error.lines() {
            if let Some((uri, reason)) = line
                .strip_prefix("E: Failed to fetch ")
                .and_then(|line| line.split_once(char::is_whitespace))
            {
                report
                    .by_uri
                    .insert(uri.to_string(), reason.trim().to_string());
            }
        }
        report
    }

    /// Why the changelog at the location is missing after the run, which got stopped at the
    /// deadline if it has no exit status. A download that did not start counts as timed out if its
    /// repository did not answer at all, as APT then still waits for the connection.
    fn failure(&self, location: &Location, status: Option<ExitStatus>) -> String {
        let answered = self
            .answered
            .iter()
            .any(|repository| location.uri.starts_with(repository.as_str()));
        let source = location.source().unwrap_or_default();
        match self
            .by_uri
            .get(&location.uri)
            .or_else(|| self.by_source.get(source))
        {
            Some(reason) => describe_failure(reason),
            None if status.is_none() && (self.started.contains(source) || !answered) => {
                TIMED_OUT.to_string()
            }
            None if status.is_none() => NOT_STARTED.to_string(),
            None => "Changelog download failed".to_string(),
        }
    }
}

/// Turns the reason APT gives for a failed changelog download into a short message for admins,
/// without the address details. APT wraps the reasons of changelog downloads in parentheses after
/// the version, like `Changelog unavailable for bash=5.2 (404  Not Found [IP: 192.0.2.1 443])`,
/// also for other failures than a missing changelog.
fn describe_failure(reason: &str) -> String {
    let (wrapped, reason) = match reason.strip_prefix("Changelog unavailable for ") {
        Some(rest) => (
            true,
            rest.split_once('(')
                .map_or("", |(_, reason)| reason.strip_suffix(')').unwrap_or(reason)),
        ),
        None => (false, reason),
    };
    let status = reason
        .split_whitespace()
        .next()
        .filter(|code| code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()));
    let lower = reason.to_ascii_lowercase();
    match status {
        Some("404") => format!("{NOT_AVAILABLE} (HTTP 404)"),
        Some(code) => format!("Changelog download failed (HTTP {code})"),
        None if wrapped && reason.trim().is_empty() => NOT_AVAILABLE.to_string(),
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

/// Downloaded changelogs by URI, compressed and with the URI in the first line, so that a hash
/// collision cannot return another changelog.
struct Cache {
    dir: OwnedFd,
}

impl Cache {
    /// Opens the cache directory, creating it if missing. Only accepts a directory that belongs to
    /// the current user and that nobody else can access, and works relative to it from then on, so
    /// that whoever can modify its parent cannot redirect the cache.
    fn open(dir: &Path) -> Option<Self> {
        if let Some(parent) = dir.parent() {
            fs::create_dir_all(parent).ok()?;
        }
        match fs::DirBuilder::new().mode(0o700).create(dir) {
            Err(err) if err.kind() != io::ErrorKind::AlreadyExists => return None,
            _ => (),
        }
        let path = CString::new(dir.as_os_str().as_bytes()).ok()?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: the path is a valid C string, and the returned descriptor gets owned right away.
        let dir = match unsafe { libc::open(path.as_ptr(), flags) } {
            fd if fd < 0 => return None,
            // SAFETY: the descriptor is valid and not owned by anything else.
            fd => unsafe { OwnedFd::from_raw_fd(fd) },
        };
        let dir = fs::File::from(dir);
        let meta = dir.metadata().ok()?;
        // SAFETY: geteuid cannot fail.
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return None;
        }
        Some(Self { dir: dir.into() })
    }

    fn key(uri: &str) -> String {
        // FNV-1a, stable across releases unlike the hasher of std
        let hash = uri.bytes().fold(0xcbf29ce484222325_u64, |hash, byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
        });
        format!("{hash:016x}")
    }

    fn name(uri: &str) -> String {
        format!("{}.gz", Self::key(uri))
    }

    fn marker(uri: &str) -> String {
        format!("{}.slow", Self::key(uri))
    }

    /// Opens a file in the cache directory, without following symbolic links.
    fn open_file(&self, name: &str, flags: libc::c_int) -> io::Result<fs::File> {
        let name = CString::new(name).map_err(|_| io::ErrorKind::InvalidInput)?;
        let flags = flags | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: the directory descriptor and the name are valid, the mode is only used when
        // creating a file, and the returned descriptor gets owned right away.
        match unsafe { libc::openat(self.dir.as_raw_fd(), name.as_ptr(), flags, 0o600) } {
            fd if fd < 0 => Err(io::Error::last_os_error()),
            // SAFETY: the descriptor is valid and not owned by anything else.
            fd => Ok(unsafe { fs::File::from_raw_fd(fd) }),
        }
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let from = CString::new(from).map_err(|_| io::ErrorKind::InvalidInput)?;
        let to = CString::new(to).map_err(|_| io::ErrorKind::InvalidInput)?;
        let dir = self.dir.as_raw_fd();
        // SAFETY: the directory descriptor and the names are valid.
        match unsafe { libc::renameat(dir, from.as_ptr(), dir, to.as_ptr()) } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    fn remove(&self, name: &str) {
        if let Ok(name) = CString::new(name) {
            // SAFETY: the directory descriptor and the name are valid.
            unsafe { libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0) };
        }
    }

    fn get(&self, uri: &str) -> Option<String> {
        let file = self.open_file(&Self::name(uri), libc::O_RDONLY).ok()?;
        if !file.metadata().ok()?.is_file() {
            return None;
        }
        let limit = MAX_CHANGELOG_SIZE + uri.len() as u64 + 1;
        let mut bytes = Vec::new();
        GzDecoder::new(file)
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() as u64 > limit {
            return None;
        }
        let text = String::from_utf8(bytes).ok()?;
        let (stored, text) = text.split_once('\n')?;
        (stored == uri).then(|| text.to_string())
    }

    /// Stores the changelog, best effort, as the next request downloads it again otherwise. Without
    /// syncing, as a damaged entry fails to decompress and gets downloaded again as well. Returns
    /// whether it got stored.
    fn put(&self, uri: &str, text: &str) -> bool {
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let name = Self::name(uri);
        let tmp = format!(
            ".{name}.{}.{}.tmp",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::Relaxed),
        );
        let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL;
        let stored = self
            .open_file(&tmp, flags)
            .and_then(|file| {
                let mut encoder = GzEncoder::new(file, Compression::default());
                encoder.write_all(uri.as_bytes())?;
                encoder.write_all(b"\n")?;
                encoder.write_all(text.as_bytes())?;
                encoder.finish().map(drop)
            })
            .and_then(|()| self.rename(&tmp, &name));
        if stored.is_ok() {
            self.remove(&Self::marker(uri));
        } else {
            self.remove(&tmp);
        }
        stored.is_ok()
    }

    /// Remembers when the download of the changelog did not finish in time, so that the next
    /// request starts it after the others, and slow downloads take turns being the first of them.
    fn mark_slow(&self, uri: &str) {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC;
        if let Ok(mut file) = self.open_file(&Self::marker(uri), flags) {
            let _ = writeln!(file, "{now}");
        }
    }

    /// When the download of the changelog last did not finish in time, if it did not yet finish
    /// since.
    fn slow_since(&self, uri: &str) -> Option<u128> {
        let mut text = String::new();
        let file = self.open_file(&Self::marker(uri), libc::O_RDONLY).ok()?;
        file.take(64).read_to_string(&mut text).ok()?;
        Some(text.trim().parse().unwrap_or_default())
    }

    /// Removes the changelogs and markers of other URIs, and files of interrupted writes.
    fn prune(&self, keep: &HashSet<&str>) {
        let keep: HashSet<String> = keep.iter().map(|uri| Self::key(uri)).collect();
        // reopens the directory the descriptor refers to, wherever it is now
        let Ok(entries) = fs::read_dir(format!("/proc/self/fd/{}", self.dir.as_raw_fd())) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let stale = if name.ends_with(".tmp") {
                self.open_file(name, libc::O_RDONLY)
                    .and_then(|file| file.metadata()?.modified())
                    .is_ok_and(|modified| modified.elapsed().unwrap_or_default() > TIMEOUT * 4)
            } else {
                name.strip_suffix(".gz")
                    .or_else(|| name.strip_suffix(".slow"))
                    .is_some_and(|key| !keep.contains(key))
            };
            if stale {
                self.remove(name);
            }
        }
    }

    fn mark_used(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Ok(mut file) =
            self.open_file("last-use", libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC)
        {
            let _ = writeln!(file, "{now}");
        }
    }

    /// Whether the cache got used in the last 30 days, by the time it records as text, so that its
    /// file times do not matter.
    fn used_recently(&self) -> bool {
        let mut text = String::new();
        let Ok(file) = self.open_file("last-use", libc::O_RDONLY) else {
            return false;
        };
        if file.take(64).read_to_string(&mut text).is_err() {
            return false;
        }
        let Ok(used) = text.trim().parse::<u64>() else {
            return false;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(used) < RECENT_USE.as_secs()
    }
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

/// The output of a command, without exit status if it got stopped, at the deadline or because
/// `stopped` is set.
struct Output {
    status: Option<ExitStatus>,
    stopped: bool,
    stdout: String,
    stderr: String,
}

fn apt_get(args: &[&str], packages: &[String], deadline: Instant) -> Result<Output, String> {
    apt_get_in(args, packages, deadline, None, || false)
}

fn apt_get_in(
    args: &[&str],
    packages: &[String],
    deadline: Instant,
    work: Option<&WorkDir>,
    stop: impl FnMut() -> bool,
) -> Result<Output, String> {
    let mut command = Command::new("apt-get");
    command.args(args).arg("--").args(packages);
    command.env("LC_ALL", "C");
    if let Some(work) = work {
        command.current_dir(&work.path).env("TMPDIR", work.tmp());
    }
    run(command, deadline, stop)
}

/// Runs the command in its own process group until it exits, the deadline passes or `stop`, which
/// gets checked a few times per second, returns true, then kills what is left of the group, and
/// returns the exit status, the output and the error output.
fn run(
    mut command: Command,
    deadline: Instant,
    mut stop: impl FnMut() -> bool,
) -> Result<Output, String> {
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
                scope.spawn(|| read_output(stderr, 1024 * 1024)),
            )
        };
        let mut polls = 0_u32;
        let mut stopped = false;
        let exited = loop {
            match has_exited(pid) {
                Ok(false) if Instant::now() < deadline => {
                    polls += 1;
                    if polls.is_multiple_of(10) && stop() {
                        stopped = true;
                        break Ok(false);
                    }
                    thread::sleep(Duration::from_millis(20));
                }
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
        let stdout = stdout.join().unwrap();
        let stderr = stderr.join().unwrap();
        let status = match exited {
            Ok(true) => Some(
                status.map_err(|err| format!("Could not wait for apt-get changelog - {err}"))?,
            ),
            Ok(false) => None,
            Err(err) => return Err(format!("Could not wait for apt-get changelog - {err}")),
        };
        Ok(Output {
            status,
            stopped,
            stdout: stdout?,
            stderr: stderr?,
        })
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
    use std::os::unix::process::ExitStatusExt;
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

    fn location(source: &str) -> Location {
        Location {
            uri: format!("https://example.invalid/{source}"),
            file: format!("{source}.changelog"),
        }
    }

    fn locations(sources: &[&str]) -> Vec<Result<Location, String>> {
        sources.iter().map(|source| Ok(location(source))).collect()
    }

    fn later() -> Instant {
        Instant::now() + TIMEOUT
    }

    fn no_installed(_: &str) -> Result<Option<Vec<ChangelogEntry>>, String> {
        panic!("only downgrades read the installed changelog")
    }

    impl From<Result<String, String>> for Download {
        fn from(result: Result<String, String>) -> Self {
            match result {
                Ok(text) => Download::Done(text),
                Err(err) => Download::Failed(err),
            }
        }
    }

    fn outcomes(results: Vec<Result<String, String>>) -> Vec<Download> {
        results.into_iter().map(Download::from).collect()
    }

    /// Downloads the text of the source each job names, as packages sharing a source share it.
    fn download_sources(jobs: &[&Job]) -> Vec<Download> {
        jobs.iter()
            .map(|job| Download::Done(text(job.location.source().unwrap())))
            .collect()
    }

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "proxmox-apt-history-test-{name}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
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
            None,
            |packages| {
                assert_eq!(packages.len(), 6);
                locations(&["zulu", "foo", "foo", "foo", "alpha", "broken"])
            },
            |jobs| {
                fetched
                    .lock()
                    .unwrap()
                    .extend(jobs.iter().map(|job| job.package.clone()));
                jobs.iter()
                    .map(|job| match job.package.as_str() {
                        "broken=3" => Err("download failed".to_string()),
                        _ => Ok(text(job.location.source().unwrap())),
                    })
                    .map(Download::from)
                    .collect()
            },
            no_installed,
        );
        assert_eq!(
            *fetched.lock().unwrap(),
            ["zulu=3", "foo-bin=3", "alpha=3", "broken=3"]
        );
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
            None,
            |_| locations(&["bar", "bar", "other"]),
            |jobs| {
                outcomes(vec![
                    Err("Changelog download failed".to_string());
                    jobs.len()
                ])
            },
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
            None,
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
    fn same_file_names_download_in_separate_rounds() {
        let mut second = change("binary", Some("1"));
        second.arch = Some("arm64".to_string());
        second.new_version = Some("2".to_string());
        let rounds = Mutex::new(Vec::new());
        let groups = download_changelogs(
            vec![
                change("binary", Some("1")),
                second,
                change("other", Some("1")),
            ],
            later(),
            None,
            |packages| {
                assert_eq!(packages, ["binary=3", "binary:arm64=2", "other=3"]);
                let mut arm = location("source");
                arm.uri.push_str("-arm64");
                vec![Ok(location("source")), Ok(arm), Ok(location("other"))]
            },
            |jobs| {
                rounds.lock().unwrap().push(
                    jobs.iter()
                        .map(|job| job.package.clone())
                        .collect::<Vec<_>>(),
                );
                download_sources(jobs)
            },
            no_installed,
        );
        assert_eq!(
            *rounds.lock().unwrap(),
            [vec!["binary=3", "other=3"], vec!["binary:arm64=2"]]
        );
        assert_eq!(groups.len(), 3);
    }

    #[test]
    fn downloads_stop_at_the_deadline() {
        let groups = download_changelogs(
            vec![change("late", Some("1"))],
            Instant::now(),
            None,
            |_| locations(&["late"]),
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
            None,
            |_| locations(&["source", "source-arm64"]),
            |jobs| outcomes(vec![Ok(text("source")); jobs.len()]),
            no_installed,
        );
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].entries.len(), 2);
        assert_eq!(groups[1].entries.len(), 1);
    }

    #[test]
    fn unresolved_packages_keep_their_own_error() {
        let groups = download_changelogs(
            vec![change("missing", None), change("valid", Some("1"))],
            later(),
            None,
            |_| vec![Err(NOT_IN_LISTS.to_string()), Ok(location("valid"))],
            download_sources,
            no_installed,
        );
        assert_eq!(groups[0].source.as_deref(), Some("valid"));
        assert_eq!(groups[1].error.as_deref(), Some(NOT_IN_LISTS));
        assert_eq!(groups[1].source, None);
    }

    #[test]
    fn associate_locations_only_if_every_failure_names_its_package() {
        let packages: Vec<String> = [
            "bash=1",
            "gone=2",
            "coreutils=3",
            "curl:amd64=4",
            "libc6:amd64=5",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let output = "'https://example.invalid/bash_1' bash.changelog\n\
            'https://example.invalid/coreutils_3' coreutils.changelog\n";
        // APT leaves out the native architecture of libc6
        let associated = associate_locations(
            &packages,
            output,
            "E: Version '2' for 'gone' was not found\nE: Unable to locate package curl:amd64\n\
             E: Version '5' for 'libc6' was not found\n",
        )
        .unwrap();
        assert_eq!(associated[0].as_ref().unwrap().file, "bash.changelog");
        assert_eq!(associated[1].as_ref().unwrap_err(), NOT_IN_LISTS);
        assert_eq!(associated[2].as_ref().unwrap().file, "coreutils.changelog");
        assert!(associated[3].is_err());
        assert!(associated[4].is_err());

        // without the architecture, a message naming two packages is ambiguous
        let multiarch: Vec<String> = ["libc6:amd64=5", "libc6:i386=5"]
            .into_iter()
            .map(str::to_string)
            .collect();
        assert!(
            associate_locations(&multiarch, "", "E: Version '5' for 'libc6' was not found\n")
                .is_none()
        );

        // an error that names no package leaves the association open
        assert!(associate_locations(&packages, output, "E: Something else\n").is_none());
        assert!(associate_locations(&packages, output, "").is_none());
    }

    #[test]
    fn associate_repositories_without_changelogs() {
        let packages: Vec<String> = ["bash=1", "vendor-tool=2:1.0-1", "libvendor:i386=3"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let associated = associate_locations(
            &packages,
            "'https://example.invalid/bash_1' bash.changelog\n",
            "E: Changelog unavailable for vendor-tool=2:1.0-1\n\
             E: Changelog unavailable for libvendor:i386=3 (no location)\n",
        )
        .unwrap();
        assert_eq!(associated[0].as_ref().unwrap().file, "bash.changelog");
        assert_eq!(associated[1].as_ref().unwrap_err(), NOT_AVAILABLE);
        assert_eq!(associated[2].as_ref().unwrap_err(), NOT_AVAILABLE);
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
            None,
            |packages| {
                packages
                    .iter()
                    .map(|package| Ok(location(package.split_once('=').unwrap().0)))
                    .collect()
            },
            |jobs| {
                jobs.iter()
                    .map(|job| {
                        Download::Done(if job.package == "large=3" {
                            "x".repeat(MAX_CHANGELOG_SIZE as usize + 1)
                        } else {
                            String::new()
                        })
                    })
                    .collect()
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
        assert_eq!(location.source(), Some("apt"));
        assert!(parse_location("https://example.invalid/changelog").is_err());
        assert!(parse_location("'https://example.invalid/changelog' ../x.changelog").is_err());
        assert!(parse_location("'https://example.invalid/changelog' .changelog").is_err());
    }

    #[test]
    fn cache_answers_later_requests() {
        let dir = TestDir::new("cache");
        let cache = Cache::open(&dir.0).unwrap();
        let downloads = Mutex::new(0);
        let request = |sources: &[&str]| {
            fetch_changelogs(
                &sources
                    .iter()
                    .map(|source| format!("{source}=3"))
                    .collect::<Vec<_>>(),
                later(),
                Some(&cache),
                |_| locations(sources),
                |jobs| {
                    *downloads.lock().unwrap() += jobs.len();
                    download_sources(jobs)
                },
            )
        };
        let first = request(&["foo", "bar"]);
        assert_eq!(first.downloaded, 2);
        let second = request(&["foo", "bar"]);
        assert_eq!(second.downloaded, 0);
        assert_eq!(*downloads.lock().unwrap(), 2);
        assert_eq!(second.entries[0].as_ref().unwrap().len(), 3);

        // only the changelogs of the latest request stay
        request(&["foo"]);
        assert!(cache.get(&location("foo").uri).is_some());
        assert!(cache.get(&location("bar").uri).is_none());

        // an entry of another URI with the same name is not taken
        fs::rename(
            dir.0.join(Cache::name(&location("foo").uri)),
            dir.0.join(Cache::name(&location("other").uri)),
        )
        .unwrap();
        assert!(cache.get(&location("other").uri).is_none());
    }

    #[test]
    fn failed_downloads_are_not_cached() {
        let dir = TestDir::new("failed");
        let cache = Cache::open(&dir.0).unwrap();
        for expected in [1, 1] {
            let fetched = fetch_changelogs(
                &["foo=3".to_string()],
                later(),
                Some(&cache),
                |_| locations(&["foo"]),
                |jobs| {
                    outcomes(vec![
                        Err("Changelog download failed".to_string());
                        jobs.len()
                    ])
                },
            );
            assert_eq!(fetched.downloaded, 0);
            assert_eq!(fetched.entries.len(), expected);
            assert!(fetched.entries[0].is_err());
        }
    }

    #[test]
    fn only_failures_naming_the_package_are_definite() {
        let package = "vendor-tool=1".to_string();
        let output = |code: i32, stdout: &str, stderr: &str| Output {
            status: Some(ExitStatus::from_raw(code << 8)),
            stopped: false,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        };
        let resolved = |output| resolved_location(&package, &output);
        assert_eq!(
            resolved(output(
                0,
                "'https://example.invalid/vendor-tool_1' vendor-tool.changelog\n",
                ""
            ))
            .unwrap()
            .file,
            "vendor-tool.changelog"
        );
        assert_eq!(
            resolved(output(100, "", "E: Unable to locate package vendor-tool\n")).unwrap_err(),
            NOT_IN_LISTS
        );
        assert_eq!(
            resolved(output(
                100,
                "",
                "E: Changelog unavailable for vendor-tool=1\n"
            ))
            .unwrap_err(),
            NOT_AVAILABLE
        );
        // as APT reports a broken list of sources
        assert_eq!(
            resolved(output(
                100,
                "",
                "E: Malformed entry 1 in list file /etc/apt/sources.list.d/x.list (Component)\n\
                 E: The list of sources could not be read.\n"
            ))
            .unwrap_err(),
            "Could not resolve the changelog location - Malformed entry 1 in list file \
             /etc/apt/sources.list.d/x.list (Component)"
        );
        assert_eq!(
            resolved(output(0, "", "")).unwrap_err(),
            "Could not resolve the changelog location"
        );
    }

    #[test]
    fn failed_resolution_keeps_the_cache() {
        let dir = TestDir::new("unresolved");
        let cache = Cache::open(&dir.0).unwrap();
        assert!(cache.put(&location("foo").uri, &text("foo")));
        let fetch = |resolved: Vec<Result<Location, String>>| {
            fetch_changelogs(
                &["foo=3".to_string()],
                later(),
                Some(&cache),
                |_| resolved,
                |_| panic!("nothing to download"),
            )
        };
        fetch(vec![Err(NOT_STARTED.to_string())]);
        assert!(cache.get(&location("foo").uri).is_some());
        fetch(vec![Err(
            "Could not resolve the changelog location".to_string()
        )]);
        assert!(cache.get(&location("foo").uri).is_some());
        fetch(vec![Err(NOT_IN_LISTS.to_string())]);
        assert!(cache.get(&location("foo").uri).is_none());
    }

    #[test]
    fn prefetch_needs_a_recent_request() {
        let dir = TestDir::new("prefetch");
        let cache = Cache::open(&dir.0).unwrap();
        assert!(cache.put(&location("foo").uri, &text("foo")));
        assert!(!cache.used_recently());
        assert_eq!(
            prefetch_update_changelogs(vec![change("foo", Some("1"))], &dir.0),
            Ok(None)
        );
        assert!(cache.get(&location("foo").uri).is_none());
        cache.mark_used();
        assert!(cache.used_recently());
        fs::write(dir.0.join("last-use"), "1000\n").unwrap();
        assert!(!cache.used_recently());
    }

    #[test]
    fn prefetch_reports_failures_but_not_missing_changelogs() {
        let dir = TestDir::new("summary");
        let cache = Cache::open(&dir.0).unwrap();
        let summary = prefetch(
            vec![
                change("ok", Some("1")),
                change("missing", Some("1")),
                change("broken", Some("1")),
            ],
            later(),
            &cache,
            |_| locations(&["ok", "missing", "broken"]),
            |jobs| {
                jobs.iter()
                    .map(|job| match job.location.source().unwrap() {
                        "ok" => Ok(text("ok")),
                        "missing" => Err(describe_failure(
                            "Changelog unavailable for missing=3 (404  Not Found [IP: 192.0.2.1 80])",
                        )),
                        // APT wraps other failures the same way
                        _ => Err(describe_failure(
                            "Changelog unavailable for broken=3 (401  Unauthorized [IP: 192.0.2.1 443])",
                        )),
                    })
                    .map(Download::from)
                    .collect()
            },
        );
        assert_eq!(
            summary,
            PrefetchSummary {
                downloaded: 1,
                failed: 1,
                error: Some("Changelog download failed (HTTP 401)".to_string()),
            }
        );
    }

    #[test]
    fn slow_downloads_go_last_next_time() {
        let dir = TestDir::new("slow");
        let cache = Cache::open(&dir.0).unwrap();
        let rounds = Mutex::new(Vec::new());
        let request = |slow: bool| {
            fetch_changelogs(
                &["big=3", "small=3"].map(str::to_string),
                later(),
                Some(&cache),
                |_| locations(&["big", "small"]),
                |jobs| {
                    rounds.lock().unwrap().push(
                        jobs.iter()
                            .map(|job| job.package.clone())
                            .collect::<Vec<_>>(),
                    );
                    jobs.iter()
                        .map(|job| match job.package.as_str() {
                            "big=3" if slow => Download::Failed(TIMED_OUT.to_string()),
                            "big=3" => Download::Done(text("big")),
                            _ => Download::Failed("Changelog download failed".to_string()),
                        })
                        .collect()
                },
            )
        };
        request(true);
        assert!(cache.slow_since(&location("big").uri).is_some());
        request(false);
        assert_eq!(
            *rounds.lock().unwrap(),
            [vec!["big=3", "small=3"], vec!["small=3", "big=3"]]
        );
        // a finished download is no longer slow, and markers of other URIs get pruned
        assert!(cache.slow_since(&location("big").uri).is_none());
        cache.mark_slow(&location("gone").uri);
        request(false);
        assert!(cache.slow_since(&location("gone").uri).is_none());
    }

    #[test]
    fn slow_downloads_take_turns() {
        let dir = TestDir::new("turns");
        let cache = Cache::open(&dir.0).unwrap();
        let firsts = Mutex::new(Vec::new());
        for _ in 0..3 {
            fetch_changelogs(
                &["a=3", "b=3", "c=3"].map(str::to_string),
                later(),
                Some(&cache),
                |_| locations(&["a", "b", "c"]),
                |jobs| {
                    // only the first one starts, the others queue behind it
                    firsts.lock().unwrap().push(jobs[0].package.clone());
                    let mut results = vec![Download::Failed(TIMED_OUT.to_string())];
                    results.resize_with(jobs.len(), || Download::Failed(NOT_STARTED.to_string()));
                    results
                },
            );
            // the markers need different times
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(*firsts.lock().unwrap(), ["a=3", "b=3", "c=3"]);
    }

    #[test]
    fn rounds_have_a_bounded_size() {
        let rounds = Mutex::new(Vec::new());
        let sources: Vec<String> = (0..MAX_BATCH * 2 + 1).map(|i| format!("pkg{i}")).collect();
        let fetched = fetch_changelogs(
            &sources
                .iter()
                .map(|source| format!("{source}=3"))
                .collect::<Vec<_>>(),
            later(),
            None,
            |_| locations(&sources.iter().map(String::as_str).collect::<Vec<_>>()),
            |jobs| {
                rounds.lock().unwrap().push(jobs.len());
                download_sources(jobs)
            },
        );
        assert_eq!(*rounds.lock().unwrap(), [MAX_BATCH, MAX_BATCH, 1]);
        assert!(fetched.entries.iter().all(Result::is_ok));
    }

    #[test]
    fn cache_needs_a_private_directory_of_its_own() {
        let dir = TestDir::new("private");
        fs::create_dir(&dir.0).unwrap();
        // explicitly, as the umask could restrict the mode on creation
        fs::set_permissions(&dir.0, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        assert!(Cache::open(&dir.0).is_none());
        let target = TestDir::new("target");
        fs::DirBuilder::new().mode(0o700).create(&target.0).unwrap();
        let link = TestDir::new("link");
        std::os::unix::fs::symlink(&target.0, &link.0).unwrap();
        assert!(Cache::open(&link.0).is_none());
    }

    #[test]
    fn concurrent_writes_publish_whole_entries() {
        let dir = TestDir::new("concurrent");
        let cache = Cache::open(&dir.0).unwrap();
        let uri = location("foo").uri;
        let content = text("foo").repeat(200);
        thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..50 {
                        assert!(cache.put(&uri, &content));
                        assert_eq!(cache.get(&uri).as_deref(), Some(content.as_str()));
                    }
                });
            }
        });
        let files: Vec<_> = fs::read_dir(&dir.0).unwrap().flatten().collect();
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn download_report_tells_failures_apart() {
        let report = DownloadReport::parse(
            "Get:1 https://example.invalid bash 5.2 Changelog [116 kB]\n\
             Err:2 https://example.invalid curl 8.14 Changelog\n  \
             Changelog unavailable for curl=8.14 (404  Not Found [IP: 192.0.2.1 443])\n\
             Get:3 https://example.invalid perl 5.40 Changelog [1 MB]\n",
            "E: Failed to fetch https://example.invalid/vim_changelog  \
             Could not connect to example.invalid:443 (192.0.2.1), connection timed out\n",
        );
        let exited = Command::new("true").status().ok();
        assert_eq!(
            report.failure(&location("curl"), exited),
            "Changelog not available from the repository (HTTP 404)"
        );
        let vim = Location {
            uri: "https://example.invalid/vim_changelog".to_string(),
            file: "vim.changelog".to_string(),
        };
        assert_eq!(report.failure(&vim, exited), TIMED_OUT);
        // stopped at the deadline: started downloads timed out, the others did not start
        assert_eq!(report.failure(&location("perl"), None), TIMED_OUT);
        assert_eq!(report.failure(&location("zsh"), None), NOT_STARTED);
        // nothing came back from this repository, APT still waits for the connection
        let unreachable = Location {
            uri: "https://unreachable.invalid/zsh".to_string(),
            file: "zsh.changelog".to_string(),
        };
        assert_eq!(report.failure(&unreachable, None), TIMED_OUT);
        assert_eq!(
            report.failure(&location("zsh"), exited),
            "Changelog download failed"
        );
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
        let output = run(command, Instant::now() + Duration::from_secs(10), || false).unwrap();
        assert!(output.status.unwrap().success());
        assert_eq!(output.stdout, "done\n");
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn commands_stop_at_the_deadline() {
        let start = Instant::now();
        let mut command = Command::new("sh");
        command.args(["-c", "echo started; sleep 30"]);
        let output = run(command, Instant::now() + Duration::from_millis(200), || {
            false
        })
        .unwrap();
        assert!(output.status.is_none());
        assert_eq!(output.stdout, "started\n");
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn commands_stop_when_asked() {
        let start = Instant::now();
        let mut command = Command::new("sleep");
        command.arg("30");
        let mut checks = 0;
        let output = run(command, Instant::now() + Duration::from_secs(20), || {
            checks += 1;
            checks == 2
        })
        .unwrap();
        assert!(output.status.is_none() && output.stopped);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    #[ignore = "downloads changelogs from the configured APT repositories"]
    fn real_download() {
        let dir = TestDir::new("real");
        let installed = |package: &str| {
            let version = Command::new("dpkg-query")
                .args(["-W", "-f=${Version}", package])
                .output()
                .unwrap();
            assert!(version.status.success());
            let mut change = change(package, None);
            change.new_version = Some(String::from_utf8(version.stdout).unwrap());
            change
        };
        let changes = vec![installed("bash"), installed("coreutils")];
        for _ in 0..2 {
            let groups = get_update_changelogs(changes.clone(), &dir.0);
            assert_eq!(groups.len(), 2, "{groups:?}");
            assert!(
                groups.iter().all(|group| group.error.is_none()),
                "{groups:?}"
            );
            assert_eq!(groups[0].source.as_deref(), Some("bash"));
            assert_eq!(groups[0].entries.len(), 1);
        }
        assert_eq!(
            fs::read_dir(&dir.0)
                .unwrap()
                .filter(|entry| entry.as_ref().unwrap().path().extension() == Some("gz".as_ref()))
                .count(),
            2
        );
    }

    #[test]
    fn oversized_downloads_leave_the_rest_of_the_round_to_retry() {
        let rounds = Mutex::new(Vec::new());
        let fetched = fetch_changelogs(
            &["big=3", "other=3", "done=3"].map(str::to_string),
            later(),
            None,
            |_| locations(&["big", "other", "done"]),
            |jobs| {
                let mut rounds = rounds.lock().unwrap();
                rounds.push(jobs.len());
                if rounds.len() > 1 {
                    return download_sources(jobs);
                }
                vec![
                    Download::Failed(TOO_LARGE.to_string()),
                    Download::Retry,
                    Download::Done(text("done")),
                ]
            },
        );
        assert_eq!(*rounds.lock().unwrap(), [3, 1]);
        assert_eq!(fetched.entries[0].as_ref().unwrap_err(), TOO_LARGE);
        assert!(fetched.entries[1].is_ok());
        assert!(fetched.entries[2].is_ok());
    }

    #[test]
    fn download_size_finds_unfinished_downloads() {
        let dir = TestDir::new("size");
        fs::create_dir_all(dir.0.join("tmp/apt-changelog-x")).unwrap();
        fs::write(dir.0.join("done.changelog"), "x".repeat(10)).unwrap();
        fs::write(
            dir.0.join("tmp/apt-changelog-x/big.changelog"),
            "x".repeat(30),
        )
        .unwrap();
        std::os::unix::fs::symlink("/", dir.0.join("tmp/link")).unwrap();
        assert_eq!(
            download_size(&dir.0),
            (40, Some((30, "big.changelog".to_string())))
        );
    }

    #[test]
    fn readable_download_errors() {
        for (reason, expected) in [
            (
                "Changelog unavailable for nss=2:3.110-1+deb13u5 (404  Not Found [IP: 146.75.122.132 443])",
                "Changelog not available from the repository (HTTP 404)",
            ),
            (
                "401  Unauthorized [IP: 51.91.38.34 443]",
                "Changelog download failed (HTTP 401)",
            ),
            (
                "503  Service Unavailable [IP: 192.0.2.1 443]",
                "Changelog download failed (HTTP 503)",
            ),
            (
                "Temporary failure resolving 'example.invalid'",
                "Changelog download failed - could not resolve the repository host",
            ),
            (
                "Could not connect to example.invalid:443 (192.0.2.1), connection timed out",
                "Changelog download timed out",
            ),
            (
                "Certificate verification failed: The certificate is NOT trusted. [IP: 192.0.2.1 443]",
                "Changelog download failed - the repository certificate is not trusted",
            ),
            (
                "Changelog unavailable for foo=1",
                "Changelog not available from the repository",
            ),
            (
                "Changelog unavailable for foo=1 (401  Unauthorized [IP: 192.0.2.1 443])",
                "Changelog download failed (HTTP 401)",
            ),
            (
                "Changelog unavailable for foo=1 (Temporary failure resolving 'example.invalid')",
                "Changelog download failed - could not resolve the repository host",
            ),
            (
                "Changelog unavailable for foo=1 (Could not connect to example.invalid:443 \
                 (192.0.2.1), connection timed out)",
                "Changelog download timed out",
            ),
            ("unexpected output", "Changelog download failed"),
        ] {
            assert_eq!(describe_failure(reason), expected);
        }
    }

    #[test]
    fn empty_updates_do_not_invoke_apt() {
        assert!(
            download_changelogs(
                Vec::new(),
                later(),
                None,
                |_| panic!(),
                |_| panic!(),
                no_installed
            )
            .is_empty()
        );
    }
}
