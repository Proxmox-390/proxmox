use std::fs::{self, File};
use std::io;
use std::os::fd::AsRawFd;

use crate::HistoryEntry;

/// The lock that dpkg frontends like APT hold for a whole transaction.
const FRONTEND_LOCK: &str = "/var/lib/dpkg/lock-frontend";

/// How much later than the logged start of a transaction the process holding the lock may have
/// started, as both times are only exact to a second and a process start time follows clock
/// changes since boot.
const START_SLACK: i64 = 5;

/// The state of the dpkg frontend lock.
#[derive(Debug)]
pub(crate) enum FrontendLock {
    /// No process holds the lock.
    Free,
    /// A process holds the lock.
    Held {
        /// Its command line, with the arguments separated by spaces.
        command_line: String,
        /// Its start time as Unix epoch.
        start_time: i64,
    },
    /// The lock could not be checked, for example without permission to open it.
    Unknown,
}

impl FrontendLock {
    /// Checks the lock without taking it.
    ///
    /// This must not run in a process holding the lock itself: its own POSIX lock is invisible to
    /// it, and closing the file here would release it. The products only run APT as a separate
    /// process, and they read the APT cache without locking.
    pub(crate) fn check() -> Self {
        Self::check_file(FRONTEND_LOCK)
    }

    fn check_file(path: &str) -> Self {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Self::Free,
            Err(_) => return Self::Unknown,
        };
        // SAFETY: an all-zero flock is a valid value.
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_type = libc::F_WRLCK as libc::c_short;
        lock.l_whence = libc::SEEK_SET as libc::c_short;
        // SAFETY: the descriptor is open and F_GETLK only reports into the valid flock.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut lock) } != 0 {
            return Self::Unknown;
        }
        if lock.l_type == libc::F_UNLCK as libc::c_short {
            return Self::Free;
        }
        // an open file description lock has no process, and one of a process in another PID
        // namespace shows as 0
        if lock.l_pid <= 0 {
            return Self::Unknown;
        }
        match process(lock.l_pid) {
            Some((command_line, start_time)) => Self::Held {
                command_line,
                start_time,
            },
            None => Self::Unknown,
        }
    }

    /// Whether the transaction, the newest one and without end, still runs.
    ///
    /// APT takes the lock before it logs the transaction, so the process holding the lock runs it
    /// if it started before. A process that started later and runs the same command line can be
    /// that command started again, or the clock got changed since, so that stays open. Any other
    /// process holding the lock means the transaction got interrupted.
    pub(crate) fn runs(&self, entry: &HistoryEntry) -> Option<bool> {
        match self {
            Self::Free => Some(false),
            Self::Unknown => None,
            Self::Held {
                command_line,
                start_time,
            } => {
                if *start_time <= entry.start_time + START_SLACK {
                    return Some(true);
                }
                let same_command = entry
                    .command_line
                    .as_deref()
                    .filter(|logged| !logged.is_empty())
                    .is_some_and(|logged| {
                        // APT drops quotes, quotes option values with spaces and cuts long
                        // command lines short
                        without_quotes(command_line).starts_with(&without_quotes(logged))
                    });
                (!same_command).then_some(false)
            }
        }
    }
}

fn without_quotes(text: &str) -> String {
    text.chars()
        .filter(|c| !matches!(c, '"' | '\'' | '\r' | '\n'))
        .collect()
}

/// The command line and start time of a process.
fn process(pid: libc::pid_t) -> Option<(String, i64)> {
    let command_line = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let command_line = String::from_utf8_lossy(&command_line)
        .trim_end_matches('\0')
        .replace('\0', " ");

    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // the fields after the command name, which can contain spaces and parentheses itself
    let (_, fields) = stat.rsplit_once(')')?;
    // the 22nd field, the start time after boot in clock ticks
    let ticks: i64 = fields.split_whitespace().nth(19)?.parse().ok()?;
    let boot_time: i64 = fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()?;
    // SAFETY: sysconf has no preconditions.
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as i64;
    if ticks_per_second <= 0 {
        return None;
    }
    Some((command_line, boot_time + ticks / ticks_per_second))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(start_time: i64, command_line: Option<&str>) -> HistoryEntry {
        HistoryEntry {
            start_time,
            start_index: 0,
            end_time: None,
            running: None,
            command_line: command_line.map(str::to_string),
            requested_by: None,
            requested_by_uid: None,
            comment: None,
            error: None,
            packages: Vec::new(),
        }
    }

    fn held(command_line: &str, start_time: i64) -> FrontendLock {
        FrontendLock::Held {
            command_line: command_line.to_string(),
            start_time,
        }
    }

    #[test]
    fn running_transaction() {
        let upgrade = entry(
            1000,
            Some("apt-get -o Dpkg::Options::='--force-confdef x' dist-upgrade"),
        );
        assert_eq!(FrontendLock::Free.runs(&upgrade), Some(false));
        assert_eq!(FrontendLock::Unknown.runs(&upgrade), None);
        // the process started long before, while downloading the packages
        let process = "apt-get -o Dpkg::Options::=--force-confdef x dist-upgrade";
        assert_eq!(held(process, 400).runs(&upgrade), Some(true));
        // or the transaction got interrupted, and another process runs now
        assert_eq!(held("apt install foo", 5000).runs(&upgrade), Some(false));
        // the same command line started again, or the clock got changed
        assert_eq!(held(process, 5000).runs(&upgrade), None);

        // APT cuts long command lines short
        let long = format!("apt install {}", "package ".repeat(100));
        let cut = entry(1000, Some(&long[..150]));
        assert_eq!(held(&long, 5000).runs(&cut), None);
        assert_eq!(held("apt install other", 5000).runs(&cut), Some(false));

        // frontends using APT as library log no command line
        let library = entry(1000, None);
        assert_eq!(
            held("/usr/bin/python3 frontend", 998).runs(&library),
            Some(true)
        );
        assert_eq!(
            held("/usr/bin/python3 frontend", 1004).runs(&library),
            Some(true)
        );
        assert_eq!(
            held("/usr/bin/python3 frontend", 1006).runs(&library),
            Some(false)
        );
        assert_eq!(held("", 1006).runs(&entry(1000, Some(""))), Some(false));
    }

    #[test]
    fn own_process() {
        let (command_line, start_time) = process(std::process::id() as libc::pid_t).unwrap();
        let program = std::env::args().next().unwrap();
        assert!(command_line.starts_with(&program), "{command_line}");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!((now - 3600..=now + 1).contains(&start_time), "{start_time}");
    }

    /// Holds a POSIX lock on the file that `LOCK_HELPER_FILE` names until its input ends, as
    /// another process for `lock_of_another_process`.
    #[test]
    #[ignore]
    fn lock_helper() {
        let Some(path) = std::env::var_os("LOCK_HELPER_FILE") else {
            return;
        };
        let file = File::options().write(true).open(path).unwrap();
        // SAFETY: an all-zero flock is a valid value.
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_type = libc::F_WRLCK as libc::c_short;
        lock.l_whence = libc::SEEK_SET as libc::c_short;
        // SAFETY: the descriptor is open and the flock is valid.
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) },
            0
        );
        println!("locked");
        let _ = io::Read::read_to_end(&mut io::stdin(), &mut Vec::new());
    }

    #[test]
    fn lock_of_another_process() {
        use std::io::BufRead;
        use std::process::{Command, Stdio};

        let path = std::env::temp_dir().join(format!(
            "proxmox-apt-history-test-lock-{}",
            std::process::id()
        ));
        File::create(&path).unwrap();
        let path_str = path.to_str().unwrap();
        assert!(matches!(
            FrontendLock::check_file(path_str),
            FrontendLock::Free
        ));

        let mut helper = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "lock::tests::lock_helper",
                "--ignored",
                "--nocapture",
            ])
            .env("LOCK_HELPER_FILE", &path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = io::BufReader::new(helper.stdout.take().unwrap());
        let mut line = String::new();
        while line.trim() != "locked" {
            line.clear();
            assert_ne!(output.read_line(&mut line).unwrap(), 0, "helper ended");
        }
        let state = FrontendLock::check_file(path_str);
        drop(helper.stdin.take());
        helper.wait().unwrap();
        let after = FrontendLock::check_file(path_str);
        let _ = fs::remove_file(&path);

        match state {
            FrontendLock::Held {
                command_line,
                start_time,
            } => {
                assert!(command_line.contains("lock_helper"), "{command_line}");
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                assert!((now - 60..=now + 1).contains(&start_time), "{start_time}");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(after, FrontendLock::Free), "{after:?}");
    }

    #[test]
    fn missing_lock_is_free() {
        assert!(matches!(
            FrontendLock::check_file("/nonexistent/lock-frontend"),
            FrontendLock::Free
        ));
    }
}
