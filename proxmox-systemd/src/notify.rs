use std::ffi::{CStr, CString, c_char, c_void};
use std::io;
use std::os::fd::{AsFd, AsRawFd, RawFd};

use crate::sys;

/// Systemd service startup states (see: ``man sd_notify``)
#[derive(Clone, Debug)]
pub enum SystemdNotify {
    Ready,
    Reloading,
    Stopping,
    Status(String),
    MainPid(libc::pid_t),
}

impl SystemdNotify {
    /// Tells systemd the startup state of the service (see: ``man sd_notify``)
    ///
    /// If a `SystemdNotify::Status` message cannot be converted to a C-String this returns an
    /// `io::ErrorKind::InvalidInput`.
    pub fn notify(self) -> Result<(), io::Error> {
        let message = self.message()?;
        sys::check_call(unsafe { sys::sd_notify(0, message.as_ptr()) }).map(drop)
    }

    fn message(self) -> Result<CString, io::Error> {
        Ok(match self {
            SystemdNotify::Ready => c"READY=1".into(),
            // Type=notify-reload services must send it with the time they began reloading.
            SystemdNotify::Reloading => {
                CString::new(format!("RELOADING=1\nMONOTONIC_USEC={}", monotonic_usec()?))?
            }
            SystemdNotify::Stopping => c"STOPPING=1".into(),
            SystemdNotify::Status(msg) => CString::new(format!("STATUS={msg}"))?,
            SystemdNotify::MainPid(pid) => CString::new(format!("MAINPID={pid}"))?,
        })
    }
}

fn monotonic_usec() -> Result<u64, io::Error> {
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(now.tv_sec as u64 * 1_000_000 + now.tv_nsec as u64 / 1_000)
}

/// Waits until all previously sent messages with sd_notify are processed
pub fn barrier(timeout: u64) -> Result<(), io::Error> {
    sys::check_call(unsafe { sys::sd_notify_barrier(0, timeout) }).map(drop)
}

/// Store a set of file descriptors in systemd's file descriptor store for this service.
pub fn store_fds(name: &str, fds: &[RawFd]) -> Result<(), io::Error> {
    validate_name(name)?;

    let message = CString::new(format!("FDSTORE=1\nFDNAME={name}"))?;

    sys::check_call(unsafe {
        sys::sd_pid_notify_with_fds(0, 0, message.as_ptr(), fds.as_ptr(), fds.len() as _)
    })
    .map(drop)
}

/// Store a file descriptor in systemd's file descriptor store for this service.
pub fn store_fd<F: AsFd + ?Sized>(name: &str, fds: &F) -> Result<(), io::Error> {
    store_fds(name, &[fds.as_fd().as_raw_fd()])
}

/// Validate a name for the `FDNAME=` argument (see `man sd_pid_notify_with_fds`).
fn validate_name(name: &str) -> Result<(), io::Error> {
    for b in name.as_bytes() {
        if *b == b':' || b.is_ascii_control() {
            return Err(io::Error::other("invalid file descriptor name"));
        }
    }
    Ok(())
}

/// An iterator over the file descriptor names in the systemd file descriptor store.
pub struct ListenFdNames {
    ptr: *mut *mut c_char,
    cur: usize,
    len: usize,
}

impl ListenFdNames {
    /// Query the file descriptor names and numbers stored in the systemd file descriptor store.
    pub fn query() -> Result<Self, io::Error> {
        let mut names = std::ptr::null_mut();
        let count = sys::check_call(unsafe { sys::sd_listen_fds_with_names(0, &mut names) })?;
        Ok(Self {
            ptr: names,
            cur: 0,
            len: count as usize,
        })
    }

    fn as_array(&self) -> &[*mut c_char] {
        if self.ptr.is_null() {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
        }
    }
}

impl Drop for ListenFdNames {
    fn drop(&mut self) {
        for name in self.as_array() {
            unsafe { libc::free(*name as *mut c_void) }
        }
    }
}

impl Iterator for ListenFdNames {
    type Item = (RawFd, Result<String, std::string::FromUtf8Error>);

    fn next(&mut self) -> Option<Self::Item> {
        let names = self.as_array();
        if self.cur >= names.len() {
            return None;
        }

        let ptr = names[self.cur] as *const c_char;
        let fd_num = (self.cur as RawFd) + sys::LISTEN_FDS_START;
        self.cur += 1;
        let name = String::from_utf8(unsafe { CStr::from_ptr(ptr) }.to_bytes().to_vec());
        Some((fd_num, name))
    }
}

#[cfg(test)]
mod tests {
    use super::SystemdNotify;

    #[test]
    fn reloading_carries_the_monotonic_time() {
        let before = super::monotonic_usec().unwrap();
        let message = SystemdNotify::Reloading.message().unwrap();
        let after = super::monotonic_usec().unwrap();
        let time = message
            .to_str()
            .unwrap()
            .strip_prefix("RELOADING=1\nMONOTONIC_USEC=")
            .expect("RELOADING=1 without MONOTONIC_USEC=")
            .parse::<u64>()
            .unwrap();
        assert!(
            (before..=after).contains(&time),
            "{before} <= {time} <= {after}"
        );
    }

    #[test]
    fn status_is_sent_as_status_field() {
        let message = SystemdNotify::Status("error during reload".into())
            .message()
            .unwrap();
        assert_eq!(message.as_bytes(), b"STATUS=error during reload");
    }
}
