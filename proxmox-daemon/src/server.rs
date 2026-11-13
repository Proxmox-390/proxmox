//! Helpers to implement restartable server listening for incoming connections.

use std::ffi::{CString, OsString, c_char};
use std::future::Future;
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::pin::{Pin, pin};

use anyhow::{Error, bail, format_err};
use futures::future::{self, Either};
use nix::unistd::{ForkResult, fork};

use proxmox_sys::fd::fd_change_cloexec;
use proxmox_sys::fs::CreateOptions;

// Helper trait to "store" something in the environment to be reused after re-executing the
// service on a reload.
#[doc(hidden)] // not public api
pub trait Reloadable: Sized {
    fn restore(var: &str) -> Result<Self, Error>;
    /// Returns a close-on-exec duplicate of the descriptor to pass on to the re-executed service.
    fn get_store_fd(&self) -> Result<OwnedFd, Error>;
}

// Manages things to be stored and reloaded upon reexec.
// Anything which should be restorable should be instantiated via this struct's `restore` method,
#[derive(Default)]
struct Reloader {
    pre_exec: Vec<PreExecEntry>,
    self_exe: PathBuf,
}

// A descriptor the re-executed service inherits, with its number in the environment variable
// `name`.
struct PreExecEntry {
    name: &'static str,
    fd: OwnedFd,
}

// Everything the re-executed service is started with, prepared before forking.
struct Reexec {
    exe: CString,
    argv: Vec<*const c_char>,
    envp: Vec<*const c_char>,
    // Own the strings `argv` and `envp` point to.
    _args: Vec<CString>,
    _env: Vec<CString>,
    journal_identifier: OsString,
    fds: Vec<OwnedFd>,
}

impl Reloader {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            pre_exec: Vec::new(),

            // Get the path to our executable as PathBuf
            self_exe: std::fs::read_link("/proc/self/exe")?,
        })
    }

    /// Restore an object from an environment variable of the given name, or, if none exists, uses
    /// the function provided in the `or_create` parameter to instantiate the new "first" instance.
    ///
    /// Values created via this method will be remembered for later re-execution.
    pub async fn restore<T, F, U>(&mut self, name: &'static str, or_create: F) -> Result<T, Error>
    where
        T: Reloadable,
        F: FnOnce() -> U,
        U: Future<Output = Result<T, Error>>,
    {
        let res = match std::env::var(name) {
            Ok(varstr) => {
                log::debug!("restoring socket from FD {varstr}");
                T::restore(&varstr)?
            }
            Err(std::env::VarError::NotPresent) => or_create().await?,
            Err(_) => bail!("variable {} has invalid value", name),
        };

        self.pre_exec.push(PreExecEntry {
            name,
            fd: res.get_store_fd()?,
        });
        Ok(res)
    }

    fn prepare_reexec(self) -> Result<Reexec, Error> {
        let args = std::env::args_os()
            .map(|arg| CString::new(arg.into_vec()))
            .collect::<Result<Vec<_>, _>>()?;
        let stored: Vec<(&str, RawFd)> = self
            .pre_exec
            .iter()
            .map(|entry| (entry.name, entry.fd.as_raw_fd()))
            .collect();
        let env = reexec_env(std::env::vars_os(), &stored)?;

        Ok(Reexec {
            exe: CString::new(self.self_exe.as_os_str().as_bytes())?,
            argv: null_terminated(&args),
            envp: null_terminated(&env),
            _args: args,
            _env: env,
            journal_identifier: self.self_exe.file_name().unwrap_or_default().to_owned(),
            fds: self.pre_exec.into_iter().map(|entry| entry.fd).collect(),
        })
    }

    pub fn fork_restart(self, pid_fn: Option<&str>) -> Result<(), Error> {
        // A process forked from a multi-threaded one inherits the locks other threads held at that
        // moment, with nobody left to release them. Rust's std, for example, holds its environment
        // lock while spawning a process, and a logger may hold its own. So prepare everything the
        // new server needs before forking.
        let reexec = self.prepare_reexec()?;

        // Synchronisation pipe:
        let (pold, pnew) = socketpair()?;

        // Start ourselves in the background:
        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                std::mem::drop(pold);
                // Double fork so systemd can supervise us without nagging...
                match unsafe { fork() } {
                    Ok(ForkResult::Child) => reexec.run(pnew),
                    Ok(ForkResult::Parent { .. }) => (),
                    Err(_) => write_stderr(b"fork() failed, restart delayed\n"),
                }
                // No matter how we managed to get here, this is the time where we bail out quickly:
                unsafe { libc::_exit(-1) }
            }
            Ok(ForkResult::Parent { child }) => {
                log::debug!(
                    "forked off a new server (first pid: {}), waiting for 2nd pid",
                    child
                );
                std::mem::drop(pnew);
                // Reap the intermediate process first, so that the new server is already
                // reparented to the service manager when it learns the new main PID below. systemd
                // supervises a new main process as its own child only if it is one at that moment.
                if let Err(err) = nix::sys::wait::waitpid(child, None) {
                    log::error!("failed to reap intermediate reload process: {err}");
                }
                let mut pold = std::fs::File::from(pold);
                let mut child_pid = (0 as libc::pid_t).to_ne_bytes();
                let child = nix::unistd::Pid::from_raw(match pold.read_exact(&mut child_pid) {
                    Ok(()) => libc::pid_t::from_ne_bytes(child_pid),
                    Err(e) => {
                        log::error!(
                            "failed to receive pid of double-forked child process: {}",
                            e
                        );
                        // systemd will complain but won't kill the service...
                        return Ok(());
                    }
                });

                if let Some(pid_fn) = pid_fn {
                    let pid_str = format!("{child}\n");
                    proxmox_sys::fs::replace_file(
                        pid_fn,
                        pid_str.as_bytes(),
                        CreateOptions::new(),
                        false,
                    )?;
                }

                if let Err(e) =
                    proxmox_systemd::notify::SystemdNotify::MainPid(child.into()).notify()
                {
                    log::error!("failed to notify systemd about the new main pid: {}", e);
                }
                // ensure systemd got the message about the new main PID before continuing, else it
                // will get confused if the new main process sends its READY signal before that
                if let Err(e) = proxmox_systemd::notify::barrier(u64::MAX) {
                    log::error!("failed to wait on systemd-processing: {}", e);
                }

                // notify child that it is now the new main process:
                if let Err(e) = pold.write_all(&[1u8]) {
                    log::error!("child vanished during reload: {}", e);
                }

                Ok(())
            }
            Err(e) => {
                log::error!("fork() failed, restart delayed: {}", e);
                Ok(())
            }
        }
    }
}

impl Reexec {
    // Runs in a process forked from a possibly multi-threaded one, so it must not log, panic or use
    // std::env, all of which can wait for locks that another thread held at the fork.
    fn run(&self, channel: OwnedFd) -> ! {
        let mut channel = std::fs::File::from(channel);
        let pid = nix::unistd::Pid::this();
        if channel.write_all(&pid.as_raw().to_ne_bytes()).is_err() {
            exit_child(b"failed to send new server PID to parent\n");
        }

        let mut ok = [0u8];
        if channel.read_exact(&mut ok).is_err() || ok[0] != 1 {
            exit_child(b"parent vanished before notifying systemd\n");
        }

        std::mem::drop(channel);

        // Try to reopen STDOUT/STDERR journald streams to get correct PID in logs
        self.redirect_journal_fd(libc::LOG_INFO, 1);
        self.redirect_journal_fd(libc::LOG_ERR, 2);

        for fd in &self.fds {
            if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0) } == -1 {
                exit_child(b"failed to pass on descriptor to new server\n");
            }
        }
        if unsafe { libc::setsid() } == -1 {
            exit_child(b"failed to create session for new server\n");
        }
        unsafe { libc::execve(self.exe.as_ptr(), self.argv.as_ptr(), self.envp.as_ptr()) };
        exit_child(b"failed to execute new server\n");
    }

    fn redirect_journal_fd(&self, priority: libc::c_int, target: RawFd) {
        match proxmox_systemd::journal::stream_fd(&self.journal_identifier, priority, true) {
            Ok(fd) => {
                if fd.as_raw_fd() == target {
                    std::mem::forget(fd);
                } else if unsafe { libc::dup2(fd.as_raw_fd(), target) } == -1 {
                    exit_child(b"failed to redirect output to the journal\n");
                }
            }
            Err(_) => write_stderr(b"failed to update journal redirection\n"),
        }
    }
}

fn write_stderr(message: &[u8]) {
    unsafe { libc::write(libc::STDERR_FILENO, message.as_ptr().cast(), message.len()) };
}

fn exit_child(message: &[u8]) -> ! {
    write_stderr(message);
    unsafe { libc::_exit(-1) }
}

/// The environment for the re-executed service: the current one, with the variables of the stored
/// descriptors set to their numbers.
fn reexec_env<I>(current: I, stored: &[(&str, RawFd)]) -> Result<Vec<CString>, Error>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let mut env = Vec::new();
    for (name, value) in current {
        if stored.iter().any(|(stored, _)| name == **stored) {
            continue;
        }
        let mut entry = name.into_vec();
        entry.push(b'=');
        entry.extend_from_slice(value.as_bytes());
        env.push(CString::new(entry)?);
    }
    for (name, fd) in stored {
        env.push(CString::new(format!("{name}={fd}"))?);
    }
    Ok(env)
}

fn null_terminated(strings: &[CString]) -> Vec<*const c_char> {
    strings
        .iter()
        .map(|string| string.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect()
}

fn fd_store_dup(fd: RawFd) -> Result<OwnedFd, Error> {
    Ok(unsafe {
        OwnedFd::from_raw_fd(nix::fcntl::fcntl(
            fd,
            nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(0),
        )?)
    })
}

/// NOTE: This must only be used for *async* I/O objects!
unsafe fn fd_restore_func<T>(var: &str) -> Result<T, Error>
where
    T: FromRawFd,
{
    let fd = var
        .parse::<u32>()
        .map_err(|e| format_err!("invalid file descriptor: {}", e))? as RawFd;
    fd_change_cloexec(fd, true)?;
    Ok(unsafe { T::from_raw_fd(fd) })
}

// For now all we need to do is store and reuse a tcp listening socket:
impl Reloadable for tokio::net::TcpListener {
    fn get_store_fd(&self) -> Result<OwnedFd, Error> {
        fd_store_dup(self.as_raw_fd())
    }

    fn restore(var: &str) -> Result<Self, Error> {
        Ok(Self::from_std(unsafe { fd_restore_func(var) }?)?)
    }
}

// For now all we need to do is store and reuse a tcp listening socket:
impl Reloadable for tokio::net::UnixListener {
    fn get_store_fd(&self) -> Result<OwnedFd, Error> {
        fd_store_dup(self.as_raw_fd())
    }

    fn restore(var: &str) -> Result<Self, Error> {
        Ok(Self::from_std(unsafe { fd_restore_func(var) }?)?)
    }
}

pub trait Listenable: Reloadable {
    type Address;
    fn bind(addr: &Self::Address) -> Pin<Box<dyn Future<Output = io::Result<Self>> + Send + '_>>;
}

impl Listenable for tokio::net::TcpListener {
    type Address = std::net::SocketAddr;

    fn bind(addr: &Self::Address) -> Pin<Box<dyn Future<Output = io::Result<Self>> + Send + '_>> {
        Box::pin(Self::bind(addr))
    }
}

impl Listenable for tokio::net::UnixListener {
    type Address = std::os::unix::net::SocketAddr;

    fn bind(addr: &Self::Address) -> Pin<Box<dyn Future<Output = io::Result<Self>> + Send + '_>> {
        Box::pin(async move {
            let addr = addr
                .as_pathname()
                .ok_or_else(|| io::Error::other("missing path for unix socket"))?;
            match std::fs::remove_file(addr) {
                Ok(()) => (),
                Err(err) if err.kind() == io::ErrorKind::NotFound => (),
                Err(err) => Err(err)?,
            }
            Self::bind(addr)
        })
    }
}

/// This creates a future representing a daemon which reloads itself when receiving a SIGHUP.
/// If this is started regularly, a listening socket is created. In this case, the file descriptor
/// number will be remembered in `PROXMOX_BACKUP_LISTEN_FD`.
/// If the variable already exists, its contents will instead be used to restore the listening
/// socket.  The finished listening socket is then passed to the `create_service` function which
/// can be used to setup the TLS and the HTTP daemon. The returned future has to call
/// [SystemdNotify::notify](proxmox_systemd::notify::SystemdNotify::notify) with
/// [SystemdNotify::Ready](proxmox_systemd::notify::SystemdNotify) when the
/// service is ready.
pub async fn create_daemon<F, S, L>(
    address: L::Address,
    create_service: F,
    pidfn: Option<&str>,
) -> Result<(), Error>
where
    L: Listenable,
    F: FnOnce(L) -> Result<S, Error>,
    S: Future<Output = Result<(), Error>>,
{
    let mut reloader = Reloader::new()?;

    let listener: L = reloader
        .restore("PROXMOX_BACKUP_LISTEN_FD", move || async move {
            Ok(L::bind(&address).await?)
        })
        .await?;

    let service = create_service(listener)?;

    let service = async move {
        if let Err(err) = service.await {
            log::error!("server error: {}", err);
        }
    };

    let server_future = Box::pin(service);
    let shutdown_future = pin!(crate::shutdown_future());

    let finish_future = match future::select(server_future, shutdown_future).await {
        Either::Left((_, _)) => {
            crate::request_shutdown(); // make sure we are in shutdown mode
            None
        }
        Either::Right((_, server_future)) => Some(server_future),
    };

    let mut reloader = Some(reloader);

    if crate::is_reload_requested() {
        log::info!("daemon reload...");
        if let Err(e) = proxmox_systemd::notify::SystemdNotify::Reloading.notify() {
            log::error!("failed to notify systemd about the state change: {}", e);
        }
        if let Err(e) = proxmox_systemd::notify::barrier(u64::MAX) {
            log::error!("failed to wait on systemd-processing: {}", e);
        }

        if let Err(e) = reloader.take().unwrap().fork_restart(pidfn) {
            log::error!("error during reload: {}", e);
            let _ =
                proxmox_systemd::notify::SystemdNotify::Status("error during reload".to_string())
                    .notify();
        }
    } else {
        log::info!("daemon shutting down...");
    }

    if let Some(future) = finish_future {
        future.await;
    }

    log::info!("daemon shut down.");
    Ok(())
}

/// Wrapper for `nix::sys::socket::socketpair` defaulting to `O_CLOEXEC`.
fn socketpair() -> Result<(OwnedFd, OwnedFd), Error> {
    use nix::sys::socket;
    Ok(socket::socketpair(
        socket::AddressFamily::Unix,
        socket::SockType::Stream,
        None,
        socket::SockFlag::SOCK_CLOEXEC,
    )?)
}

#[cfg(test)]
mod tests {
    use std::ffi::{CStr, OsString};
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn reexec_env_sets_stored_descriptors() {
        let var = |name: &str, value: &[u8]| (name.into(), OsString::from_vec(value.to_vec()));
        let current = vec![
            var("PATH", b"/usr/sbin:/usr/bin"),
            var("PROXMOX_BACKUP_LISTEN_FD", b"3"),
            var("RAW", b"\xff=x"),
            var("EMPTY", b""),
        ];
        let env = super::reexec_env(current, &[("PROXMOX_BACKUP_LISTEN_FD", 7)]).unwrap();
        let env: Vec<&[u8]> = env.iter().map(|entry| entry.as_bytes()).collect();
        assert_eq!(
            env,
            [
                &b"PATH=/usr/sbin:/usr/bin"[..],
                b"RAW=\xff=x",
                b"EMPTY=",
                b"PROXMOX_BACKUP_LISTEN_FD=7",
            ]
        );
    }

    #[test]
    fn null_terminated_points_to_strings() {
        let strings = vec![c"a".to_owned(), c"bc".to_owned()];
        let pointers = super::null_terminated(&strings);
        assert_eq!(pointers.len(), 3);
        assert_eq!(unsafe { CStr::from_ptr(pointers[0]) }, c"a");
        assert_eq!(unsafe { CStr::from_ptr(pointers[1]) }, c"bc");
        assert!(pointers[2].is_null());
    }
}
