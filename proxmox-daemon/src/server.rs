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
    // `envp` with the stop marker, for passing on a stop that arrived during the reload.
    envp_stop: Vec<*const c_char>,
    // Own the strings `argv`, `envp` and `envp_stop` point to.
    _args: Vec<CString>,
    _env: Vec<CString>,
    journal_identifier: OsString,
    fds: Vec<OwnedFd>,
}

// A forked new server, which waits for the acknowledgement on `channel` before it executes itself.
struct Successor {
    pid: nix::unistd::Pid,
    channel: std::fs::File,
}

// The acknowledgement that lets the new server go on, and the one that also tells it to stop.
const HANDOVER: u8 = 1;
const HANDOVER_STOP: u8 = 2;

/// Set in the environment of a new server to make it stop right after it started, as a stop
/// arrived during the reload that started it.
const STOP_ENV: &str = "PROXMOX_DAEMON_STOP";

// The signals that ask a daemon to shut down.
const SHUTDOWN_SIGNALS: [libc::c_int; 2] = [libc::SIGTERM, libc::SIGINT];

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

        Reexec::new(
            CString::new(self.self_exe.as_os_str().as_bytes())?,
            args,
            env,
            self.self_exe.file_name().unwrap_or_default().to_owned(),
            self.pre_exec.into_iter().map(|entry| entry.fd).collect(),
        )
    }

    pub fn fork_restart(self, pid_fn: Option<&str>) -> Result<(), Error> {
        // A process forked from a multi-threaded one inherits the locks other threads held at that
        // moment, with nobody left to release them. Rust's std, for example, holds its environment
        // lock while spawning a process, and a logger may hold its own. So prepare everything the
        // new server needs before forking.
        let reexec = self.prepare_reexec()?;
        let Some(mut successor) = reexec.fork_successor()? else {
            return Ok(());
        };

        if let Some(pid_fn) = pid_fn {
            let pid_str = format!("{}\n", successor.pid);
            proxmox_sys::fs::replace_file(pid_fn, pid_str.as_bytes(), CreateOptions::new(), false)?;
        }

        if let Err(e) =
            proxmox_systemd::notify::SystemdNotify::MainPid(successor.pid.into()).notify()
        {
            log::error!("failed to notify systemd about the new main pid: {}", e);
        }
        // ensure systemd got the message about the new main PID before continuing, else it
        // will get confused if the new main process sends its READY signal before that
        if let Err(e) = wait_for_systemd() {
            log::error!("failed to wait on systemd-processing: {}", e);
        }

        // The service manager may have sent a stop during the reload to the old main process
        // only, so pass it on.
        let stop = crate::state::is_stop_latched();
        if stop {
            log::info!("passing on a stop request to the new server");
        }
        // notify child that it is now the new main process:
        if let Err(e) = successor.hand_over(stop) {
            log::error!("child vanished during reload: {}", e);
        }

        Ok(())
    }
}

impl Successor {
    fn hand_over(&mut self, stop: bool) -> io::Result<()> {
        self.channel
            .write_all(&[if stop { HANDOVER_STOP } else { HANDOVER }])
    }
}

impl Reexec {
    fn new(
        exe: CString,
        args: Vec<CString>,
        mut env: Vec<CString>,
        journal_identifier: OsString,
        fds: Vec<OwnedFd>,
    ) -> Result<Self, Error> {
        let argv = null_terminated(&args);
        let envp = null_terminated(&env);
        // Growing the vector moves the CString handles, but not the string data `envp` points to.
        env.push(CString::new(format!("{STOP_ENV}=1"))?);
        let envp_stop = null_terminated(&env);
        Ok(Self {
            exe,
            argv,
            envp,
            envp_stop,
            _args: args,
            _env: env,
            journal_identifier,
            fds,
        })
    }

    /// Forks off the new server through an intermediate process, so that it gets reparented to
    /// the service manager, and receives its PID. Returns `None` if that failed, after logging why.
    fn fork_successor(&self) -> Result<Option<Successor>, Error> {
        // Synchronisation pipe:
        let (pold, pnew) = socketpair()?;

        // Fork with shutdown signals blocked, which the new server keeps until the handover is
        // done, see run().
        let signal_mask = set_signal_mask(libc::SIG_BLOCK, &shutdown_signal_set())?;
        let forked = unsafe { fork() };
        if !matches!(forked, Ok(ForkResult::Child))
            && let Err(err) = set_signal_mask(libc::SIG_SETMASK, &signal_mask)
        {
            log::error!("failed to restore signal mask after fork: {err}");
        }

        match forked {
            Ok(ForkResult::Child) => {
                std::mem::drop(pold);
                // Double fork so systemd can supervise us without nagging...
                match unsafe { fork() } {
                    Ok(ForkResult::Child) => self.run(pnew, &signal_mask),
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
                // reparented to the service manager before that learns the new main PID. systemd
                // supervises a new main process as its own child only if it is one at that moment.
                if let Err(err) = nix::sys::wait::waitpid(child, None) {
                    log::error!("failed to reap intermediate reload process: {err}");
                }
                let mut channel = std::fs::File::from(pold);
                let mut child_pid = (0 as libc::pid_t).to_ne_bytes();
                match channel.read_exact(&mut child_pid) {
                    Ok(()) => Ok(Some(Successor {
                        pid: nix::unistd::Pid::from_raw(libc::pid_t::from_ne_bytes(child_pid)),
                        channel,
                    })),
                    Err(e) => {
                        log::error!(
                            "failed to receive pid of double-forked child process: {}",
                            e
                        );
                        // systemd will complain but won't kill the service...
                        Ok(None)
                    }
                }
            }
            Err(e) => {
                log::error!("fork() failed, restart delayed: {}", e);
                Ok(None)
            }
        }
    }

    // Runs in a process forked from a possibly multi-threaded one, so it must not log, panic or use
    // std::env, all of which can wait for locks that another thread held at the fork.
    fn run(&self, channel: OwnedFd, signal_mask: &libc::sigset_t) -> ! {
        // Shutdown signals stay blocked until the handover is done, as the inherited handlers would
        // swallow them, with nothing polling their Tokio streams here. One that arrived meanwhile
        // counts like a stop passed on by the old server, so the new one stops once it took over.
        let mut channel = std::fs::File::from(channel);
        let pid = nix::unistd::Pid::this();
        if channel.write_all(&pid.as_raw().to_ne_bytes()).is_err() {
            exit_child(b"failed to send new server PID to parent\n");
        }

        let mut handover = [0u8];
        if channel.read_exact(&mut handover).is_err()
            || !matches!(handover[0], HANDOVER | HANDOVER_STOP)
        {
            exit_child(b"parent vanished before notifying systemd\n");
        }

        std::mem::drop(channel);

        let stop = match take_shutdown_signals() {
            Ok(pending) => pending || handover[0] == HANDOVER_STOP,
            Err(_) => exit_child(b"failed to reset signal handlers\n"),
        };
        if set_signal_mask(libc::SIG_SETMASK, signal_mask).is_err() {
            exit_child(b"failed to restore signal mask\n");
        }

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
        let envp = if stop { &self.envp_stop } else { &self.envp };
        unsafe { libc::execve(self.exe.as_ptr(), self.argv.as_ptr(), envp.as_ptr()) };
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

fn shutdown_signal_set() -> libc::sigset_t {
    let mut set = unsafe { std::mem::zeroed() };
    unsafe { libc::sigemptyset(&mut set) };
    for signal in SHUTDOWN_SIGNALS {
        unsafe { libc::sigaddset(&mut set, signal) };
    }
    set
}

/// Changes the signal mask of the calling thread and returns the previous one.
fn set_signal_mask(how: libc::c_int, set: &libc::sigset_t) -> io::Result<libc::sigset_t> {
    let mut previous = unsafe { std::mem::zeroed() };
    match unsafe { libc::pthread_sigmask(how, set, &mut previous) } {
        0 => Ok(previous),
        err => Err(io::Error::from_raw_os_error(err)),
    }
}

/// Resets the blocked shutdown signals to their default action like exec does, keeping an ignored
/// one ignored, and discards pending ones. Returns whether one was pending.
fn take_shutdown_signals() -> io::Result<bool> {
    // Reset before looking for pending ones, so that one arriving in between either gets counted or
    // stays pending for its default action.
    let mut reset = [false; SHUTDOWN_SIGNALS.len()];
    for (signal, reset) in SHUTDOWN_SIGNALS.into_iter().zip(&mut reset) {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigaction(signal, std::ptr::null(), &mut action) } == -1 {
            return Err(io::Error::last_os_error());
        }
        if action.sa_sigaction != libc::SIG_IGN {
            set_signal_action(signal, libc::SIG_DFL)?;
            *reset = true;
        }
    }

    let mut pending: libc::sigset_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigpending(&mut pending) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut was_pending = false;
    for (signal, reset) in SHUTDOWN_SIGNALS.into_iter().zip(reset) {
        if reset && unsafe { libc::sigismember(&pending, signal) } == 1 {
            was_pending = true;
            // Ignoring a signal discards a pending one.
            set_signal_action(signal, libc::SIG_IGN)?;
            set_signal_action(signal, libc::SIG_DFL)?;
        }
    }
    Ok(was_pending)
}

fn set_signal_action(signal: libc::c_int, handler: libc::sighandler_t) -> io::Result<()> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = handler;
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The environment for the re-executed service: the current one without a stop marker, with the
/// variables of the stored descriptors set to their numbers.
fn reexec_env<I>(current: I, stored: &[(&str, RawFd)]) -> Result<Vec<CString>, Error>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let mut env = Vec::new();
    for (name, value) in current {
        if name == STOP_ENV || stored.iter().any(|(stored, _)| name == **stored) {
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
    if std::env::var_os(STOP_ENV).is_some() {
        log::info!("stopping as requested during the reload that started this server");
        crate::state::latch_stop();
        crate::request_shutdown();
    }

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

    if crate::is_reload_requested() {
        log::info!("daemon reload...");
        if let Err(e) = proxmox_systemd::notify::SystemdNotify::Reloading.notify() {
            log::error!("failed to notify systemd about the state change: {}", e);
        }
        if let Err(e) = wait_for_systemd() {
            log::error!("failed to wait on systemd-processing: {}", e);
        }

        if let Err(e) = reloader.fork_restart(pidfn) {
            log::error!("error during reload: {}", e);
            let _ =
                proxmox_systemd::notify::SystemdNotify::Status("error during reload".to_string())
                    .notify();
        }
    } else {
        log::info!("daemon shutting down...");
        // Close the reload copy of the listening socket, so that connection attempts get refused
        // once the service dropped its listener, instead of waiting until the process exits.
        drop(reloader);
    }

    if let Some(future) = finish_future {
        future.await;
    }

    log::info!("daemon shut down.");
    Ok(())
}

/// Waits until systemd processed the notifications sent before. A signal handled by the calling
/// thread ends the wait early, without systemd having caught up, so wait again then.
fn wait_for_systemd() -> io::Result<()> {
    loop {
        match proxmox_systemd::notify::barrier(u64::MAX) {
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
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
    use std::ffi::{CStr, CString, OsString};
    use std::io::Read;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::net::UnixDatagram;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use tokio::signal::unix::SignalKind;

    // Serializes the tests that change or depend on process-wide state, like the environment, and
    // those whose sockets a forked process would keep open.
    static PROCESS_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn reexec_env_sets_stored_descriptors() {
        let var = |name: &str, value: &[u8]| (name.into(), OsString::from_vec(value.to_vec()));
        let current = vec![
            var("PATH", b"/usr/sbin:/usr/bin"),
            var("PROXMOX_BACKUP_LISTEN_FD", b"3"),
            var("PROXMOX_DAEMON_STOP", b"1"),
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

    #[test]
    fn stop_refuses_connections_once_the_service_dropped_its_listener() {
        let _lock = PROCESS_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        let (closed_sender, closed) = tokio::sync::oneshot::channel();
        let (finish, finish_receiver) = tokio::sync::oneshot::channel::<()>();

        let daemon = super::create_daemon::<_, _, tokio::net::TcpListener>(
            ([127, 0, 0, 1], 0).into(),
            move |listener| {
                Ok(async move {
                    crate::shutdown_future().await;
                    let address = listener.local_addr()?;
                    drop(listener);
                    let _ = closed_sender.send(address);
                    let _ = finish_receiver.await;
                    Ok(())
                })
            },
            None,
        );
        let connect_while_finishing = async move {
            crate::request_shutdown();
            let address = closed.await.unwrap();
            let result = std::net::TcpStream::connect(address);
            let _ = finish.send(());
            result
        };

        let (daemon, connected) =
            runtime.block_on(futures::future::join(daemon, connect_while_finishing));
        daemon.unwrap();
        let err = connected.expect_err("connection to stopping daemon was accepted");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
    }

    #[test]
    fn barrier_wait_continues_after_an_interrupting_signal() {
        let _lock = PROCESS_LOCK.lock().unwrap_or_else(|err| err.into_inner());

        // Any handled signal interrupts the wait, like a second SIGHUP does in a daemon.
        extern "C" fn handle(_: libc::c_int) {}
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = handle as extern "C" fn(libc::c_int) as libc::sighandler_t;
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGUSR1, &action, &mut previous) },
            0
        );

        let path = std::env::temp_dir().join(format!(
            "proxmox-daemon-barrier-test-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let socket = UnixDatagram::bind(&path).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        unsafe { std::env::set_var("NOTIFY_SOCKET", &path) };

        let waiter = unsafe { libc::pthread_self() };
        let waiter_tid = unsafe { libc::gettid() };
        // Stands in for systemd, holding back the first barrier until the wait for it was
        // interrupted.
        let manager = std::thread::spawn(move || {
            let first = receive_barrier(&socket);
            assert!(first.is_some(), "no barrier received");
            wait_until_polling(waiter_tid);
            assert_eq!(unsafe { libc::pthread_kill(waiter, libc::SIGUSR1) }, 0);
            receive_barrier(&socket).is_some()
        });
        let result = super::wait_for_systemd();
        let waited_again = manager.join().unwrap();

        unsafe { std::env::remove_var("NOTIFY_SOCKET") };
        let _ = std::fs::remove_file(&path);
        unsafe { libc::sigaction(libc::SIGUSR1, &previous, std::ptr::null_mut()) };

        result.expect("barrier wait failed");
        assert!(
            waited_again,
            "barrier wait did not continue after the signal"
        );
    }

    // Receives a barrier notification and returns the descriptor whose closing releases it.
    fn receive_barrier(socket: &UnixDatagram) -> Option<OwnedFd> {
        let mut data = [0u8; 64];
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        let mut control = [0u64; 8];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control) as _;
        let len =
            unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        if len < 0 {
            return None;
        }
        assert_eq!(&data[..len as usize], b"BARRIER=1");
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        assert!(!header.is_null(), "barrier without descriptor");
        let fd = unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>()) };
        Some(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn wait_until_polling(tid: libc::pid_t) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let wchan = std::fs::read_to_string(format!("/proc/self/task/{tid}/wchan"));
            if wchan.is_ok_and(|wchan| wchan.contains("poll")) {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn new_server_stops_if_told_by_the_handover_or_a_pending_signal() {
        let _lock = PROCESS_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        // Adopt the new server once its intermediate parent exits, to wait for it.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1 as libc::c_ulong) },
            0
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        // Handlers as daemons install them, which the forked new server inherits.
        let _handlers = runtime.block_on(async {
            [SignalKind::terminate(), SignalKind::interrupt()]
                .map(|kind| tokio::signal::unix::signal(kind).unwrap())
        });

        let cases = [
            (None, false, "unset"),
            (None, true, "1"),
            (Some(libc::SIGTERM), false, "1"),
            (Some(libc::SIGINT), false, "1"),
        ];
        for (signal, stop, expected) in cases {
            let (mut report, reported_by_child) = std::io::pipe().unwrap();
            // Through /proc, as the shell may support only single-digit descriptor numbers.
            let script = format!(
                "printf %s \"${{{}-unset}}\" >/proc/self/fd/{}",
                super::STOP_ENV,
                reported_by_child.as_raw_fd()
            );
            let reexec = super::Reexec::new(
                c"/bin/sh".to_owned(),
                vec![
                    c"sh".to_owned(),
                    c"-c".to_owned(),
                    CString::new(script).unwrap(),
                ],
                Vec::new(),
                "proxmox-daemon-test".into(),
                vec![reported_by_child.into()],
            )
            .unwrap();

            let mut successor = reexec.fork_successor().unwrap().expect("no new server");
            let pid = successor.pid.as_raw();
            if let Some(signal) = signal {
                assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
            }
            successor.hand_over(stop).unwrap();
            drop(reexec);

            let status = wait_for_exit(pid);
            let mut reported = String::new();
            report.read_to_string(&mut reported).unwrap();
            let case = format!("signal {signal:?}, stop acknowledged: {stop}");
            assert_eq!(reported, expected, "{case}: status {status:#x}");
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "{case}: status {status:#x}"
            );
        }
    }

    // Kills the child if it does not exit in time, so that a failure does not hang.
    fn wait_for_exit(pid: libc::pid_t) -> libc::c_int {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut status = 0;
        loop {
            match unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } {
                0 if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                0 => {
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                    unsafe { libc::waitpid(pid, &mut status, 0) };
                    return status;
                }
                res => {
                    assert_eq!(res, pid, "{}", std::io::Error::last_os_error());
                    return status;
                }
            }
        }
    }
}
