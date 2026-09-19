use super::super::CollectorCtx;
use super::fanotify::{
    self, FAN_CLASS_NOTIF, FAN_CLOEXEC, FAN_EVENT_ON_CHILD, FAN_MARK_ADD, FAN_MARK_MOUNT,
    FAN_NONBLOCK, FAN_OPEN, FAN_OPEN_EXEC, FAN_REPORT_TID, FAN_UNLIMITED_MARKS,
    FAN_UNLIMITED_QUEUE, decode_events,
};
use super::{FileAuditHandle, RateLimiter};
use crate::model::{Event, FileEvent, FileOp};
use crate::sensitive::SensitiveMatcher;
use std::collections::HashSet;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const MAX_EVENTS_PER_SECOND_PER_PID: u32 = 400;
const MARK_REFRESH: Duration = Duration::from_secs(60);
const READ_BUFFER: usize = 128 * 1024;

pub struct FanotifyAudit {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    available: bool,
}

impl FileAuditHandle for FanotifyAudit {
    fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }

    fn available(&self) -> bool {
        self.available
    }
}

pub fn start(ctx: CollectorCtx) -> FanotifyAudit {
    if !crate::util::is_root() {
        tracing::warn!("file read auditing needs root; run the daemon as root to enable it");
        return FanotifyAudit {
            stop: Arc::new(AtomicBool::new(false)),
            handle: None,
            available: false,
        };
    }

    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let handle = std::thread::Builder::new()
        .name("agentmon-fanotify".into())
        .spawn(move || run(ctx, thread_stop))
        .ok();
    let available = handle.is_some();
    FanotifyAudit {
        stop,
        handle,
        available,
    }
}

/// Directories worth watching: every agent's working directory, plus whatever
/// the config asks for. Mount marks cover the whole filesystem containing them.
fn watch_roots(ctx: &CollectorCtx) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for pid in ctx.tracked_pids() {
        if let Some(cwd) = ctx
            .registry
            .read()
            .ok()
            .and_then(|registry| registry.cwd(pid).map(|path| path.to_path_buf()))
        {
            roots.push(cwd);
        }
    }
    for root in &ctx.config.watch_roots {
        roots.push(crate::util::expand_tilde(root));
    }
    if let Some(home) = crate::util::home_dir() {
        roots.push(home);
    }
    roots
}

fn run(ctx: CollectorCtx, stop: Arc<AtomicBool>) {
    let fd = match init_fanotify() {
        Ok(fd) => fd,
        Err(err) => {
            tracing::warn!("fanotify unavailable: {err}");
            return;
        }
    };

    let matcher = SensitiveMatcher::new(&ctx.config.sensitive_globs);
    let mut limiter = RateLimiter::default();
    let mut marked: HashSet<PathBuf> = HashSet::new();
    let mut last_mark = Instant::now() - MARK_REFRESH;
    let mut buffer = vec![0u8; READ_BUFFER];

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        if last_mark.elapsed() >= MARK_REFRESH {
            match fanotify::read_mountinfo() {
                Ok(mountinfo) => {
                    for root in watch_roots(&ctx) {
                        let Some(mount) = fanotify::mount_point_of(&root, &mountinfo) else {
                            continue;
                        };
                        if marked.contains(&mount) {
                            continue;
                        }
                        match add_mark(fd, &mount) {
                            Ok(()) => {
                                tracing::info!(mount = %mount.display(), "watching mount for file reads");
                                marked.insert(mount);
                            }
                            Err(err) => tracing::warn!("cannot mark {}: {err}", mount.display()),
                        }
                    }
                }
                Err(err) => tracing::debug!("cannot read mountinfo: {err}"),
            }
            last_mark = Instant::now();
        }

        if !wait_readable(fd, 500) {
            continue;
        }

        // SAFETY: fd is a valid fanotify descriptor and buffer is a live slice.
        let read =
            unsafe { libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };
        if read <= 0 {
            continue;
        }
        let events = decode_events(&buffer[..read as usize]);
        for event in events {
            if !event.has_path() {
                continue;
            }
            let path = std::fs::read_link(format!("/proc/self/fd/{}", event.fd)).ok();
            // SAFETY: closing a descriptor received from fanotify; it must be
            // closed whether or not the event is kept.
            unsafe { libc::close(event.fd) };
            let Some(path) = path else { continue };
            if !event.is_open() {
                continue;
            }
            handle_path(&ctx, &matcher, &mut limiter, event.pid, path);
        }
    }

    // SAFETY: fd came from fanotify_init and is not used afterwards.
    unsafe { libc::close(fd) };
}

fn handle_path(
    ctx: &CollectorCtx,
    matcher: &SensitiveMatcher,
    limiter: &mut RateLimiter,
    pid: u32,
    path: PathBuf,
) {
    let Some(agent_id) = ctx.agent_for(pid) else {
        return;
    };
    let sensitive = matcher.classify(&path).is_some();
    let under_cwd = ctx
        .registry
        .read()
        .ok()
        .and_then(|registry| registry.cwd(pid).map(|cwd| path.starts_with(cwd)))
        .unwrap_or(false);
    if !sensitive && !under_cwd {
        return;
    }
    if !sensitive && !limiter.allow(pid, MAX_EVENTS_PER_SECOND_PER_PID) {
        return;
    }

    ctx.emit(Event::File(FileEvent {
        ts: crate::util::now_ms(),
        pid,
        agent_id: Some(agent_id),
        path,
        op: FileOp::Open,
        source: "fanotify".into(),
        process_exe: ctx
            .registry
            .read()
            .ok()
            .and_then(|registry| registry.exe(pid).map(|path| path.display().to_string())),
    }));
}

fn init_fanotify() -> Result<i32, String> {
    let flags = FAN_CLASS_NOTIF
        | FAN_CLOEXEC
        | FAN_NONBLOCK
        | FAN_UNLIMITED_QUEUE
        | FAN_UNLIMITED_MARKS
        | FAN_REPORT_TID;
    let event_flags = (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as u32;
    // SAFETY: plain syscall wrapper, integer arguments only.
    let fd = unsafe { libc::fanotify_init(flags, event_flags) };
    if fd < 0 {
        return Err(format!(
            "fanotify_init failed: {} (needs CAP_SYS_ADMIN)",
            std::io::Error::last_os_error()
        ));
    }
    Ok(fd)
}

fn add_mark(fd: i32, mount: &Path) -> Result<(), String> {
    let path = CString::new(mount.as_os_str().as_encoded_bytes())
        .map_err(|_| "mount path contains a NUL byte".to_string())?;
    // Legacy descriptor mode (no FAN_REPORT_FID), so events carry a descriptor
    // that can be resolved through /proc/self/fd without CAP_DAC_READ_SEARCH.
    let mask = FAN_OPEN | FAN_OPEN_EXEC | FAN_EVENT_ON_CHILD;
    // SAFETY: fd is a valid fanotify descriptor, path is a valid C string.
    let rc = unsafe {
        libc::fanotify_mark(
            fd,
            FAN_MARK_ADD | FAN_MARK_MOUNT,
            mask,
            libc::AT_FDCWD,
            path.as_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

fn wait_readable(fd: i32, timeout_ms: i32) -> bool {
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll_fd points at one initialised entry.
    let rc = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
    rc > 0 && (poll_fd.revents & libc::POLLIN) != 0
}
