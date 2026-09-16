//! Small host helpers: monotonic uptime, boot id, mode file, atomic writes,
//! and an exclusive file lock shared with `toggle`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::{Duration, Instant};

/// Seconds since boot from `/proc/uptime` (monotonic, not host-adjustable).
pub fn uptime_secs() -> io::Result<f64> {
    let s = fs::read_to_string("/proc/uptime")?;
    s.split_whitespace()
        .next()
        .and_then(|f| f.parse::<f64>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unparseable /proc/uptime"))
}

pub fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Content of the searcher network state file; `maintenance` when absent,
/// matching `toggle`'s default.
pub fn read_mode(path: &Path) -> String {
    match fs::read_to_string(path) {
        Ok(s) => {
            let t = s.trim();
            if t.is_empty() {
                "maintenance".to_string()
            } else {
                t.to_string()
            }
        }
        Err(_) => "maintenance".to_string(),
    }
}

/// Write `contents` to `path` atomically (temp file in the same directory,
/// fsync, rename) with the given mode.
pub fn write_atomic(path: &Path, contents: &str, mode: u32) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = dir.join(format!(".{file_name}.tmp.{}", std::process::id()));
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
        // mode() only applies at creation; enforce when the tmp file pre-existed
        f.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Exclusive `flock(2)` on `path`, held until dropped.
#[derive(Debug)]
pub struct FlockGuard {
    _file: File,
}

pub fn lock_exclusive(path: &Path, timeout: Duration) -> io::Result<FlockGuard> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: flock on a valid, open file descriptor with constant flags.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(FlockGuard { _file: file });
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EWOULDBLOCK) && err.raw_os_error() != Some(libc::EINTR)
        {
            return Err(err);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("timed out waiting for lock {}", path.display()),
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_replaces_content_and_mode() {
        let dir = std::env::temp_dir().join(format!("egress-resolver-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("hosts");
        write_atomic(&p, "one\n", 0o644).unwrap();
        write_atomic(&p, "two\n", 0o644).unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "two\n");
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(
            fs::read_dir(&dir).unwrap().count() == 1,
            "no temp file left behind"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn lock_is_exclusive_and_times_out() {
        let dir = std::env::temp_dir().join(format!("egress-resolver-lock-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("lock");
        let g = lock_exclusive(&p, Duration::from_millis(100)).unwrap();
        let err = lock_exclusive(&p, Duration::from_millis(250)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        drop(g);
        lock_exclusive(&p, Duration::from_millis(100)).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_mode_defaults_to_maintenance() {
        assert_eq!(read_mode(Path::new("/nonexistent/state")), "maintenance");
    }

    #[test]
    fn uptime_is_positive() {
        assert!(uptime_secs().unwrap() > 0.0);
    }
}
