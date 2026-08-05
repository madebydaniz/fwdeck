//! Process-level wiring: tracing setup and host facts. Terminal wiring lives
//! in `ui::run`; backend wiring lives in `main`.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing_subscriber::EnvFilter;

use crate::config::Config;

/// `~/.local/state/fwdeck` on Linux (falls back to the local data dir).
#[must_use]
pub fn state_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("com", "madebydaniz", "fwdeck").map(|dirs| {
        dirs.state_dir()
            .map_or_else(|| dirs.data_local_dir().to_path_buf(), Path::to_path_buf)
    })
}

/// The state directory, created private (`0700`) if missing and chmod'd down
/// if it already exists with looser bits. Every state file (log, audit,
/// snapshots) holds firewall topology, so the containing directory must never
/// be group/other-readable — and whichever subsystem runs first must be the
/// one that sets the mode, so they all funnel through here.
#[must_use]
pub fn ensure_state_dir() -> Option<PathBuf> {
    let dir = state_dir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        // recursive create only chmods dirs it creates — so also clamp an
        // already-existing directory down to 0700.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .ok()?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok()?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

#[derive(Clone)]
struct FileWriter(Arc<File>);

impl Write for FileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self.0).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self.0).flush()
    }
}

/// File-only logging — stderr belongs to the alternate screen while the TUI
/// runs. Logging failures are non-fatal; returns whether logging is active.
#[allow(clippy::must_use_candidate)] // side-effecting; the flag is informational
pub fn init_tracing(config: &Config) -> bool {
    let Some(dir) = ensure_state_dir() else {
        return false;
    };
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    // The log records operation descriptions (source IPs, rich rules) — private.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let Ok(file) = options.open(dir.join("fwdeck.log")) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if file
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .is_err()
        {
            return false;
        }
    }
    let writer = FileWriter(Arc::new(file));
    let filter = EnvFilter::try_new(&config.log_level).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .try_init()
        .is_ok()
}

/// True when fwdeck appears to run inside an SSH session — mutations then get
/// an extra connectivity warning in the confirmation modal.
#[must_use]
pub fn ssh_session() -> bool {
    ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"]
        .iter()
        .any(|key| std::env::var_os(key).is_some_and(|value| !value.is_empty()))
}

/// The local interface carrying the current SSH session, if detectable.
///
/// The SSH client's IP address (`SSH_CONNECTION` field 0), when this process
/// runs inside an SSH session. The precise anchor for "which zone protects my
/// session": source bindings beat interface bindings in firewalld's dispatch.
#[must_use]
pub fn ssh_client_ip() -> Option<std::net::IpAddr> {
    let connection = std::env::var("SSH_CONNECTION").ok()?;
    connection.split_whitespace().next()?.parse().ok()
}

/// `SSH_CONNECTION` is `client_ip client_port server_ip server_port`; the
/// server IP is the address the session landed on. We match it against the
/// interface list from `ip -o addr` (universally present on Linux). Called once
/// at startup; a coarse SSH warning still fires if this returns `None`.
#[must_use]
pub fn ssh_interface() -> Option<String> {
    let connection = std::env::var("SSH_CONNECTION").ok()?;
    let server_ip = connection.split_whitespace().nth(2)?;
    interface_for_address(server_ip)
}

fn interface_for_address(address: &str) -> Option<String> {
    // Best-effort startup probe, hard-bounded so a hung `ip` can't freeze
    // startup; resolved from trusted dirs with a cleared env (may run as root).
    let text = crate::infrastructure::process::probe_output(
        "ip",
        &["-o", "addr", "show"],
        std::time::Duration::from_secs(2),
    )?;
    parse_ip_addr_interface(&text, address)
}

/// Parses `ip -o addr show` output, returning the interface whose address
/// matches `target` (the CIDR prefix is stripped before comparison).
fn parse_ip_addr_interface(output: &str, target: &str) -> Option<String> {
    // `2: eth0    inet 10.0.0.5/24 brd ... scope global eth0\ ...`
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        let _index = fields.next();
        let Some(iface) = fields.next() else { continue };
        let mut fields = fields.skip_while(|f| *f != "inet" && *f != "inet6");
        let Some(_family) = fields.next() else {
            continue;
        };
        if let Some(addr) = fields.next() {
            let ip = addr.split('/').next().unwrap_or(addr);
            if ip == target {
                return Some(iface.trim_end_matches(':').to_owned());
            }
        }
    }
    None
}

/// Best-effort hostname for the context header.
#[must_use]
pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .or_else(|| std::env::var("HOST").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "localhost".to_owned())
}

/// RAII guard for the advisory, process-wide mutation lock. The operating
/// system releases the lock when this handle is dropped, including on panic or
/// ordinary process termination; the lock file itself deliberately persists so
/// unlink/recreate races can never create two independently locked inodes.
#[derive(Debug)]
pub struct InstanceLock {
    file: File,
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // Closing the file also releases the lock, but an explicit unlock makes
        // guard-drop behavior deterministic before the descriptor is closed.
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

/// Acquires the advisory single-instance lock. Two `fwdeck` processes mutating
/// one firewall is a recipe for conflicting plans, so the lock is held by the
/// returned guard for the full mutation lifetime. Returns the current holder's
/// PID when available; metadata is informational and never decides ownership.
pub fn acquire_instance_lock() -> Result<InstanceLock, Option<u32>> {
    let Some(dir) = ensure_state_dir() else {
        return Err(None); // mutation without an enforceable lock is unsafe
    };
    acquire_instance_lock_at(&dir.join("fwdeck.lock"))
}

/// Reports PID metadata only when another process currently holds the OS lock.
/// `Ok(None)` means the lock is available and any stale file is harmless.
pub fn instance_lock_holder() -> Result<Option<u32>, String> {
    let Some(dir) = state_dir() else {
        return Err("no state directory available".to_owned());
    };
    instance_lock_holder_at(&dir.join("fwdeck.lock")).map_err(|error| error.to_string())
}

fn open_lock_file(path: &Path, create: bool) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn acquire_instance_lock_at(path: &Path) -> Result<InstanceLock, Option<u32>> {
    let mut file = open_lock_file(path, true).map_err(|_| None)?;
    if let Err(error) = fs2::FileExt::try_lock_exclusive(&file) {
        if error.kind() == fs2::lock_contended_error().kind() {
            return Err(read_lock_pid(&mut file));
        }
        return Err(None);
    }
    if write_lock_pid(&mut file).is_err() {
        return Err(None);
    }
    Ok(InstanceLock { file })
}

fn instance_lock_holder_at(path: &Path) -> std::io::Result<Option<u32>> {
    let mut file = match open_lock_file(path, false) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    match fs2::FileExt::try_lock_exclusive(&file) {
        Ok(()) => {
            fs2::FileExt::unlock(&file)?;
            Ok(None)
        }
        Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
            Ok(read_lock_pid(&mut file))
        }
        Err(error) => Err(error),
    }
}

fn read_lock_pid(file: &mut File) -> Option<u32> {
    use std::io::{Read as _, Seek as _};
    file.rewind().ok()?;
    let mut metadata = String::new();
    file.read_to_string(&mut metadata).ok()?;
    metadata.trim().parse().ok()
}

fn write_lock_pid(file: &mut File) -> std::io::Result<()> {
    use std::io::{Seek as _, Write as _};
    file.set_len(0)?;
    file.rewind()?;
    write!(file, "{}", std::process::id())?;
    file.sync_data()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{acquire_instance_lock_at, instance_lock_holder_at, parse_ip_addr_interface};

    const IP_ADDR: &str = "1: lo    inet 127.0.0.1/8 scope host lo\n\
2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n\
3: eth1    inet 192.168.1.10/24 scope global eth1\n";

    #[test]
    fn matches_the_interface_owning_the_address() {
        assert_eq!(
            parse_ip_addr_interface(IP_ADDR, "10.0.0.5").as_deref(),
            Some("eth0")
        );
        assert_eq!(
            parse_ip_addr_interface(IP_ADDR, "192.168.1.10").as_deref(),
            Some("eth1")
        );
        assert_eq!(parse_ip_addr_interface(IP_ADDR, "8.8.8.8"), None);
    }

    #[test]
    fn os_lock_is_exclusive_and_released_by_guard_drop() {
        let dir = std::env::temp_dir().join(format!("fwdeck-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fwdeck.lock");
        let first = acquire_instance_lock_at(&path).unwrap();
        assert_eq!(
            acquire_instance_lock_at(&path).unwrap_err(),
            Some(std::process::id())
        );
        assert_eq!(
            instance_lock_holder_at(&path).unwrap(),
            Some(std::process::id())
        );
        drop(first);

        assert_eq!(instance_lock_holder_at(&path).unwrap(), None);
        let second = acquire_instance_lock_at(&path).unwrap();
        assert!(path.exists(), "the stable lock inode must persist");
        drop(second);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
