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

/// Advisory single-instance lock: two `fwdeck` processes mutating one
/// firewall is a recipe for conflicting plans. Creates `fwdeck.lock`
/// (`O_EXCL`) in the state
/// dir containing our PID; a stale lock (dead PID) is reclaimed. Returns the
/// other instance's PID when the firewall is already being managed.
pub fn acquire_instance_lock() -> Result<(), Option<u32>> {
    let Some(dir) = ensure_state_dir() else {
        return Err(None); // mutation without an enforceable lock is unsafe
    };
    let path = dir.join("fwdeck.lock");
    for _ in 0..2 {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                use std::io::Write as _;
                if write!(file, "{}", std::process::id()).is_ok() && file.sync_data().is_ok() {
                    return Ok(());
                }
                let _ = std::fs::remove_file(&path);
                return Err(None);
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                let holder = std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|pid| pid.trim().parse::<u32>().ok());
                if let Some(pid) = holder {
                    // A dead holder leaves a stale lock — reclaim it.
                    if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                }
                return Err(holder);
            }
            Err(_) => return Err(None), // caller degrades to read-only
        }
    }
    Ok(())
}

/// Removes the instance lock on clean shutdown.
pub fn release_instance_lock() {
    if let Some(dir) = state_dir() {
        let _ = release_owned_lock(&dir.join("fwdeck.lock"));
    }
}

fn release_owned_lock(path: &Path) -> std::io::Result<bool> {
    let owner = match std::fs::read_to_string(path) {
        Ok(owner) => owner,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    if owner.trim().parse::<u32>().ok() != Some(std::process::id()) {
        return Ok(false);
    }
    std::fs::remove_file(path)?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(true)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{parse_ip_addr_interface, release_owned_lock};

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
    fn releases_only_a_lock_owned_by_this_process() {
        let dir = std::env::temp_dir().join(format!("fwdeck-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fwdeck.lock");
        std::fs::write(&path, format!("{}", std::process::id())).unwrap();
        assert!(release_owned_lock(&path).unwrap());
        assert!(!path.exists());

        std::fs::write(&path, format!("{}", std::process::id().saturating_add(1))).unwrap();
        assert!(!release_owned_lock(&path).unwrap());
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
