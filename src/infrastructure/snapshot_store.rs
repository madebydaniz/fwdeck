//! Persists point-in-time firewall snapshots as JSON under
//! `~/.local/state/fwdeck/snapshots/`. A safety record taken before risky
//! changes; the file is a full serialization of `FirewallSnapshot`.
//!
//! `save` writes them; `load` and `list` feed the restore flow, which diffs a
//! saved snapshot against the current state and stages a reviewable plan —
//! restore is never applied automatically.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::FirewallSnapshot;

/// Current snapshot-file schema. Bump on breaking envelope changes.
pub const SCHEMA_VERSION: u32 = 1;

/// The on-disk envelope around a saved snapshot: enough metadata to refuse a
/// restore against the wrong host or an incompatible schema, and to tell the
/// operator exactly where a file came from.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SnapshotFile {
    /// Envelope schema version ([`SCHEMA_VERSION`]).
    pub schema: u32,
    /// Hostname the snapshot was taken on.
    pub host: String,
    /// `fwdeck` version that wrote the file.
    pub fwdeck_version: String,
    /// firewalld version at capture time, when known.
    pub firewalld_version: Option<String>,
    /// Unix seconds at capture time.
    pub taken_at: u64,
    /// The captured state itself.
    pub snapshot: FirewallSnapshot,
}

/// A saved snapshot file on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotEntry {
    /// Filename within the snapshots directory (e.g. `snapshot-<ms>.json`).
    pub name: String,
    /// File size in bytes.
    pub bytes: u64,
}

fn snapshot_dir() -> Option<std::path::PathBuf> {
    Some(crate::bootstrap::state_dir()?.join("snapshots"))
}

/// Serializes `snapshot` to a timestamped JSON file and returns its path.
/// The timestamp is taken here so callers (the pure reducer) need no clock.
pub fn save(snapshot: &FirewallSnapshot) -> Result<String, String> {
    // The parent state dir is created 0700 via ensure_state_dir; the snapshots
    // subdirectory inherits privacy from create_private_dir.
    crate::bootstrap::ensure_state_dir().ok_or_else(|| "no state directory".to_owned())?;
    let dir = snapshot_dir().ok_or_else(|| "no state directory".to_owned())?;
    create_private_dir(&dir).map_err(|err| err.to_string())?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());
    // Reserve a unique filename by *atomically* creating it (O_EXCL), bumping a
    // suffix on collision. This closes the check-then-create race a
    // `while path.exists()` loop leaves open: two saves in the same millisecond
    // can no longer pick the same name and clobber each other.
    let path = reserve_unique_path(&dir, stamp).map_err(|err| err.to_string())?;
    let envelope = SnapshotFile {
        schema: SCHEMA_VERSION,
        host: crate::bootstrap::hostname(),
        fwdeck_version: env!("CARGO_PKG_VERSION").to_owned(),
        firewalld_version: snapshot.status.version.clone(),
        taken_at: stamp
            .checked_div(1000)
            .and_then(|seconds| u64::try_from(seconds).ok())
            .unwrap_or(0),
        snapshot: snapshot.clone(),
    };
    let json = serde_json::to_string_pretty(&envelope).map_err(|err| err.to_string())?;
    // Snapshots reveal firewall topology: private perms, written atomically
    // (temp + fsync + rename) so a crash never leaves a torn file.
    write_private_atomic(&path, json.as_bytes()).map_err(|err| err.to_string())?;
    Ok(path.display().to_string())
}

/// Atomically claims a unique `snapshot-<stamp>[-<n>].json` name by creating it
/// with `O_EXCL` (`0600`). Returns the reserved path; the caller fills it via
/// the temp-file + rename in [`write_private_atomic`]. Reserving up front means
/// two concurrent saves can never resolve to the same name.
fn reserve_unique_path(dir: &std::path::Path, stamp: u128) -> std::io::Result<std::path::PathBuf> {
    let mut counter = 0u32;
    loop {
        let name = if counter == 0 {
            format!("snapshot-{stamp}.json")
        } else {
            format!("snapshot-{stamp}-{counter}.json")
        };
        let path = dir.join(name);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(_reserved) => return Ok(path),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => counter += 1,
            Err(err) => return Err(err),
        }
    }
}

/// Creates `dir` (and parents) with `0700` on Unix.
fn create_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)
}

/// Writes `bytes` to `path` with `0600` perms via temp file + fsync + rename.
fn write_private_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let tmp = path.with_extension("json.tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)
}

/// Loads and deserializes a saved snapshot by filename. Deserialization
/// re-validates every value, so a tampered file fails to load. Envelope files
/// are checked for schema compatibility and **host identity** — restoring one
/// machine's firewall onto another is refused; legacy bare-snapshot files
/// (pre-envelope) still load.
pub fn load(name: &str) -> Result<FirewallSnapshot, String> {
    // Reject path separators: only files in the snapshot dir are loadable.
    if name.contains('/') || name.contains('\\') {
        return Err("invalid snapshot name".to_owned());
    }
    let dir = snapshot_dir().ok_or_else(|| "no state directory".to_owned())?;
    let raw = std::fs::read_to_string(dir.join(name)).map_err(|err| err.to_string())?;
    if let Ok(envelope) = serde_json::from_str::<SnapshotFile>(&raw) {
        if envelope.schema > SCHEMA_VERSION {
            return Err(format!(
                "snapshot schema v{} is newer than this fwdeck understands (v{SCHEMA_VERSION})",
                envelope.schema
            ));
        }
        let here = crate::bootstrap::hostname();
        if envelope.host != here {
            return Err(format!(
                "snapshot was taken on `{}` but this host is `{here}` — refusing a cross-host restore",
                envelope.host
            ));
        }
        return Ok(envelope.snapshot);
    }
    // Legacy bare snapshot (pre-envelope files).
    serde_json::from_str(&raw).map_err(|err| err.to_string())
}

/// Lists saved snapshots, newest first (filenames sort lexically by timestamp).
#[must_use]
pub fn list() -> Vec<SnapshotEntry> {
    let Some(dir) = snapshot_dir() else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut snapshots: Vec<SnapshotEntry> = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            if std::path::Path::new(&name)
                .extension()
                .is_none_or(|ext| ext != "json")
            {
                return None;
            }
            let bytes = entry.metadata().ok().map_or(0, |m| m.len());
            Some(SnapshotEntry { name, bytes })
        })
        .collect();
    snapshots.sort_by(|a, b| b.name.cmp(&a.name));
    snapshots
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{reserve_unique_path, write_private_atomic};

    #[test]
    fn atomic_write_is_exact_and_private() {
        let dir = std::env::temp_dir().join(format!("fwdeck-snapw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("snapshot-1.json");
        write_private_atomic(&path, br#"{"schema":1}"#).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), br#"{"schema":1}"#);
        // The temp file is renamed into place, never left behind.
        assert!(!path.with_extension("json.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "snapshot must be 0600");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reserved_names_never_collide() {
        let dir = std::env::temp_dir().join(format!("fwdeck-snap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Two saves in the same millisecond must resolve to distinct files, and
        // both names are actually reserved on disk (O_EXCL), not merely planned.
        let stamp = 1_700_000_000_000u128;
        let first = reserve_unique_path(&dir, stamp).unwrap();
        let second = reserve_unique_path(&dir, stamp).unwrap();
        assert_ne!(first, second);
        assert!(first.exists() && second.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
