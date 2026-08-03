//! Persists point-in-time firewall snapshots as JSON under
//! `~/.local/state/fwdeck/snapshots/`. A safety record taken before risky
//! changes; the file is a full serialization of `FirewallSnapshot`.
//!
//! `save` writes them; `load` and `list` feed the restore flow, which diffs a
//! saved snapshot against the current state and stages a reviewable plan —
//! restore is never applied automatically.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::{DegradedSection, FirewallSnapshot, SnapshotSection};

/// Current snapshot-file schema. Bump on breaking envelope changes.
pub const SCHEMA_VERSION: u32 = 2;

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
    /// Excluded from automatic retention pruning.
    pub pinned: bool,
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
    super::state_file::create_private_dir(&dir).map_err(|err| err.to_string())?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());
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
    // The completed temp inode is linked into its final unique name only after
    // fsync, so readers never observe an empty reservation or a torn file.
    let path = write_snapshot_file(&dir, stamp, json.as_bytes()).map_err(|err| err.to_string())?;
    Ok(path.display().to_string())
}

fn write_snapshot_file(
    dir: &std::path::Path,
    stamp: u128,
    bytes: &[u8],
) -> std::io::Result<std::path::PathBuf> {
    super::state_file::write_private_atomic_unique(dir, bytes, |collision| {
        let name = if collision == 0 {
            format!("snapshot-{stamp}.json")
        } else {
            format!("snapshot-{stamp}-{collision}.json")
        };
        dir.join(name)
    })
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
        let mut snapshot = envelope.snapshot;
        if envelope.schema < SCHEMA_VERSION {
            snapshot.degraded.push(DegradedSection::new(
                SnapshotSection::LegacySnapshot,
                None,
                format!(
                    "schema v{} stored ipsets and policies without separate runtime/permanent state",
                    envelope.schema
                ),
            ));
        }
        return Ok(snapshot);
    }
    // Legacy bare snapshot (pre-envelope files).
    let mut snapshot: FirewallSnapshot =
        serde_json::from_str(&raw).map_err(|err| err.to_string())?;
    snapshot.degraded.push(DegradedSection::new(
        SnapshotSection::LegacySnapshot,
        None,
        "bare snapshot stored ipsets and policies without separate runtime/permanent state",
    ));
    Ok(snapshot)
}

/// Pins or unpins an app-generated snapshot. Pinned snapshots are excluded
/// from automatic retention pruning.
pub fn set_pinned(name: &str, pinned: bool) -> Result<(), String> {
    let dir = snapshot_dir().ok_or_else(|| "no state directory".to_owned())?;
    set_pinned_in_dir(&dir, name, pinned).map_err(|err| err.to_string())
}

fn set_pinned_in_dir(dir: &std::path::Path, name: &str, pinned: bool) -> std::io::Result<()> {
    if !super::retention::is_snapshot_name(name) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "only app-generated snapshot names can be pinned",
        ));
    }
    let snapshot = dir.join(name);
    let metadata = std::fs::symlink_metadata(&snapshot)?;
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "snapshot is not a regular file",
        ));
    }
    let marker = dir.join(super::retention::pin_name(name));
    if pinned {
        super::state_file::create_private_dir(dir)?;
        super::state_file::write_private_atomic_replace(&marker, b"pinned\n")
    } else {
        match std::fs::remove_file(marker) {
            Ok(()) => super::state_file::sync_dir(dir),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }
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
            let pinned = std::fs::symlink_metadata(dir.join(super::retention::pin_name(&name)))
                .is_ok_and(|metadata| metadata.file_type().is_file());
            Some(SnapshotEntry {
                name,
                bytes,
                pinned,
            })
        })
        .collect();
    snapshots.sort_by(|a, b| b.name.cmp(&a.name));
    snapshots
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{set_pinned_in_dir, write_snapshot_file};

    #[test]
    fn same_millisecond_saves_publish_distinct_complete_files() {
        let dir = std::env::temp_dir().join(format!("fwdeck-snap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let stamp = 1_700_000_000_000u128;
        let first = write_snapshot_file(&dir, stamp, b"first").unwrap();
        let second = write_snapshot_file(&dir, stamp, b"second").unwrap();
        assert_ne!(first, second);
        assert_eq!(std::fs::read(first).unwrap(), b"first");
        assert_eq!(std::fs::read(second).unwrap(), b"second");
        assert!(std::fs::read_dir(&dir).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".fwdeck-")
        }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pin_marker_is_private_and_reversible() {
        let dir = std::env::temp_dir().join(format!("fwdeck-pin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let name = "snapshot-1700000000000.json";
        std::fs::write(dir.join(name), "{}").unwrap();
        set_pinned_in_dir(&dir, name, true).unwrap();
        let marker = dir.join(super::super::retention::pin_name(name));
        assert!(marker.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&marker).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        set_pinned_in_dir(&dir, name, false).unwrap();
        assert!(!marker.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn pin_rejects_unknown_names() {
        let dir = std::env::temp_dir().join(format!("fwdeck-pin-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("import.json"), "{}").unwrap();
        assert!(set_pinned_in_dir(&dir, "import.json", true).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
