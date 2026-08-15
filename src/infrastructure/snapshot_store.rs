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

fn snapshot_file(snapshot: &FirewallSnapshot, stamp: u128, host: String) -> SnapshotFile {
    SnapshotFile {
        schema: SCHEMA_VERSION,
        host,
        fwdeck_version: env!("CARGO_PKG_VERSION").to_owned(),
        firewalld_version: snapshot.status.version.clone(),
        taken_at: stamp
            .checked_div(1000)
            .and_then(|seconds| u64::try_from(seconds).ok())
            .unwrap_or(0),
        snapshot: snapshot.clone(),
    }
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
    let envelope = snapshot_file(snapshot, stamp, crate::bootstrap::hostname());
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
    let dir = snapshot_dir().ok_or_else(|| "no state directory".to_owned())?;
    load_from_dir(&dir, name, &crate::bootstrap::hostname())
}

fn load_from_dir(
    dir: &std::path::Path,
    name: &str,
    current_host: &str,
) -> Result<FirewallSnapshot, String> {
    // Reject path separators: only files in the snapshot dir are loadable.
    if name.contains('/') || name.contains('\\') {
        return Err("invalid snapshot name".to_owned());
    }
    let path = dir.join(name);
    let metadata = std::fs::symlink_metadata(&path).map_err(|err| err.to_string())?;
    if !metadata.file_type().is_file() {
        return Err("snapshot is not a regular file".to_owned());
    }
    let raw = std::fs::read_to_string(path).map_err(|err| err.to_string())?;
    if let Ok(envelope) = serde_json::from_str::<SnapshotFile>(&raw) {
        if envelope.schema > SCHEMA_VERSION {
            return Err(format!(
                "snapshot schema v{} is newer than this fwdeck understands (v{SCHEMA_VERSION})",
                envelope.schema
            ));
        }
        if envelope.host != current_host {
            return Err(format!(
                "snapshot was taken on `{}` but this host is `{current_host}` — refusing a cross-host restore",
                envelope.host,
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
    list_in_dir(&dir)
}

fn list_in_dir(dir: &std::path::Path) -> Vec<SnapshotEntry> {
    let Ok(entries) = std::fs::read_dir(dir) else {
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
            if !entry.file_type().ok()?.is_file() {
                return None;
            }
            let metadata = entry.metadata().ok()?;
            let bytes = metadata.len();
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
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::domain::{SnapshotSection, mock};

    use super::{
        SCHEMA_VERSION, list_in_dir, load_from_dir, set_pinned_in_dir, snapshot_file,
        write_snapshot_file,
    };

    static TEST_SEQ: AtomicU64 = AtomicU64::new(1);

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let sequence = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "fwdeck-snapshot-{label}-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_json(path: &std::path::Path, value: &impl serde::Serialize) {
        std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    }

    #[test]
    fn envelope_round_trip_preserves_same_host_snapshot() {
        let dir = temp_dir("round-trip");
        let expected = mock::sample().unwrap();
        let envelope = snapshot_file(&expected, 1_700_000_000_123, "host-a".to_owned());
        let name = "snapshot-1700000000123.json";
        write_json(&dir.join(name), &envelope);

        let loaded = load_from_dir(&dir, name, "host-a").unwrap();

        assert_eq!(loaded, expected);
        assert_eq!(envelope.taken_at, 1_700_000_000);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn load_rejects_future_schema_and_cross_host_envelopes() {
        let dir = temp_dir("envelope-safety");
        let snapshot = mock::sample().unwrap();
        let name = "snapshot-1700000000000.json";
        let mut envelope = snapshot_file(&snapshot, 1_700_000_000_000, "host-a".to_owned());
        envelope.schema = SCHEMA_VERSION + 1;
        write_json(&dir.join(name), &envelope);
        assert!(
            load_from_dir(&dir, name, "host-a")
                .unwrap_err()
                .contains("newer")
        );

        envelope.schema = SCHEMA_VERSION;
        write_json(&dir.join(name), &envelope);
        assert!(
            load_from_dir(&dir, name, "host-b")
                .unwrap_err()
                .contains("cross-host")
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn legacy_envelope_and_bare_snapshot_are_marked_degraded() {
        let dir = temp_dir("legacy");
        let snapshot = mock::sample().unwrap();
        let envelope_name = "snapshot-1700000000000.json";
        let mut envelope = snapshot_file(&snapshot, 1_700_000_000_000, "host-a".to_owned());
        envelope.schema = SCHEMA_VERSION - 1;
        write_json(&dir.join(envelope_name), &envelope);

        let loaded = load_from_dir(&dir, envelope_name, "host-a").unwrap();
        assert_eq!(
            loaded.degraded.last().map(|entry| entry.section),
            Some(SnapshotSection::LegacySnapshot)
        );

        let bare_name = "snapshot-1700000000001.json";
        write_json(&dir.join(bare_name), &snapshot);
        let loaded = load_from_dir(&dir, bare_name, "host-a").unwrap();
        assert_eq!(
            loaded.degraded.last().map(|entry| entry.section),
            Some(SnapshotSection::LegacySnapshot)
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn load_rejects_traversal_and_non_regular_inputs() {
        let dir = temp_dir("invalid-input");
        assert_eq!(
            load_from_dir(&dir, "../snapshot-1.json", "host-a").unwrap_err(),
            "invalid snapshot name"
        );
        std::fs::create_dir(dir.join("snapshot-2.json")).unwrap();
        assert!(
            load_from_dir(&dir, "snapshot-2.json", "host-a")
                .unwrap_err()
                .contains("regular file")
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.join("snapshot-2.json"), dir.join("snapshot-3.json"))
                .unwrap();
            assert!(
                load_from_dir(&dir, "snapshot-3.json", "host-a")
                    .unwrap_err()
                    .contains("regular file")
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn list_returns_regular_json_files_newest_first_with_pin_state() {
        let dir = temp_dir("list");
        std::fs::write(dir.join("snapshot-100.json"), b"old").unwrap();
        std::fs::write(dir.join("snapshot-200.json"), b"newer").unwrap();
        std::fs::write(dir.join("notes.txt"), b"ignored").unwrap();
        std::fs::create_dir(dir.join("snapshot-300.json")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.join("snapshot-200.json"), dir.join("snapshot-400.json"))
            .unwrap();
        std::fs::write(
            dir.join(super::super::retention::pin_name("snapshot-100.json")),
            b"pinned\n",
        )
        .unwrap();

        let entries = list_in_dir(&dir);

        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            ["snapshot-200.json", "snapshot-100.json"]
        );
        assert_eq!(entries[0].bytes, 5);
        assert!(!entries[0].pinned);
        assert!(entries[1].pinned);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn same_millisecond_saves_publish_distinct_complete_files() {
        let dir = temp_dir("same-millisecond");
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
        let dir = temp_dir("pin");
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
        set_pinned_in_dir(&dir, name, false).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn pin_rejects_unknown_names() {
        let dir = temp_dir("pin-bad");
        std::fs::write(dir.join("import.json"), "{}").unwrap();
        assert!(set_pinned_in_dir(&dir, "import.json", true).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
