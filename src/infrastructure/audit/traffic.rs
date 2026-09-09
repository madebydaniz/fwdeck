//! Dedicated private configuration-evaluation audit namespace.

use crate::application::traffic_test_audit::{
    TrafficAuditError, TrafficAuditSink, TrafficAuditSummary,
};
use crate::config::AuditRetentionConfig;
use std::path::PathBuf;
use std::{io::Write, path::Path};

/// Lazy durable traffic sink; construction never creates operator state.
pub struct FileTrafficAuditSink {
    root: Option<PathBuf>,
    retention: AuditRetentionConfig,
}
impl FileTrafficAuditSink {
    /// Injects a state root; traffic records live in its own `traffic-audit` directory.
    #[must_use]
    pub fn new(root: Option<PathBuf>, retention: AuditRetentionConfig) -> Self {
        Self { root, retention }
    }
}
impl TrafficAuditSink for FileTrafficAuditSink {
    fn append(&self, summary: &TrafficAuditSummary) -> Result<(), TrafficAuditError> {
        let line = summary.to_json()?;
        let bytes = u64::try_from(line.len())
            .map_err(|_| TrafficAuditError::RecordTooLarge)?
            .saturating_add(1);
        if bytes > self.retention.max_file_size {
            return Err(TrafficAuditError::RecordTooLarge);
        }
        if self.retention.max_files == 0 {
            return Err(TrafficAuditError::Storage);
        }
        let root = self.root.as_ref().ok_or(TrafficAuditError::Storage)?;
        private_directory(root)?;
        let dir = root.join("traffic-audit");
        private_directory(&dir)?;
        let lock = open_private(&dir.join(".lock"))?;
        fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| TrafficAuditError::Busy)?;
        let path = dir.join("audit.jsonl");
        validate_leaf(&path)?;
        super::rotate_if_large(
            &path,
            self.retention
                .max_file_size
                .saturating_sub(bytes)
                .saturating_add(1),
        )
        .map_err(|_| TrafficAuditError::Persistence)?;
        let mut file = open_private(&path)?;
        file.write_all(line.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.flush())
            .and_then(|()| file.sync_all())
            .map_err(|_| TrafficAuditError::Persistence)?;
        crate::infrastructure::state_file::sync_dir(&dir)
            .and_then(|()| crate::infrastructure::state_file::sync_dir(root))
            .map_err(|_| TrafficAuditError::Persistence)?;
        crate::infrastructure::retention::prune_audit_root(&dir, self.retention.max_files)
            .map_err(|_| TrafficAuditError::Persistence)
    }
}

fn private_directory(path: &Path) -> Result<(), TrafficAuditError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_dir() => return Err(TrafficAuditError::Storage),
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(TrafficAuditError::Storage);
        }
        _ => {}
    }
    crate::infrastructure::state_file::create_private_dir(path)
        .map_err(|_| TrafficAuditError::Storage)
}

fn validate_leaf(path: &Path) -> Result<(), TrafficAuditError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(TrafficAuditError::Storage),
    }
}

fn open_private(path: &Path) -> Result<std::fs::File, TrafficAuditError> {
    validate_leaf(path)?;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|_| TrafficAuditError::Storage)?;
    if !file
        .metadata()
        .map_err(|_| TrafficAuditError::Storage)?
        .is_file()
    {
        return Err(TrafficAuditError::Storage);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| TrafficAuditError::Storage)?;
    }
    Ok(file)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            Self(std::env::temp_dir().join(format!(
                    "fwdeck-p25b-sink-{}-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos(),
                    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                )))
        }
        fn sink(&self, max_files: usize, max_file_size: u64) -> FileTrafficAuditSink {
            FileTrafficAuditSink::new(
                Some(self.0.clone()),
                AuditRetentionConfig {
                    max_files,
                    max_file_size,
                },
            )
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn record() -> TrafficAuditSummary {
        TrafficAuditSummary::new(
            "test",
            crate::application::traffic_test_audit::tests::context(),
            1,
            std::time::Duration::ZERO,
            crate::application::traffic_test_audit::TrafficAuditOutcome::Shutdown,
            None,
        )
    }

    #[test]
    fn rotation_enforces_incoming_size_and_count_without_pruning_other_namespaces() {
        let root = Scratch::new();
        let record = record();
        let bytes = u64::try_from(record.to_json().unwrap().len() + 1).unwrap();
        let sink = root.sink(2, bytes);
        std::fs::create_dir_all(root.0.join("traffic-audit")).unwrap();
        std::fs::write(root.0.join("audit.jsonl"), "operation-marker").unwrap();
        std::fs::write(root.0.join("traffic-audit/unrelated.jsonl"), "keep").unwrap();
        for _ in 0..5 {
            sink.append(&record).unwrap();
        }
        let files: Vec<_> = std::fs::read_dir(root.0.join("traffic-audit"))
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("audit"))
            .collect();
        assert_eq!(files.len(), 2);
        for file in files {
            assert!(file.metadata().unwrap().len() <= bytes);
        }
        assert_eq!(
            std::fs::read_to_string(root.0.join("audit.jsonl")).unwrap(),
            "operation-marker"
        );
        assert_eq!(
            std::fs::read_to_string(root.0.join("traffic-audit/unrelated.jsonl")).unwrap(),
            "keep"
        );
        assert_eq!(
            root.sink(1, 1).append(&record),
            Err(TrafficAuditError::RecordTooLarge)
        );
        assert_eq!(
            root.sink(0, 4096).append(&record),
            Err(TrafficAuditError::Storage)
        );
    }

    #[test]
    fn zero_or_unavailable_configuration_never_creates_files() {
        let root = Scratch::new();
        assert_eq!(
            root.sink(1, 0).append(&record()),
            Err(TrafficAuditError::RecordTooLarge)
        );
        assert!(!root.0.exists());
        assert_eq!(
            FileTrafficAuditSink::new(
                None,
                AuditRetentionConfig {
                    max_files: 1,
                    max_file_size: 4096
                }
            )
            .append(&record()),
            Err(TrafficAuditError::Storage)
        );
    }

    #[test]
    fn independent_writer_lock_contention_is_typed_and_cannot_interleave_rotation() {
        let root = Scratch::new();
        let sink = root.sink(1, 4096);
        sink.append(&record()).unwrap();
        let lock = open_private(&root.0.join("traffic-audit/.lock")).unwrap();
        fs2::FileExt::try_lock_exclusive(&lock).unwrap();
        assert_eq!(sink.append(&record()), Err(TrafficAuditError::Busy));
        assert_eq!(
            std::fs::read_to_string(root.0.join("traffic-audit/audit.jsonl"))
                .unwrap()
                .lines()
                .count(),
            1
        );
        fs2::FileExt::unlock(&lock).unwrap();
        drop(lock);
        sink.append(&record()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_and_nonregular_directory_lock_and_log_are_rejected() {
        for leaf in [
            "traffic-audit",
            "traffic-audit/.lock",
            "traffic-audit/audit.jsonl",
        ] {
            let root = Scratch::new();
            let sink = root.sink(1, 4096);
            std::fs::create_dir_all(root.0.join("traffic-audit")).unwrap();
            let target = root.0.join("protected");
            std::fs::write(&target, "protected-marker").unwrap();
            let leaf_path = root.0.join(leaf);
            if leaf == "traffic-audit" {
                std::fs::remove_dir(&leaf_path).unwrap();
            }
            std::os::unix::fs::symlink(&target, &leaf_path).unwrap();
            assert_eq!(sink.append(&record()), Err(TrafficAuditError::Storage));
            assert_eq!(
                std::fs::read_to_string(&target).unwrap(),
                "protected-marker"
            );
        }
        let root = Scratch::new();
        std::fs::create_dir_all(root.0.join("traffic-audit/audit.jsonl")).unwrap();
        assert_eq!(
            root.sink(1, 4096).append(&record()),
            Err(TrafficAuditError::Storage)
        );
    }
    #[test]
    fn first_record_creates_only_private_traffic_namespace_and_durable_jsonl() {
        let root = std::env::temp_dir().join(format!(
            "fwdeck-traffic-audit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let sink = FileTrafficAuditSink::new(
            Some(root.clone()),
            AuditRetentionConfig {
                max_files: 2,
                max_file_size: 4096,
            },
        );
        assert!(!root.exists());
        let summary = crate::application::traffic_test_audit::TrafficAuditSummary::new(
            "test",
            crate::application::traffic_test_audit::tests::context(),
            1,
            std::time::Duration::ZERO,
            crate::application::traffic_test_audit::TrafficAuditOutcome::Shutdown,
            None,
        );
        sink.append(&summary).unwrap();
        let file = root.join("traffic-audit/audit.jsonl");
        assert!(file.is_file(), "accepted summary must be persisted");
        assert!(!root.join("audit.jsonl").exists());
        assert_eq!(std::fs::read_to_string(&file).unwrap().lines().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(file.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
