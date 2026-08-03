//! Structured audit trail: one JSON line per executed operation in
//! `~/.local/state/fwdeck/audit.jsonl`, rotated at the configured size into
//! timestamped archives. Failures are
//! returned to the caller so the UI can surface them — a silent audit gap in
//! a firewall tool is itself an incident. Files and the state dir are created
//! private (`0700`/`0600`) — audit lines reveal topology.
//!
//! This is an *advisory, append-only* record, not a cryptographically
//! tamper-evident log: anyone who can write the file can rewrite it. For
//! integrity guarantees, ship the JSONL to a central log store.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::application::ports::OperationOutcome;
use crate::config::AuditRetentionConfig;

/// Appends one JSON line describing `outcome` (id, timestamp, actor uid, host,
/// version, operation, status, per-step invocations) to `audit.jsonl`.
/// Returns the failure text when the line could not be written.
pub fn record(
    op_id: u64,
    outcome: &OperationOutcome,
    retention: AuditRetentionConfig,
) -> Result<(), String> {
    let Some(dir) = crate::bootstrap::ensure_state_dir() else {
        return Err("no state directory available".to_owned());
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let status = match outcome {
        OperationOutcome::Applied { .. } => "applied",
        OperationOutcome::PartiallyApplied { .. } => "partially-applied",
        OperationOutcome::Failed { .. } => "failed",
        OperationOutcome::Indeterminate { .. } => "indeterminate",
    };
    let steps: Vec<serde_json::Value> = outcome
        .steps()
        .iter()
        .map(|step| {
            serde_json::json!({
                "target": step.target,
                "invocation": step.invocation,
                "ok": step.result.is_ok(),
                "error": step.result.as_ref().err().map(ToString::to_string),
            })
        })
        .collect();
    let line = serde_json::json!({
        "id": op_id,
        "ts": timestamp,
        "uid": super::process_uid(),
        "host": crate::bootstrap::hostname(),
        "fwdeck": env!("CARGO_PKG_VERSION"),
        "operation": outcome.operation().describe(),
        "target": outcome.operation().target().label(),
        "status": status,
        "steps": steps,
    });
    let path = dir.join("audit.jsonl");
    rotate_if_large(&path, retention.max_file_size)?;
    append_line(&path, &line.to_string())
}

/// Appends `line` plus a newline to `path`, creating it `0600` (audit lines
/// reveal firewall topology). Split out so the append/permission behavior is
/// unit-testable without a real state directory.
fn append_line(path: &std::path::Path, line: &str) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|err| format!("audit open: {err}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("audit chmod: {err}"))?;
    }
    file.write_all(format!("{line}\n").as_bytes())
        .map_err(|err| format!("audit write: {err}"))?;
    file.sync_data().map_err(|err| format!("audit sync: {err}"))
}

/// Moves an oversized active log to a timestamped, collision-safe archive.
fn rotate_if_large(path: &std::path::Path, max_bytes: u64) -> Result<(), String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());
    rotate_if_large_at(path, max_bytes, stamp)
}

fn rotate_if_large_at(path: &std::path::Path, max_bytes: u64, stamp: u128) -> Result<(), String> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("audit metadata: {err}")),
    };
    if metadata.len() < max_bytes {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("audit chmod before rotation: {err}"))?;
    }
    let dir = path
        .parent()
        .ok_or_else(|| "audit path has no parent directory".to_owned())?;
    super::state_file::move_atomic_unique(path, |collision| {
        let suffix = if collision == 0 {
            String::new()
        } else {
            format!("-{collision}")
        };
        dir.join(format!("audit-{stamp}{suffix}.jsonl"))
    })
    .map(|_| ())
    .map_err(|err| format!("audit rotation: {err}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{append_line, rotate_if_large_at};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("fwdeck-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn append_is_private_and_accumulates() {
        let dir = scratch("audit-append");
        let path = dir.join("audit.jsonl");
        append_line(&path, r#"{"a":1}"#).unwrap();
        append_line(&path, r#"{"b":2}"#).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"a\":1}\n{\"b\":2}\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "audit file must be 0600");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotates_once_past_threshold() {
        let dir = scratch("audit-rotate");
        let path = dir.join("audit.jsonl");
        std::fs::write(&path, b"oversized").unwrap();
        rotate_if_large_at(&path, 4, 123).unwrap();
        assert!(
            !path.exists(),
            "oversized log should have been rotated away"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("audit-123.jsonl")).unwrap(),
            "oversized"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_timestamp_rotation_never_clobbers_an_archive() {
        let dir = scratch("audit-rotate-collision");
        let path = dir.join("audit.jsonl");
        std::fs::write(&path, b"first").unwrap();
        rotate_if_large_at(&path, 1, 123).unwrap();
        std::fs::write(&path, b"second").unwrap();
        rotate_if_large_at(&path, 1, 123).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("audit-123.jsonl")).unwrap(),
            "first"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("audit-123-1.jsonl")).unwrap(),
            "second"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
