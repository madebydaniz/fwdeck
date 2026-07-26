//! Structured audit trail: one JSON line per executed operation in
//! `~/.local/state/fwdeck/audit.jsonl`, rotated at ~5 MB. Failures are
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

/// Rotate `audit.jsonl` to `audit.jsonl.1` beyond this size.
const ROTATE_BYTES: u64 = 5 * 1024 * 1024;

/// Appends one JSON line describing `outcome` (id, timestamp, actor uid, host,
/// version, operation, status, per-step invocations) to `audit.jsonl`.
/// Returns the failure text when the line could not be written.
pub fn record(op_id: u64, outcome: &OperationOutcome) -> Result<(), String> {
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
    rotate_if_large(&path);
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
    writeln!(file, "{line}").map_err(|err| format!("audit write: {err}"))
}

/// One-deep rotation: `audit.jsonl` → `audit.jsonl.1` past [`ROTATE_BYTES`].
fn rotate_if_large(path: &std::path::Path) {
    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    if metadata.len() >= ROTATE_BYTES {
        let _ = std::fs::rename(path, path.with_extension("jsonl.1"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{ROTATE_BYTES, append_line, rotate_if_large};

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
        std::fs::write(
            &path,
            vec![b'x'; usize::try_from(ROTATE_BYTES).unwrap() + 1],
        )
        .unwrap();
        rotate_if_large(&path);
        assert!(
            !path.exists(),
            "oversized log should have been rotated away"
        );
        assert!(
            path.with_extension("jsonl.1").exists(),
            "rotated file missing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
