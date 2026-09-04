//! Infrastructure layer: process execution and the firewall-cmd backend.
//! Implements the ports defined by the application layer.

pub mod audit;
pub mod counters;
pub mod firewalld;
pub mod install;
pub mod logs;
pub mod process;
pub mod retention;
pub mod rollback;
pub mod snapshot_store;
mod state_file;
pub mod traffic_test_store;

use firewalld::command::ExportFormat;

/// Writes a rendered export to `~/.local/state/fwdeck/exports/` and returns the
/// path. The filename is deterministic per format (overwritten each time) to
/// avoid needing a clock in this layer.
pub fn export_write(format: ExportFormat, contents: &str) -> Result<String, String> {
    let dir = crate::bootstrap::ensure_state_dir()
        .ok_or_else(|| "no state directory".to_owned())?
        .join("exports");
    state_file::create_private_dir(&dir).map_err(|err| err.to_string())?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());
    let path = write_export_file(&dir, format, stamp, contents).map_err(|err| err.to_string())?;
    Ok(path.display().to_string())
}

fn write_export_file(
    dir: &std::path::Path,
    format: ExportFormat,
    stamp: u128,
    contents: &str,
) -> std::io::Result<std::path::PathBuf> {
    state_file::write_private_atomic_unique(dir, contents.as_bytes(), |collision| {
        let suffix = if collision == 0 {
            String::new()
        } else {
            format!("-{collision}")
        };
        dir.join(format!(
            "staged-plan-{stamp}{suffix}.{}",
            format.extension()
        ))
    })
}

/// The current effective uid (0 on non-Unix). Shared by doctor and audit.
#[must_use]
pub fn process_uid() -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        // Bias toward "not root" when the probe fails: a false root reading
        // would arm the root-only watchdog we can't actually run.
        std::fs::metadata("/proc/self").map_or(u32::MAX, |m| m.uid())
    }
    #[cfg(not(unix))]
    0
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{ExportFormat, write_export_file};

    #[test]
    fn same_millisecond_exports_are_private_complete_and_distinct() {
        let dir = std::env::temp_dir().join(format!("fwdeck-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        super::state_file::create_private_dir(&dir).unwrap();
        let first = write_export_file(&dir, ExportFormat::Json, 1, "old").unwrap();
        let second = write_export_file(&dir, ExportFormat::Json, 1, "new").unwrap();
        assert_ne!(first, second);
        assert_eq!(std::fs::read_to_string(&first).unwrap(), "old");
        assert_eq!(std::fs::read_to_string(&second).unwrap(), "new");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&first).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
