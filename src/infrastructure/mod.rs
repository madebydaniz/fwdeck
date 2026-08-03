//! Infrastructure layer: process execution and the firewall-cmd backend.
//! Implements the ports defined by the application layer.

pub mod audit;
pub mod counters;
pub mod firewalld;
pub mod install;
pub mod logs;
pub mod process;
pub mod rollback;
pub mod snapshot_store;

use std::io::Write;

use firewalld::command::ExportFormat;

/// Writes a rendered export to `~/.local/state/fwdeck/exports/` and returns the
/// path. The filename is deterministic per format (overwritten each time) to
/// avoid needing a clock in this layer.
pub fn export_write(format: ExportFormat, contents: &str) -> Result<String, String> {
    let dir = crate::bootstrap::state_dir()
        .ok_or_else(|| "no state directory".to_owned())?
        .join("exports");
    std::fs::create_dir_all(&dir).map_err(|err| err.to_string())?;
    let path = dir.join(format!("staged-plan.{}", format.extension()));
    let mut file = std::fs::File::create(&path).map_err(|err| err.to_string())?;
    file.write_all(contents.as_bytes())
        .map_err(|err| err.to_string())?;
    Ok(path.display().to_string())
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
