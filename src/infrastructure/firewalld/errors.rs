//! Exit-code and stderr mapping to `FirewallError` categories. The constants
//! and patterns below are verified against real outputs captured in
//! `tests/fixtures/firewall_cmd/`.

use crate::application::ports::FirewallError;
use crate::infrastructure::process::{CommandOutput, ProcessError};

/// firewalld `NOT_RUNNING` (fixture: `state_not_running.txt`, exit 252).
pub const EXIT_NOT_RUNNING: i32 = 252;
/// firewalld `NOT_AUTHORIZED` (fixture: `perm_denied_stderr.txt`, exit 253).
pub const EXIT_NOT_AUTHORIZED: i32 = 253;

/// Maps a spawn/timeout/IO failure (the process never answered usefully) to
/// its `FirewallError` category: missing binary → `NotInstalled`, timeout →
/// `Timeout`, anything else → `Process`.
#[must_use]
pub fn map_process_error(err: ProcessError) -> FirewallError {
    match err {
        ProcessError::NotFound(_) => FirewallError::NotInstalled,
        ProcessError::Timeout(duration) => FirewallError::Timeout(duration),
        other => FirewallError::Process(other.to_string()),
    }
}

/// Categorizes a non-zero exit by code or stderr pattern: 253 /
/// `Authorization failed` → `PermissionDenied` (keeping the human stderr
/// line, dropping any D-Bus traceback), 252 / `FirewallD is not running` →
/// `DaemonNotRunning`, otherwise `CommandFailed` with stderr truncated for
/// display.
#[must_use]
pub fn map_failure(output: &CommandOutput) -> FirewallError {
    let stderr = output.stderr.trim();
    let code = output.exit_code.unwrap_or(-1);

    if code == EXIT_NOT_AUTHORIZED
        || stderr.contains("Authorization failed")
        || stderr.contains("NotAuthorizedException")
    {
        // The stderr may contain a D-Bus traceback; keep the human line.
        let detail = stderr
            .lines()
            .find(|line| line.contains("Authorization failed"))
            .unwrap_or("run as root or configure polkit")
            .trim()
            .to_owned();
        return FirewallError::PermissionDenied { detail };
    }
    if code == EXIT_NOT_RUNNING || stderr.contains("FirewallD is not running") {
        return FirewallError::DaemonNotRunning;
    }
    FirewallError::CommandFailed {
        code,
        stderr: truncate(stderr, 300),
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        text.to_owned()
    } else {
        let mut end = max;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &text[..end])
    }
}
