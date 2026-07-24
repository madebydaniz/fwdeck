//! Process execution behind a trait so command construction and parsing can be
//! tested with a fake runner. No shell is ever involved: `program` is a bare
//! executable name and `args` a typed-built vector.

use std::future::Future;
use std::process::Stdio;
use std::time::{Duration, Instant};

/// Default per-process timeout. A healthy firewall-cmd answers in milliseconds.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// One process invocation to execute: bare program name, typed-built argv,
/// and a hard timeout. No shell interpretation anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRequest {
    /// Bare executable name, resolved via [`resolve_trusted`] at spawn time.
    pub program: &'static str,
    /// Arguments, each an exact argv element (never shell-joined).
    pub args: Vec<String>,
    /// Hard deadline; on expiry the child is killed and
    /// [`ProcessError::Timeout`] is returned.
    pub timeout: Duration,
}

/// Captured result of a finished process.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// `None` when the process was killed by a signal.
    pub exit_code: Option<i32>,
    /// Captured stdout, lossily decoded as UTF-8.
    pub stdout: String,
    /// Captured stderr, lossily decoded as UTF-8.
    pub stderr: String,
    /// Wall-clock time from spawn to exit.
    pub duration: Duration,
}

/// Failures where the process produced no usable output at all — as opposed
/// to running and exiting non-zero, which is a [`CommandOutput`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProcessError {
    /// The executable does not exist (mapped to `FirewallError::NotInstalled`).
    #[error("executable `{0}` not found")]
    NotFound(&'static str),
    /// Spawn failed for a reason other than a missing binary.
    #[error("failed to spawn `{program}`: {message}")]
    Spawn {
        /// The program that failed to spawn.
        program: &'static str,
        /// OS error description.
        message: String,
    },
    /// Reading the child's output failed.
    #[error("process I/O error: {0}")]
    Io(String),
    /// The timeout elapsed; the child was killed (`kill_on_drop`).
    #[error("process timed out after {0:?}")]
    Timeout(Duration),
}

/// Process-execution port: the firewalld backend depends on this, so command
/// construction and parsing are testable with a fake runner.
pub trait CommandRunner: Send + Sync + 'static {
    /// Runs `request` to completion (or timeout) and captures its output.
    fn run(
        &self,
        request: CommandRequest,
    ) -> impl Future<Output = Result<CommandOutput, ProcessError>> + Send;
}

/// The only directories privileged system binaries are resolved from — a
/// tool that runs as root must never let a user-writable `PATH` entry decide
/// which `firewall-cmd` gets executed.
pub const TRUSTED_BIN_DIRS: [&str; 4] = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

/// Resolves `program` against [`TRUSTED_BIN_DIRS`] only. Falls back to the
/// bare name (regular `PATH` lookup) when not found there, so unusual layouts
/// still work — but the trusted directories always win.
#[must_use]
pub fn resolve_trusted(program: &str) -> std::path::PathBuf {
    for dir in TRUSTED_BIN_DIRS {
        let candidate = std::path::Path::new(dir).join(program);
        if candidate.is_file() {
            return candidate;
        }
    }
    std::path::PathBuf::from(program)
}

/// Real runner on tokio. Binaries resolve from trusted directories, the
/// environment is cleared down to a pinned-locale whitelist (no `LD_*` /
/// `PYTHON*` inheritance into a privileged child), and `kill_on_drop` reaps
/// children abandoned by a timeout.
pub struct TokioRunner;

impl CommandRunner for TokioRunner {
    async fn run(&self, request: CommandRequest) -> Result<CommandOutput, ProcessError> {
        let started = Instant::now();
        let child = tokio::process::Command::new(resolve_trusted(request.program))
            .args(&request.args)
            .env_clear()
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("PATH", TRUSTED_BIN_DIRS.join(":"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| match err.kind() {
                std::io::ErrorKind::NotFound => ProcessError::NotFound(request.program),
                _ => ProcessError::Spawn {
                    program: request.program,
                    message: err.to_string(),
                },
            })?;

        let output = tokio::time::timeout(request.timeout, child.wait_with_output())
            .await
            .map_err(|_| ProcessError::Timeout(request.timeout))?
            .map_err(|err| ProcessError::Io(err.to_string()))?;

        let duration = started.elapsed();
        tracing::debug!(
            program = request.program,
            args = ?request.args,
            exit = ?output.status.code(),
            elapsed_ms = duration.as_millis(),
            "command finished"
        );
        Ok(CommandOutput {
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            duration,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn request(program: &'static str, args: &[&str], timeout: Duration) -> CommandRequest {
        CommandRequest {
            program,
            args: args.iter().map(|&a| a.to_owned()).collect(),
            timeout,
        }
    }

    #[tokio::test]
    async fn pins_the_locale() {
        let output = TokioRunner
            .run(request("env", &[], DEFAULT_TIMEOUT))
            .await
            .unwrap();
        assert!(output.stdout.contains("LC_ALL=C"));
        assert!(output.stdout.contains("LANG=C"));
    }

    #[tokio::test]
    async fn captures_exit_code_and_streams_separately() {
        let output = TokioRunner
            .run(request(
                "sh",
                &["-c", "echo out; echo err >&2; exit 3"],
                DEFAULT_TIMEOUT,
            ))
            .await
            .unwrap();
        assert_eq!(output.exit_code, Some(3));
        assert_eq!(output.stdout.trim(), "out");
        assert_eq!(output.stderr.trim(), "err");
    }

    #[tokio::test]
    async fn times_out_and_kills_slow_processes() {
        let result = TokioRunner
            .run(request("sleep", &["5"], Duration::from_millis(50)))
            .await;
        assert!(matches!(result, Err(ProcessError::Timeout(_))));
    }

    #[tokio::test]
    async fn maps_missing_executables() {
        let result = TokioRunner
            .run(request("fwdeck-does-not-exist", &[], DEFAULT_TIMEOUT))
            .await;
        assert!(matches!(result, Err(ProcessError::NotFound(_))));
    }
}
