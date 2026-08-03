//! Bounded systemd dead-man's-switch adapter.

use std::sync::OnceLock;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::application::ports::{RollbackGuard, RollbackGuardError, RollbackGuardId};
use crate::domain::FirewallOperation;
use crate::infrastructure::firewalld::command;
use crate::infrastructure::process::{
    CommandRequest, CommandRunner, DEFAULT_TIMEOUT, TokioRunner, resolve_trusted,
};

const WATCHDOG_GRACE: Duration = Duration::from_secs(15);
static PROCESS_NONCE: OnceLock<u128> = OnceLock::new();

/// systemd-backed rollback guard. Every process invocation is argv-only,
/// trusted-path resolved, environment-cleared, and timeout-bounded by its
/// [`CommandRunner`].
pub struct SystemdRollbackGuard<R> {
    runner: R,
}

impl<R> SystemdRollbackGuard<R> {
    /// Creates a guard over the supplied process runner.
    pub const fn new(runner: R) -> Self {
        Self { runner }
    }
}

fn unit_name(id: RollbackGuardId) -> String {
    let nonce = PROCESS_NONCE.get_or_init(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    });
    format!(
        "fwdeck-rollback-{}-{nonce}-{}",
        std::process::id(),
        id.get()
    )
}

fn arm_args(
    unit: &str,
    delay: Duration,
    firewall_cmd: &std::path::Path,
    inverse_args: &[String],
) -> Vec<String> {
    let mut args = vec![
        "--collect".to_owned(),
        format!("--unit={unit}"),
        format!("--on-active={}s", delay.as_secs()),
        "--timer-property=AccuracySec=1s".to_owned(),
        firewall_cmd.to_string_lossy().into_owned(),
    ];
    args.extend(inverse_args.iter().cloned());
    args
}

fn disarm_args(unit: &str) -> Vec<String> {
    vec!["stop".to_owned(), format!("{unit}.timer")]
}

fn arm_request(
    unit: &str,
    delay: Duration,
    firewall_cmd: &std::path::Path,
    inverse_args: &[String],
) -> CommandRequest {
    CommandRequest {
        program: "systemd-run",
        args: arm_args(
            unit,
            delay.saturating_add(WATCHDOG_GRACE),
            firewall_cmd,
            inverse_args,
        ),
        timeout: DEFAULT_TIMEOUT,
    }
}

fn disarm_request(unit: &str) -> CommandRequest {
    CommandRequest {
        program: "systemctl",
        args: disarm_args(unit),
        timeout: DEFAULT_TIMEOUT,
    }
}

fn require_success(
    output: &crate::infrastructure::process::CommandOutput,
) -> Result<(), RollbackGuardError> {
    if output.exit_code == Some(0) {
        return Ok(());
    }
    let stderr = output.stderr.trim();
    let detail = if stderr.is_empty() {
        output.stdout.trim()
    } else {
        stderr
    };
    Err(RollbackGuardError::CommandFailed {
        code: output.exit_code.unwrap_or(-1),
        stderr: detail.chars().take(500).collect(),
    })
}

impl<R: CommandRunner> RollbackGuard for SystemdRollbackGuard<R> {
    async fn arm(
        &self,
        id: RollbackGuardId,
        operation: &FirewallOperation,
        delay: Duration,
    ) -> Result<Option<String>, RollbackGuardError> {
        let systemd_run = resolve_trusted("systemd-run");
        let systemctl = resolve_trusted("systemctl");
        let firewall_cmd = resolve_trusted(command::PROGRAM);
        if crate::infrastructure::process_uid() != 0
            || !systemd_run.is_absolute()
            || !systemctl.is_absolute()
            || !firewall_cmd.is_absolute()
        {
            return Ok(None);
        }
        let Some(runtime_inverse) = operation.inverse_runtime() else {
            return Ok(None);
        };
        let Some(planned) = command::plan(&runtime_inverse, DEFAULT_TIMEOUT)
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        let unit = unit_name(id);
        let request = arm_request(&unit, delay, &firewall_cmd, &planned.request.args);
        let output = self
            .runner
            .run(request)
            .await
            .map_err(|error| RollbackGuardError::Process(error.to_string()))?;
        require_success(&output)?;
        tracing::info!(unit, "rollback watchdog armed");
        Ok(Some(unit))
    }

    async fn disarm(&self, unit: &str) -> Result<(), RollbackGuardError> {
        let systemctl = resolve_trusted("systemctl");
        if !systemctl.is_absolute() {
            return Ok(());
        }
        let output = self
            .runner
            .run(disarm_request(unit))
            .await
            .map_err(|error| RollbackGuardError::Process(error.to_string()))?;
        require_success(&output)
    }
}

/// Cancels a watchdog from the UI shell using the same bounded adapter as the
/// engine. Best-effort callers can log the returned diagnostic and continue.
pub async fn disarm_watchdog(unit: &str) -> Result<(), RollbackGuardError> {
    SystemdRollbackGuard::new(TokioRunner).disarm(unit).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_ids_produce_distinct_process_scoped_units() {
        let first = unit_name(RollbackGuardId::new(41));
        let second = unit_name(RollbackGuardId::new(42));
        assert_ne!(first, second);
        assert!(first.ends_with("-41"));
        assert!(second.ends_with("-42"));
    }

    #[test]
    fn arm_request_contains_grace_and_is_timeout_bounded() {
        let request = arm_request(
            "fwdeck-rollback-42-7",
            Duration::from_secs(30),
            std::path::Path::new("/usr/bin/firewall-cmd"),
            &["--zone=public".to_owned(), "--add-service=ssh".to_owned()],
        );
        assert_eq!(request.program, "systemd-run");
        assert_eq!(request.timeout, DEFAULT_TIMEOUT);
        assert_eq!(
            request.args,
            [
                "--collect",
                "--unit=fwdeck-rollback-42-7",
                "--on-active=45s",
                "--timer-property=AccuracySec=1s",
                "/usr/bin/firewall-cmd",
                "--zone=public",
                "--add-service=ssh",
            ]
        );
    }

    #[test]
    fn disarm_request_is_timeout_bounded() {
        let request = disarm_request("fwdeck-rollback-42-7");
        assert_eq!(request.program, "systemctl");
        assert_eq!(request.timeout, DEFAULT_TIMEOUT);
        assert_eq!(request.args, ["stop", "fwdeck-rollback-42-7.timer"]);
    }
}
