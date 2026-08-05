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

struct RollbackPrerequisites {
    uid: u32,
    systemd_run: std::path::PathBuf,
    systemctl: std::path::PathBuf,
    firewall_cmd: std::path::PathBuf,
}

impl RollbackPrerequisites {
    fn resolve() -> Self {
        Self {
            uid: crate::infrastructure::process_uid(),
            systemd_run: resolve_trusted("systemd-run"),
            systemctl: resolve_trusted("systemctl"),
            firewall_cmd: resolve_trusted(command::PROGRAM),
        }
    }

    fn available(&self) -> bool {
        self.uid == 0
            && self.systemd_run.is_absolute()
            && self.systemctl.is_absolute()
            && self.firewall_cmd.is_absolute()
    }
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

impl<R: CommandRunner> SystemdRollbackGuard<R> {
    async fn arm_with_prerequisites(
        &self,
        id: RollbackGuardId,
        operation: &FirewallOperation,
        delay: Duration,
        prerequisites: &RollbackPrerequisites,
    ) -> Result<Option<String>, RollbackGuardError> {
        if !prerequisites.available() {
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
        let request = arm_request(
            &unit,
            delay,
            &prerequisites.firewall_cmd,
            &planned.request.args,
        );
        let output = self
            .runner
            .run(request)
            .await
            .map_err(|error| RollbackGuardError::Process(error.to_string()))?;
        require_success(&output)?;
        tracing::info!(unit, "rollback watchdog armed");
        Ok(Some(unit))
    }

    async fn disarm_with_path(
        &self,
        unit: &str,
        systemctl: &std::path::Path,
    ) -> Result<(), RollbackGuardError> {
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

impl<R: CommandRunner> RollbackGuard for SystemdRollbackGuard<R> {
    async fn arm(
        &self,
        id: RollbackGuardId,
        operation: &FirewallOperation,
        delay: Duration,
    ) -> Result<Option<String>, RollbackGuardError> {
        self.arm_with_prerequisites(id, operation, delay, &RollbackPrerequisites::resolve())
            .await
    }

    async fn disarm(&self, unit: &str) -> Result<(), RollbackGuardError> {
        let systemctl = resolve_trusted("systemctl");
        self.disarm_with_path(unit, &systemctl).await
    }
}

/// Cancels a watchdog from the UI shell using the same bounded adapter as the
/// engine. Best-effort callers can log the returned diagnostic and continue.
pub async fn disarm_watchdog(unit: &str) -> Result<(), RollbackGuardError> {
    SystemdRollbackGuard::new(TokioRunner).disarm(unit).await
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::domain::{ConfigurationTarget, ServiceName, ZoneName};
    use crate::infrastructure::process::{CommandOutput, ProcessError};

    #[derive(Clone, Default)]
    struct FakeRunner {
        queue: Arc<Mutex<VecDeque<Result<CommandOutput, ProcessError>>>>,
        seen: Arc<Mutex<Vec<CommandRequest>>>,
    }

    impl FakeRunner {
        fn push(&self, response: Result<CommandOutput, ProcessError>) {
            self.queue.lock().unwrap().push_back(response);
        }

        fn seen(&self) -> Vec<CommandRequest> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl CommandRunner for FakeRunner {
        async fn run(&self, request: CommandRequest) -> Result<CommandOutput, ProcessError> {
            self.seen.lock().unwrap().push(request);
            self.queue
                .lock()
                .unwrap()
                .pop_front()
                .expect("guard issued an unexpected extra command")
        }
    }

    fn output(exit_code: Option<i32>, stdout: &str, stderr: &str) -> CommandOutput {
        CommandOutput {
            exit_code,
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
            duration: Duration::ZERO,
        }
    }

    fn prerequisites(uid: u32) -> RollbackPrerequisites {
        RollbackPrerequisites {
            uid,
            systemd_run: "/usr/bin/systemd-run".into(),
            systemctl: "/usr/bin/systemctl".into(),
            firewall_cmd: "/usr/bin/firewall-cmd".into(),
        }
    }

    fn reversible_operation() -> FirewallOperation {
        FirewallOperation::AddService {
            zone: ZoneName::parse("public").unwrap(),
            service: ServiceName::parse("ssh").unwrap(),
            target: ConfigurationTarget::Runtime,
        }
    }

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

    #[test]
    fn command_failures_use_stderr_then_stdout_and_bound_the_detail() {
        let long_stderr = "x".repeat(600);
        let error = require_success(&output(Some(7), "ignored", &long_stderr)).unwrap_err();
        assert!(matches!(
            error,
            RollbackGuardError::CommandFailed { code: 7, stderr } if stderr.len() == 500
        ));

        let error = require_success(&output(None, "fallback detail\n", "")).unwrap_err();
        assert_eq!(
            error,
            RollbackGuardError::CommandFailed {
                code: -1,
                stderr: "fallback detail".to_owned(),
            }
        );
        assert!(require_success(&output(Some(0), "", "")).is_ok());
    }

    #[tokio::test]
    async fn arm_skips_unavailable_or_non_reversible_operations_without_a_process() {
        let runner = FakeRunner::default();
        let guard = SystemdRollbackGuard::new(runner.clone());

        assert!(
            guard
                .arm_with_prerequisites(
                    RollbackGuardId::new(1),
                    &reversible_operation(),
                    Duration::from_secs(30),
                    &prerequisites(1000),
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            guard
                .arm_with_prerequisites(
                    RollbackGuardId::new(2),
                    &FirewallOperation::Reload,
                    Duration::from_secs(30),
                    &prerequisites(0),
                )
                .await
                .unwrap()
                .is_none()
        );
        assert!(runner.seen().is_empty());
    }

    #[tokio::test]
    async fn arm_runs_the_runtime_inverse_and_returns_the_unit() {
        let runner = FakeRunner::default();
        runner.push(Ok(output(Some(0), "Running as unit", "")));
        let guard = SystemdRollbackGuard::new(runner.clone());

        let unit = guard
            .arm_with_prerequisites(
                RollbackGuardId::new(7),
                &reversible_operation(),
                Duration::from_secs(30),
                &prerequisites(0),
            )
            .await
            .unwrap()
            .unwrap();

        assert!(unit.starts_with("fwdeck-rollback-"));
        assert!(unit.ends_with("-7"));
        let seen = runner.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].program, "systemd-run");
        assert_eq!(seen[0].timeout, DEFAULT_TIMEOUT);
        assert!(seen[0].args.contains(&"--remove-service=ssh".to_owned()));
    }

    #[tokio::test]
    async fn arm_maps_runner_and_command_failures() {
        let runner = FakeRunner::default();
        runner.push(Err(ProcessError::Io("pipe closed".to_owned())));
        runner.push(Ok(output(Some(5), "", "permission denied")));
        let guard = SystemdRollbackGuard::new(runner);
        let operation = reversible_operation();
        let prerequisites = prerequisites(0);

        assert!(matches!(
            guard
                .arm_with_prerequisites(
                    RollbackGuardId::new(8),
                    &operation,
                    Duration::from_secs(30),
                    &prerequisites,
                )
                .await,
            Err(RollbackGuardError::Process(message)) if message.contains("pipe closed")
        ));
        assert!(matches!(
            guard
                .arm_with_prerequisites(
                    RollbackGuardId::new(9),
                    &operation,
                    Duration::from_secs(30),
                    &prerequisites,
                )
                .await,
            Err(RollbackGuardError::CommandFailed { code: 5, stderr })
                if stderr == "permission denied"
        ));
    }

    #[tokio::test]
    async fn disarm_handles_unavailable_success_and_failure_paths() {
        let runner = FakeRunner::default();
        runner.push(Ok(output(Some(0), "", "")));
        runner.push(Err(ProcessError::Io("systemctl pipe".to_owned())));
        let guard = SystemdRollbackGuard::new(runner.clone());

        guard
            .disarm_with_path("unit-a", std::path::Path::new("systemctl"))
            .await
            .unwrap();
        guard
            .disarm_with_path("unit-b", std::path::Path::new("/usr/bin/systemctl"))
            .await
            .unwrap();
        assert!(matches!(
            guard
                .disarm_with_path("unit-c", std::path::Path::new("/usr/bin/systemctl"))
                .await,
            Err(RollbackGuardError::Process(message)) if message.contains("systemctl pipe")
        ));

        let seen = runner.seen();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], disarm_request("unit-b"));
        assert_eq!(seen[1], disarm_request("unit-c"));
    }
}
