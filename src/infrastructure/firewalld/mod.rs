//! `firewall-cmd` backend: typed command construction, output parsing, and
//! error mapping. One implementation of the `FirewallBackend` trait (the D-Bus
//! backend is another), so it is swappable without touching the application or
//! UI layers.

pub mod command;
#[cfg(feature = "dbus")]
pub mod dbus;
pub mod errors;
pub mod parse;

use std::str::FromStr;
use std::time::Duration;

use crate::application::ports::{FirewallBackend, FirewallError, OperationOutcome, StepReport};
use std::collections::BTreeMap;

use crate::domain::{
    FirewallOperation, FirewallSnapshot, FirewallStatus, IpSetInfo, IpSetName, LogDenied,
    NetfilterBackend, PolicyDetails, PolicyName, ServiceDefinition, ServiceName,
};

/// Fallback so the browse overlay is never empty if `--get-services` fails.
use super::process::{CommandOutput, CommandRequest, CommandRunner, DEFAULT_TIMEOUT};

/// Path of the daemon config; `FirewallBackend=` is not exposed via firewall-cmd.
const FIREWALLD_CONF: &str = "/etc/firewalld/firewalld.conf";

/// `FirewallBackend` implementation that shells out to `firewall-cmd` (or
/// `firewall-offline-cmd` in offline mode) through a [`CommandRunner`].
/// Optional data (ipsets, policies, services, direct rules) soft-fails into
/// the snapshot's `degraded` list instead of killing the refresh.
/// Cached copies of the slow-moving snapshot sections (one subprocess per
/// object), refetched every [`HEAVY_SECTION_EVERY`] refreshes or immediately
/// after any mutation.
#[derive(Default)]
struct HeavySections {
    /// Refreshes since the last full heavy fetch; `None` forces a fetch.
    age: Option<u32>,
    ipsets: BTreeMap<IpSetName, IpSetInfo>,
    policies: BTreeMap<PolicyName, PolicyDetails>,
    direct_rules: Vec<String>,
    degraded: Vec<String>,
}

/// Heavy sections are refetched on every Nth refresh (they change rarely and
/// cost one process per object); mutations invalidate the cache immediately.
const HEAVY_SECTION_EVERY: u32 = 3;

/// The `firewall-cmd` backend: the full-featured reference implementation of
/// `FirewallBackend`. Sections that fail to fetch degrade with an honest
/// report instead of an empty lie; heavy sections are tier-cached.
pub struct CliBackend<R> {
    runner: R,
    timeout: Duration,
    mode: command::BackendMode,
    // process-lifetime cache — service definitions only change when
    // service files change; restart fwdeck to pick those up.
    definitions: std::sync::Mutex<BTreeMap<ServiceName, ServiceDefinition>>,
    /// Tiered-refresh cache for ipsets/policies/direct rules.
    heavy: std::sync::Mutex<HeavySections>,
}

impl<R: CommandRunner> CliBackend<R> {
    /// Live backend talking to a running daemon via `firewall-cmd`.
    pub fn new(runner: R) -> Self {
        Self::with_mode(runner, command::BackendMode::Live)
    }

    /// Offline backend: talks to `firewall-offline-cmd`, permanent config only,
    /// usable when the daemon is down (install / chroot / recovery).
    pub fn offline(runner: R) -> Self {
        Self::with_mode(runner, command::BackendMode::Offline)
    }

    fn with_mode(runner: R, mode: command::BackendMode) -> Self {
        Self {
            runner,
            timeout: DEFAULT_TIMEOUT,
            mode,
            definitions: std::sync::Mutex::new(BTreeMap::new()),
            heavy: std::sync::Mutex::new(HeavySections::default()),
        }
    }

    /// Whether this backend runs in offline mode (`firewall-offline-cmd`).
    #[must_use]
    pub fn is_offline(&self) -> bool {
        self.mode == command::BackendMode::Offline
    }

    /// Definitions for every referenced service; fetches only cache misses.
    /// Soft-fails per service — enrichment must never kill a snapshot.
    async fn service_definitions(
        &self,
        names: Vec<ServiceName>,
    ) -> BTreeMap<ServiceName, ServiceDefinition> {
        let missing: Vec<ServiceName> = {
            let cache = self
                .definitions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            names
                .iter()
                .filter(|name| !cache.contains_key(*name))
                .cloned()
                .collect()
        };
        let fetched = bounded_fan_out(missing.into_iter().map(|name| async move {
            let arg = format!("--info-service={name}");
            match self.run_ok(self.request(&[&arg])).await {
                Ok(raw) => Some((name, parse::parse_service_info(&raw))),
                Err(err) => {
                    tracing::warn!(service = %name, error = %err, "service info failed");
                    None
                }
            }
        }))
        .await;
        {
            let mut cache = self
                .definitions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cache.extend(fetched.into_iter().flatten());
        }
        let cache = self
            .definitions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        names
            .into_iter()
            .filter_map(|name| cache.get(&name).cloned().map(|def| (name, def)))
            .collect()
    }

    fn request(&self, args: &[&str]) -> CommandRequest {
        command::request_with(self.mode.program(), args, self.timeout)
    }

    async fn run(&self, request: CommandRequest) -> Result<CommandOutput, FirewallError> {
        self.runner
            .run(request)
            .await
            .map_err(errors::map_process_error)
    }

    /// Runs a command and requires exit code 0.
    async fn run_ok(&self, request: CommandRequest) -> Result<String, FirewallError> {
        let output = self.run(request).await?;
        if output.exit_code == Some(0) {
            Ok(output.stdout)
        } else {
            Err(errors::map_failure(&output))
        }
    }

    /// `--state` is special: exit 252 with "not running" is a valid answer,
    /// not an error.
    async fn daemon_running(&self) -> Result<bool, FirewallError> {
        let output = self.run(self.request(&["--state"])).await?;
        match (output.exit_code, output.stdout.trim()) {
            (Some(0), _) => Ok(true),
            (_, "not running") | (Some(errors::EXIT_NOT_RUNNING), _) => Ok(false),
            _ => Err(errors::map_failure(&output)),
        }
    }

    /// Full fetch of the tier-cached sections (plus available services, which
    /// is ordered between them to keep the fixture command order stable) and
    /// repopulation of the cache.
    #[allow(clippy::type_complexity)]
    async fn fetch_heavy_sections(
        &self,
    ) -> (
        BTreeMap<IpSetName, IpSetInfo>,
        BTreeMap<PolicyName, PolicyDetails>,
        Vec<String>,
        Vec<String>,
        Vec<ServiceName>,
        Option<String>,
    ) {
        let (ipsets, ipsets_err) = self.ipsets().await;
        let (direct_rules, direct_err) = self.direct_rules().await;
        let (available_services, services_err) = self.available_services().await;
        let (policies, policies_err) = self.policies().await;
        let degraded: Vec<String> = [ipsets_err, direct_err, policies_err]
            .into_iter()
            .flatten()
            .collect();
        let mut heavy = self
            .heavy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        heavy.age = Some(1);
        heavy.ipsets = ipsets.clone();
        heavy.policies = policies.clone();
        heavy.direct_rules.clone_from(&direct_rules);
        heavy.degraded.clone_from(&degraded);
        drop(heavy);
        (
            ipsets,
            policies,
            direct_rules,
            degraded,
            available_services,
            services_err,
        )
    }

    /// `firewall-cmd --check-config`: firewalld's own permanent-config lint.
    pub async fn check_config(&self) -> Result<(), FirewallError> {
        self.run_ok(self.request(&["--check-config"]))
            .await
            .map(|_| ())
    }

    /// `--query-panic`: exit 0 = on, exit 1 = off — both are answers.
    async fn panic_mode(&self) -> Result<bool, FirewallError> {
        let output = self.run(self.request(&["--query-panic"])).await?;
        match output.exit_code {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(errors::map_failure(&output)),
        }
    }

    /// IP sets are optional data: failures degrade to empty, never kill the
    /// snapshot — but the failure is reported so the UI can say "unknown"
    /// instead of "none".
    async fn ipsets(&self) -> (BTreeMap<IpSetName, IpSetInfo>, Option<String>) {
        let names = match self.run_ok(self.request(&["--get-ipsets"])).await {
            Ok(raw) => parse::parse_ipset_names(&raw).unwrap_or_default(),
            Err(err) => {
                tracing::warn!(error = %err, "ipset listing failed");
                return (BTreeMap::new(), Some(format!("ipsets: {err}")));
            }
        };
        // Concurrent: each `--info-ipset` spawn costs ~100 ms; serially that
        // scales with the set count and stalls every refresh (ADR-2 intent).
        let infos = bounded_fan_out(names.into_iter().map(|name| async move {
            let arg = format!("--info-ipset={name}");
            match self.run_ok(self.request(&[&arg])).await {
                Ok(raw) => Some((name, parse::parse_ipset_info(&raw))),
                Err(err) => {
                    tracing::warn!(ipset = %name, error = %err, "ipset info failed");
                    None
                }
            }
        }))
        .await;
        (infos.into_iter().flatten().collect(), None)
    }

    async fn available_services(&self) -> (Vec<ServiceName>, Option<String>) {
        match self.run_ok(self.request(&["--get-services"])).await {
            Ok(raw) => (parse::parse_service_names(&raw).unwrap_or_default(), None),
            Err(err) => {
                tracing::warn!(error = %err, "service listing failed");
                (Vec::new(), Some(format!("services: {err}")))
            }
        }
    }

    /// Policies degrade to empty on failure — optional data, never fatal, but
    /// the failure is reported for honest display.
    async fn policies(&self) -> (BTreeMap<PolicyName, PolicyDetails>, Option<String>) {
        let names = match self.run_ok(self.request(&["--get-policies"])).await {
            Ok(raw) => parse::parse_policy_names(&raw).unwrap_or_default(),
            Err(err) => {
                tracing::warn!(error = %err, "policy listing failed");
                return (BTreeMap::new(), Some(format!("policies: {err}")));
            }
        };
        let infos = bounded_fan_out(names.into_iter().map(|name| async move {
            let arg = format!("--info-policy={name}");
            match self.run_ok(self.request(&[&arg])).await {
                Ok(raw) => match parse::parse_policy_info(&raw) {
                    Ok(details) => Some((name, details)),
                    Err(err) => {
                        tracing::warn!(policy = %name, error = %err, "policy parse failed");
                        None
                    }
                },
                Err(err) => {
                    tracing::warn!(policy = %name, error = %err, "policy info failed");
                    None
                }
            }
        }))
        .await;
        (infos.into_iter().flatten().collect(), None)
    }

    async fn direct_rules(&self) -> (Vec<String>, Option<String>) {
        match self
            .run_ok(self.request(&["--direct", "--get-all-rules"]))
            .await
        {
            Ok(raw) => (parse::parse_direct_rules(&raw), None),
            Err(err) => {
                tracing::warn!(error = %err, "direct rule listing failed");
                (Vec::new(), Some(format!("direct rules: {err}")))
            }
        }
    }
}

/// Runs a set of independent fetch futures with bounded concurrency: enough
/// parallelism to hide the ~100 ms per-process spawn cost, without ever
/// stampeding the daemon with one process per object.
async fn bounded_fan_out<T>(
    futures: impl Iterator<Item = impl std::future::Future<Output = T>>,
) -> Vec<T> {
    use futures_util::StreamExt as _;
    futures_util::stream::iter(futures)
        .buffer_unordered(8)
        .collect()
        .await
}

/// Reads the configured netfilter backend from firewalld.conf. Shared by the
/// CLI and D-Bus backends — the setting is not exposed over either API, so
/// both must read the daemon's config file.
pub(crate) fn netfilter_backend() -> NetfilterBackend {
    std::fs::read_to_string(FIREWALLD_CONF)
        .ok()
        .map_or(NetfilterBackend::Unknown, |conf| {
            parse::parse_conf_backend(&conf)
        })
}

impl<R: CommandRunner> FirewallBackend for CliBackend<R> {
    async fn probe(&self) -> Result<FirewallStatus, FirewallError> {
        // Offline mode reads the permanent config with no running daemon.
        if self.is_offline() {
            let version = self
                .run_ok(self.request(&["--version"]))
                .await
                .ok()
                .map(|v| v.trim().to_owned());
            let log_denied = self
                .run_ok(self.request(&["--get-log-denied"]))
                .await
                .ok()
                .and_then(|raw| LogDenied::from_str(raw.trim()).ok())
                .unwrap_or(LogDenied::Off);
            return Ok(FirewallStatus {
                daemon_running: false,
                version,
                backend: netfilter_backend(),
                log_denied,
                panic_mode: false,
            });
        }
        let daemon_running = self.daemon_running().await?;
        // Client version works even when the daemon is down.
        let version = self
            .run_ok(self.request(&["--version"]))
            .await
            .ok()
            .map(|v| v.trim().to_owned());
        let (log_denied, panic_mode) = if daemon_running {
            let raw = self.run_ok(self.request(&["--get-log-denied"])).await?;
            let log_denied = LogDenied::from_str(raw.trim())
                .map_err(|err| FirewallError::Parse(err.to_string()))?;
            (log_denied, self.panic_mode().await?)
        } else {
            (LogDenied::Off, false)
        };
        Ok(FirewallStatus {
            daemon_running,
            version,
            backend: netfilter_backend(),
            log_denied,
            panic_mode,
        })
    }

    async fn snapshot(&self) -> Result<FirewallSnapshot, FirewallError> {
        let status = self.probe().await?;
        if !status.daemon_running && !self.is_offline() {
            return Err(FirewallError::DaemonNotRunning);
        }

        let default_zone = self.run_ok(self.request(&["--get-default-zone"])).await?;
        let default_zone = parse::parse_default_zone(&default_zone)?;

        // Offline: no daemon → no active zones, and the single permanent config
        // stands in for both runtime and permanent (there is no drift offline).
        let (active, runtime, permanent) = if self.is_offline() {
            let config = self.run_ok(self.request(&["--list-all-zones"])).await?;
            let config = parse::parse_list_all_zones(&config)?;
            (BTreeMap::new(), config.clone(), config)
        } else {
            let active = self.run_ok(self.request(&["--get-active-zones"])).await?;
            let active = parse::parse_active_zones(&active)?;
            let runtime = self.run_ok(self.request(&["--list-all-zones"])).await?;
            let runtime = parse::parse_list_all_zones(&runtime)?;
            let permanent = self
                .run_ok(self.request(&["--permanent", "--list-all-zones"]))
                .await?;
            let permanent = parse::parse_list_all_zones(&permanent)?;
            (active, runtime, permanent)
        };
        // Tiered refresh: the per-object sections (one subprocess each) are
        // reused for a few refreshes; mutations invalidate the cache.
        let cached = {
            let mut heavy = self
                .heavy
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(age) = heavy.age.as_mut()
                && *age < HEAVY_SECTION_EVERY
            {
                *age += 1;
                Some((
                    heavy.ipsets.clone(),
                    heavy.policies.clone(),
                    heavy.direct_rules.clone(),
                    heavy.degraded.clone(),
                ))
            } else {
                None
            }
        };
        let (ipsets, policies, direct_rules, mut degraded, available_services, services_err) =
            if let Some((ipsets, policies, direct_rules, degraded)) = cached {
                let (available_services, services_err) = self.available_services().await;
                (
                    ipsets,
                    policies,
                    direct_rules,
                    degraded,
                    available_services,
                    services_err,
                )
            } else {
                self.fetch_heavy_sections().await
            };
        degraded.extend(services_err);

        let mut snapshot = FirewallSnapshot {
            status,
            default_zone,
            active,
            runtime,
            permanent,
            ipsets,
            service_definitions: BTreeMap::new(),
            available_services,
            policies,
            direct_rules,
            degraded,
        };
        snapshot.service_definitions = self
            .service_definitions(snapshot.referenced_services())
            .await;
        Ok(snapshot)
    }

    async fn apply(&self, operation: &FirewallOperation) -> OperationOutcome {
        // Any mutation invalidates the tiered heavy-section cache: the very
        // next refresh refetches ipsets/policies/direct rules.
        self.heavy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .age = None;
        let planned = command::plan_in(operation, self.timeout, self.mode);
        if planned.is_empty() {
            return OperationOutcome::Failed {
                operation: operation.clone(),
                steps: vec![StepReport {
                    target: "offline",
                    invocation: Vec::new(),
                    result: Err(FirewallError::Process(
                        "operation has no offline-mode equivalent".to_owned(),
                    )),
                }],
            };
        }
        let mut steps: Vec<StepReport> = Vec::with_capacity(planned.len());

        for (index, step) in planned.into_iter().enumerate() {
            let result = self.run_ok(step.request.clone()).await.map(|_| ());
            let failed = result.is_err();
            steps.push(StepReport {
                target: step.target,
                invocation: step.request.args,
                result,
            });
            if failed {
                // A timeout means the command MAY have taken effect after the
                // response was lost — that is not a failure, it is unknown.
                let timed_out = matches!(
                    steps.last().and_then(|step| step.result.as_ref().err()),
                    Some(FirewallError::Timeout(_))
                );
                if timed_out {
                    return OperationOutcome::Indeterminate {
                        operation: operation.clone(),
                        steps,
                    };
                }
                // Nothing applied yet → clean failure. Runtime already applied
                // → honest partial report with rollback metadata (ADR-3).
                return if index == 0 {
                    OperationOutcome::Failed {
                        operation: operation.clone(),
                        steps,
                    }
                } else {
                    OperationOutcome::PartiallyApplied {
                        operation: operation.clone(),
                        steps,
                        rollback_hint: operation.inverse_runtime(),
                    }
                };
            }
        }
        OperationOutcome::Applied {
            operation: operation.clone(),
            steps,
        }
    }
}
