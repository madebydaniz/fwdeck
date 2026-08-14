//! `firewall-cmd` backend: typed command construction, output parsing, and
//! error mapping. One implementation of the `FirewallBackend` trait (the D-Bus
//! backend is another), so it is swappable without touching the application or
//! UI layers.

pub mod command;
#[cfg(feature = "dbus")]
pub mod dbus;
mod detail_priority;
pub mod errors;
pub mod parse;

use std::str::FromStr;
use std::time::{Duration, Instant};

use crate::application::ports::{
    FirewallBackend, FirewallError, OperationOutcome, OverviewRead, SnapshotRead, StepReport,
};
use crate::application::{RefreshOverview, RefreshPrioritySource};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::domain::{
    ActiveZone, ConfigurationTarget, DegradedSection, FirewallOperation, FirewallSnapshot,
    FirewallStatus, IpSetInfo, IpSetName, LogDenied, NetfilterBackend, PolicyDetails, PolicyName,
    RefreshObservation, RefreshSection, RefreshSectionObservation, Scoped, ServiceDefinition,
    ServiceName, SnapshotSection, ZoneDetails, ZoneName,
};
use detail_priority::{DetailQueue, DetailWork};

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
    ipsets: Scoped<BTreeMap<IpSetName, IpSetInfo>>,
    policies: Scoped<BTreeMap<PolicyName, PolicyDetails>>,
    direct_rules: Vec<String>,
    degraded: Vec<DegradedSection>,
}

/// Heavy sections are refetched on every Nth refresh (they change rarely and
/// cost one process per object); mutations invalidate the cache immediately.
const HEAVY_SECTION_EVERY: u32 = 3;

tokio::task_local! {
    static REFRESH_RECORDER: Arc<RefreshRecorder>;
    static REFRESH_SECTION: RefreshSection;
}

#[derive(Debug, Default)]
struct RefreshSectionStats {
    elapsed: Duration,
    process_count: u64,
}

#[derive(Debug, Default)]
struct RefreshRecorder {
    process_count: AtomicU64,
    sections: std::sync::Mutex<BTreeMap<RefreshSection, RefreshSectionStats>>,
}

impl RefreshRecorder {
    fn record_process(&self, section: Option<RefreshSection>) {
        self.process_count.fetch_add(1, Ordering::Relaxed);
        let Some(section) = section else {
            return;
        };
        let mut sections = self
            .sections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sections.entry(section).or_default().process_count += 1;
    }

    fn record_section(&self, section: RefreshSection, elapsed: Duration) {
        let mut sections = self
            .sections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sections.entry(section).or_default().elapsed += elapsed;
    }

    fn finish(&self, elapsed: Duration) -> RefreshObservation {
        let sections = self
            .sections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(section, stats)| RefreshSectionObservation {
                section: *section,
                elapsed: stats.elapsed,
                process_count: stats.process_count,
            })
            .collect();
        RefreshObservation::new(
            elapsed,
            self.process_count.load(Ordering::Relaxed),
            sections,
        )
    }
}

async fn observe_section<T>(
    section: RefreshSection,
    future: impl std::future::Future<Output = T>,
) -> T {
    let started = Instant::now();
    let output = REFRESH_SECTION.scope(section, future).await;
    let _ = REFRESH_RECORDER.try_with(|recorder| {
        recorder.record_section(section, started.elapsed());
    });
    output
}

type ZoneSections = (
    BTreeMap<ZoneName, ActiveZone>,
    BTreeMap<ZoneName, ZoneDetails>,
    BTreeMap<ZoneName, ZoneDetails>,
    Vec<DegradedSection>,
);

type ServiceDetail = (
    Option<(ServiceName, ServiceDefinition)>,
    Option<DegradedSection>,
);
type PolicyDetail = (Option<(PolicyName, PolicyDetails)>, Option<DegradedSection>);

enum DetailResult {
    Service(ServiceDetail),
    Policy {
        target: ConfigurationTarget,
        detail: Box<PolicyDetail>,
    },
}

struct HydratedDetails {
    service_definitions: BTreeMap<ServiceName, ServiceDefinition>,
    policies: Scoped<BTreeMap<PolicyName, PolicyDetails>>,
    service_degraded: Vec<DegradedSection>,
    policy_degraded: Vec<DegradedSection>,
}

/// The `firewall-cmd` backend: the full-featured reference implementation of
/// `FirewallBackend`. Sections that fail to fetch degrade with an honest
/// report instead of an empty lie; heavy sections are tier-cached.
pub struct CliBackend<R> {
    runner: R,
    timeout: Duration,
    mode: command::BackendMode,
    // Service-definition cache. Service mutations invalidate it before apply.
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
    /// Soft-fails per service, with a structured degradation record so a
    /// missing definition is never presented as an empty definition.
    async fn service_definitions(
        &self,
        names: Vec<ServiceName>,
    ) -> (
        BTreeMap<ServiceName, ServiceDefinition>,
        Vec<DegradedSection>,
    ) {
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
                Ok(raw) => (Some((name, parse::parse_service_info(&raw))), None),
                Err(err) => {
                    tracing::warn!(service = %name, error = %err, "service info failed");
                    let degraded = DegradedSection::new(
                        SnapshotSection::ServiceDefinitions,
                        None,
                        err.to_string(),
                    )
                    .with_object(name.to_string());
                    (None, Some(degraded))
                }
            }
        }))
        .await;
        let mut degraded = Vec::new();
        {
            let mut cache = self
                .definitions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (definition, failure) in fetched {
                cache.extend(definition);
                degraded.extend(failure);
            }
        }
        let cache = self
            .definitions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let definitions = names
            .into_iter()
            .filter_map(|name| cache.get(&name).cloned().map(|def| (name, def)))
            .collect();
        (definitions, degraded)
    }

    fn request(&self, args: &[&str]) -> CommandRequest {
        command::request_with(self.mode.program(), args, self.timeout)
    }

    async fn run(&self, request: CommandRequest) -> Result<CommandOutput, FirewallError> {
        let _ = REFRESH_RECORDER.try_with(|recorder| {
            let section = REFRESH_SECTION.try_with(|section| *section).ok();
            recorder.record_process(section);
        });
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
        Scoped<BTreeMap<IpSetName, IpSetInfo>>,
        Scoped<BTreeMap<PolicyName, PolicyDetails>>,
        Vec<String>,
        Vec<DegradedSection>,
        Vec<ServiceName>,
        Option<DegradedSection>,
    ) {
        let (ipsets, mut degraded) = observe_section(RefreshSection::IpSets, self.ipsets()).await;
        let (direct_rules, direct_err) =
            observe_section(RefreshSection::DirectRules, self.direct_rules()).await;
        let (available_services, services_err) =
            observe_section(RefreshSection::Services, self.available_services()).await;
        let (policies, policy_degraded) =
            observe_section(RefreshSection::Policies, self.policies()).await;
        degraded.extend(direct_err);
        degraded.extend(policy_degraded);
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

    /// Fetches heavy snapshot sections using the exact policy names captured
    /// by an earlier overview read, repopulating the existing tier cache.
    #[allow(clippy::type_complexity)]
    async fn fetch_hydrated_sections(
        &self,
        overview: &RefreshOverview,
        priority: &RefreshPrioritySource,
    ) -> (
        Scoped<BTreeMap<IpSetName, IpSetInfo>>,
        Scoped<BTreeMap<PolicyName, PolicyDetails>>,
        Vec<String>,
        Vec<DegradedSection>,
        BTreeMap<ServiceName, ServiceDefinition>,
        Vec<DegradedSection>,
    ) {
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
        if let Some((ipsets, policies, direct_rules, degraded)) = cached {
            let details = self
                .hydrate_detail_work(overview, priority, overview.referenced_services(), None)
                .await;
            return (
                ipsets,
                policies,
                direct_rules,
                degraded,
                details.service_definitions,
                details.service_degraded,
            );
        }

        let (ipsets, mut degraded) = observe_section(RefreshSection::IpSets, self.ipsets()).await;
        let (direct_rules, direct_err) =
            observe_section(RefreshSection::DirectRules, self.direct_rules()).await;
        let details = self
            .hydrate_detail_work(
                overview,
                priority,
                overview.referenced_services(),
                Some(&overview.policy_names),
            )
            .await;
        degraded.extend(direct_err);
        degraded.extend(details.policy_degraded);
        let mut heavy = self
            .heavy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        heavy.age = Some(1);
        heavy.ipsets = ipsets.clone();
        heavy.policies = details.policies.clone();
        heavy.direct_rules.clone_from(&direct_rules);
        heavy.degraded.clone_from(&degraded);
        drop(heavy);
        (
            ipsets,
            details.policies,
            direct_rules,
            degraded,
            details.service_definitions,
            details.service_degraded,
        )
    }

    async fn hydrate_detail_work(
        &self,
        overview: &RefreshOverview,
        priority: &RefreshPrioritySource,
        service_names: Vec<ServiceName>,
        policy_names: Option<&Scoped<Vec<PolicyName>>>,
    ) -> HydratedDetails {
        let mut pending: Vec<DetailWork> = {
            let cache = self
                .definitions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            service_names
                .iter()
                .filter(|name| !cache.contains_key(*name))
                .cloned()
                .map(DetailWork::Service)
                .collect()
        };
        if let Some(policy_names) = policy_names {
            pending.extend(
                policy_names
                    .runtime
                    .iter()
                    .cloned()
                    .map(|name| DetailWork::Policy {
                        target: ConfigurationTarget::Runtime,
                        name,
                    }),
            );
            pending.extend(
                policy_names
                    .permanent
                    .iter()
                    .cloned()
                    .map(|name| DetailWork::Policy {
                        target: ConfigurationTarget::Permanent,
                        name,
                    }),
            );
        }

        let mut queue = DetailQueue::new(pending);
        let mut policies: Scoped<BTreeMap<PolicyName, PolicyDetails>> = Scoped::default();
        let mut definitions = Vec::new();
        let mut service_degraded = Vec::new();
        let mut policy_degraded = Vec::new();
        while !queue.is_empty() {
            let latest = priority.latest();
            let batch = queue.take_batch(8, overview, &latest);
            let completed = bounded_fan_out(
                batch
                    .into_iter()
                    .map(|work| async move { self.fetch_detail(work).await }),
            )
            .await;
            for result in completed {
                match result {
                    DetailResult::Service((definition, failure)) => {
                        definitions.extend(definition);
                        service_degraded.extend(failure);
                    }
                    DetailResult::Policy { target, detail } => {
                        let (definition, failure) = *detail;
                        if let Some((name, details)) = definition {
                            match target {
                                ConfigurationTarget::Runtime => {
                                    policies.runtime.insert(name, details);
                                }
                                ConfigurationTarget::Permanent => {
                                    policies.permanent.insert(name, details);
                                }
                                ConfigurationTarget::RuntimeAndPermanent => {
                                    policies.runtime.insert(name.clone(), details.clone());
                                    policies.permanent.insert(name, details);
                                }
                            }
                        }
                        policy_degraded.extend(failure);
                    }
                }
            }
        }

        let mut cache = self
            .definitions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.extend(definitions);
        let service_definitions = service_names
            .into_iter()
            .filter_map(|name| cache.get(&name).cloned().map(|details| (name, details)))
            .collect();
        HydratedDetails {
            service_definitions,
            policies,
            service_degraded,
            policy_degraded,
        }
    }

    async fn fetch_detail(&self, work: DetailWork) -> DetailResult {
        match work {
            DetailWork::Service(name) => DetailResult::Service(
                observe_section(RefreshSection::Services, self.fetch_service_detail(name)).await,
            ),
            DetailWork::Policy { target, name } => DetailResult::Policy {
                target,
                detail: Box::new(
                    observe_section(
                        RefreshSection::Policies,
                        self.fetch_policy_detail(target, name),
                    )
                    .await,
                ),
            },
        }
    }

    async fn fetch_service_detail(&self, name: ServiceName) -> ServiceDetail {
        let arg = format!("--info-service={name}");
        match self.run_ok(self.request(&[&arg])).await {
            Ok(raw) => (Some((name, parse::parse_service_info(&raw))), None),
            Err(err) => {
                tracing::warn!(service = %name, error = %err, "service info failed");
                let degraded = DegradedSection::new(
                    SnapshotSection::ServiceDefinitions,
                    None,
                    err.to_string(),
                )
                .with_object(name.to_string());
                (None, Some(degraded))
            }
        }
    }

    async fn fetch_policy_detail(
        &self,
        target: ConfigurationTarget,
        name: PolicyName,
    ) -> PolicyDetail {
        let arg = format!("--info-policy={name}");
        let request = if target == ConfigurationTarget::Permanent && !self.is_offline() {
            self.request(&["--permanent", &arg])
        } else {
            self.request(&[&arg])
        };
        match self.run_ok(request).await {
            Ok(raw) => match parse::parse_policy_info(&raw) {
                Ok(details) => (Some((name, details)), None),
                Err(err) => {
                    tracing::warn!(policy = %name, error = %err, "policy parse failed");
                    let failure = DegradedSection::new(
                        SnapshotSection::Policies,
                        Some(target),
                        format!("unparseable details: {err}"),
                    )
                    .with_object(name.to_string());
                    (None, Some(failure))
                }
            },
            Err(err) => {
                tracing::warn!(policy = %name, error = %err, "policy info failed");
                let failure =
                    DegradedSection::new(SnapshotSection::Policies, Some(target), err.to_string())
                        .with_object(name.to_string());
                (None, Some(failure))
            }
        }
    }

    async fn refresh_overview(&self) -> Result<RefreshOverview, FirewallError> {
        let status = observe_section(RefreshSection::Status, self.probe()).await?;
        if !status.daemon_running && !self.is_offline() {
            return Err(FirewallError::DaemonNotRunning);
        }
        let (default_zone, active, runtime, permanent, mut degraded) =
            self.fetch_zone_overview().await?;
        let (available_services, service_error) =
            observe_section(RefreshSection::Services, self.available_services()).await;
        if let Some(service_error) = service_error {
            degraded.push(service_error);
        }
        let (policy_names, policy_errors) =
            observe_section(RefreshSection::Policies, self.policy_names()).await;
        degraded.extend(policy_errors);
        Ok(RefreshOverview {
            status,
            default_zone,
            active,
            runtime,
            permanent,
            available_services,
            policy_names,
            degraded,
        })
    }

    async fn hydrate_overview(
        &self,
        overview: Arc<RefreshOverview>,
        priority: &RefreshPrioritySource,
    ) -> Result<FirewallSnapshot, FirewallError> {
        let (ipsets, policies, direct_rules, mut degraded, service_definitions, service_degraded) =
            self.fetch_hydrated_sections(&overview, priority).await;
        degraded.extend(service_degraded);
        degraded.extend(overview.degraded.clone());
        Ok(FirewallSnapshot {
            status: overview.status.clone(),
            default_zone: overview.default_zone.clone(),
            active: overview.active.clone(),
            runtime: overview.runtime.clone(),
            permanent: overview.permanent.clone(),
            ipsets,
            service_definitions,
            available_services: overview.available_services.clone(),
            policies,
            direct_rules,
            degraded,
        })
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

    /// Fetches one scope of IP sets, recording list and per-object failures.
    async fn ipsets_for(
        &self,
        target: ConfigurationTarget,
    ) -> (BTreeMap<IpSetName, IpSetInfo>, Vec<DegradedSection>) {
        let request = if target == ConfigurationTarget::Permanent && !self.is_offline() {
            self.request(&["--permanent", "--get-ipsets"])
        } else {
            self.request(&["--get-ipsets"])
        };
        let names = match self.run_ok(request).await {
            Ok(raw) => match parse::parse_ipset_names(&raw) {
                Ok(names) => names,
                Err(err) => {
                    tracing::warn!(error = %err, "ipset listing unparseable");
                    return (
                        BTreeMap::new(),
                        vec![DegradedSection::new(
                            SnapshotSection::IpSets,
                            Some(target),
                            format!("unparseable listing: {err}"),
                        )],
                    );
                }
            },
            Err(err) => {
                tracing::warn!(error = %err, "ipset listing failed");
                return (
                    BTreeMap::new(),
                    vec![DegradedSection::new(
                        SnapshotSection::IpSets,
                        Some(target),
                        err.to_string(),
                    )],
                );
            }
        };
        // Concurrent: each `--info-ipset` spawn costs ~100 ms; serially that
        // scales with the set count and stalls every refresh (ADR-2 intent).
        let infos = bounded_fan_out(names.into_iter().map(|name| async move {
            let arg = format!("--info-ipset={name}");
            let request = if target == ConfigurationTarget::Permanent && !self.is_offline() {
                self.request(&["--permanent", &arg])
            } else {
                self.request(&[&arg])
            };
            match self.run_ok(request).await {
                Ok(raw) => (Some((name, parse::parse_ipset_info(&raw))), None),
                Err(err) => {
                    tracing::warn!(ipset = %name, error = %err, "ipset info failed");
                    let failure = DegradedSection::new(
                        SnapshotSection::IpSets,
                        Some(target),
                        err.to_string(),
                    )
                    .with_object(name.to_string());
                    (None, Some(failure))
                }
            }
        }))
        .await;
        let mut ipsets = BTreeMap::new();
        let mut degraded = Vec::new();
        for (info, failure) in infos {
            ipsets.extend(info);
            degraded.extend(failure);
        }
        (ipsets, degraded)
    }

    /// Fetches runtime and permanent IP sets independently. Offline mode has
    /// no runtime configuration, so only permanent data is queried.
    async fn ipsets(&self) -> (Scoped<BTreeMap<IpSetName, IpSetInfo>>, Vec<DegradedSection>) {
        if self.is_offline() {
            let (permanent, mut degraded) = self.ipsets_for(ConfigurationTarget::Permanent).await;
            degraded.push(DegradedSection::new(
                SnapshotSection::IpSets,
                Some(ConfigurationTarget::Runtime),
                "runtime configuration is unavailable in offline mode",
            ));
            return (
                Scoped {
                    runtime: BTreeMap::new(),
                    permanent,
                },
                degraded,
            );
        }
        let (runtime, mut degraded) = self.ipsets_for(ConfigurationTarget::Runtime).await;
        let (permanent, permanent_degraded) = self.ipsets_for(ConfigurationTarget::Permanent).await;
        degraded.extend(permanent_degraded);
        (Scoped { runtime, permanent }, degraded)
    }

    async fn available_services(&self) -> (Vec<ServiceName>, Option<DegradedSection>) {
        match self.run_ok(self.request(&["--get-services"])).await {
            Ok(raw) => match parse::parse_service_names(&raw) {
                Ok(names) => (names, None),
                Err(err) => {
                    tracing::warn!(error = %err, "service listing unparseable");
                    (
                        Vec::new(),
                        Some(DegradedSection::new(
                            SnapshotSection::Services,
                            None,
                            format!("unparseable listing: {err}"),
                        )),
                    )
                }
            },
            Err(err) => {
                tracing::warn!(error = %err, "service listing failed");
                (
                    Vec::new(),
                    Some(DegradedSection::new(
                        SnapshotSection::Services,
                        None,
                        err.to_string(),
                    )),
                )
            }
        }
    }

    /// Fetches policy names for one configuration scope.
    async fn policy_names_for(
        &self,
        target: ConfigurationTarget,
    ) -> (Vec<PolicyName>, Vec<DegradedSection>) {
        let request = if target == ConfigurationTarget::Permanent && !self.is_offline() {
            self.request(&["--permanent", "--get-policies"])
        } else {
            self.request(&["--get-policies"])
        };
        match self.run_ok(request).await {
            Ok(raw) => match parse::parse_policy_names(&raw) {
                Ok(names) => (names, Vec::new()),
                Err(err) => {
                    tracing::warn!(error = %err, "policy listing unparseable");
                    (
                        Vec::new(),
                        vec![DegradedSection::new(
                            SnapshotSection::Policies,
                            Some(target),
                            format!("unparseable listing: {err}"),
                        )],
                    )
                }
            },
            Err(err) => {
                tracing::warn!(error = %err, "policy listing failed");
                (
                    Vec::new(),
                    vec![DegradedSection::new(
                        SnapshotSection::Policies,
                        Some(target),
                        err.to_string(),
                    )],
                )
            }
        }
    }

    /// Fetches policy names for each available configuration scope.
    async fn policy_names(&self) -> (Scoped<Vec<PolicyName>>, Vec<DegradedSection>) {
        if self.is_offline() {
            let (permanent, mut degraded) =
                self.policy_names_for(ConfigurationTarget::Permanent).await;
            degraded.push(DegradedSection::new(
                SnapshotSection::Policies,
                Some(ConfigurationTarget::Runtime),
                "runtime configuration is unavailable in offline mode",
            ));
            return (
                Scoped {
                    runtime: Vec::new(),
                    permanent,
                },
                degraded,
            );
        }
        let (runtime, mut degraded) = self.policy_names_for(ConfigurationTarget::Runtime).await;
        let (permanent, permanent_degraded) =
            self.policy_names_for(ConfigurationTarget::Permanent).await;
        degraded.extend(permanent_degraded);
        (Scoped { runtime, permanent }, degraded)
    }

    /// Fetches policy details for the exact names captured by policy listing.
    async fn policies_for(
        &self,
        target: ConfigurationTarget,
        names: Vec<PolicyName>,
    ) -> (BTreeMap<PolicyName, PolicyDetails>, Vec<DegradedSection>) {
        let infos = bounded_fan_out(names.into_iter().map(|name| async move {
            let arg = format!("--info-policy={name}");
            let request = if target == ConfigurationTarget::Permanent && !self.is_offline() {
                self.request(&["--permanent", &arg])
            } else {
                self.request(&[&arg])
            };
            match self.run_ok(request).await {
                Ok(raw) => match parse::parse_policy_info(&raw) {
                    Ok(details) => (Some((name, details)), None),
                    Err(err) => {
                        tracing::warn!(policy = %name, error = %err, "policy parse failed");
                        let failure = DegradedSection::new(
                            SnapshotSection::Policies,
                            Some(target),
                            format!("unparseable details: {err}"),
                        )
                        .with_object(name.to_string());
                        (None, Some(failure))
                    }
                },
                Err(err) => {
                    tracing::warn!(policy = %name, error = %err, "policy info failed");
                    let failure = DegradedSection::new(
                        SnapshotSection::Policies,
                        Some(target),
                        err.to_string(),
                    )
                    .with_object(name.to_string());
                    (None, Some(failure))
                }
            }
        }))
        .await;
        let mut policies = BTreeMap::new();
        let mut degraded = Vec::new();
        for (info, failure) in infos {
            policies.extend(info);
            degraded.extend(failure);
        }
        (policies, degraded)
    }

    async fn policies(
        &self,
    ) -> (
        Scoped<BTreeMap<PolicyName, PolicyDetails>>,
        Vec<DegradedSection>,
    ) {
        let (names, mut degraded) = self.policy_names().await;
        let (runtime, runtime_degraded) = self
            .policies_for(ConfigurationTarget::Runtime, names.runtime)
            .await;
        let (permanent, permanent_degraded) = self
            .policies_for(ConfigurationTarget::Permanent, names.permanent)
            .await;
        degraded.extend(runtime_degraded);
        degraded.extend(permanent_degraded);
        (Scoped { runtime, permanent }, degraded)
    }

    async fn direct_rules(&self) -> (Vec<String>, Option<DegradedSection>) {
        match self
            .run_ok(self.request(&["--direct", "--get-all-rules"]))
            .await
        {
            Ok(raw) => (parse::parse_direct_rules(&raw), None),
            Err(err) => {
                tracing::warn!(error = %err, "direct rule listing failed");
                (
                    Vec::new(),
                    Some(DegradedSection::new(
                        SnapshotSection::DirectRules,
                        Some(ConfigurationTarget::Runtime),
                        err.to_string(),
                    )),
                )
            }
        }
    }

    async fn fetch_zone_overview(
        &self,
    ) -> Result<
        (
            ZoneName,
            BTreeMap<ZoneName, ActiveZone>,
            BTreeMap<ZoneName, ZoneDetails>,
            BTreeMap<ZoneName, ZoneDetails>,
            Vec<DegradedSection>,
        ),
        FirewallError,
    > {
        observe_section(RefreshSection::Zones, async {
            let default_zone = self.run_ok(self.request(&["--get-default-zone"])).await?;
            let default_zone = parse::parse_default_zone(&default_zone)?;
            let (active, runtime, permanent, degraded) = self.zone_sections().await?;
            Ok((default_zone, active, runtime, permanent, degraded))
        })
        .await
    }

    /// Fetches runtime/permanent zones and records malformed individual zone
    /// blocks without making the entire snapshot unavailable.
    async fn zone_sections(&self) -> Result<ZoneSections, FirewallError> {
        if self.is_offline() {
            let config = self.run_ok(self.request(&["--list-all-zones"])).await?;
            let (config, degraded) = parse::parse_list_all_zones(&config);
            let mut degraded: Vec<_> = degraded
                .into_iter()
                .map(|message| {
                    DegradedSection::new(
                        SnapshotSection::Zones,
                        Some(ConfigurationTarget::Permanent),
                        message,
                    )
                })
                .collect();
            degraded.push(DegradedSection::new(
                SnapshotSection::Zones,
                Some(ConfigurationTarget::Runtime),
                "runtime configuration is unavailable in offline mode",
            ));
            return Ok((BTreeMap::new(), BTreeMap::new(), config, degraded));
        }

        let active = self.run_ok(self.request(&["--get-active-zones"])).await?;
        let active = parse::parse_active_zones(&active)?;
        let runtime = self.run_ok(self.request(&["--list-all-zones"])).await?;
        let (runtime, runtime_degraded) = parse::parse_list_all_zones(&runtime);
        let mut degraded: Vec<DegradedSection> = runtime_degraded
            .into_iter()
            .map(|message| {
                DegradedSection::new(
                    SnapshotSection::Zones,
                    Some(ConfigurationTarget::Runtime),
                    message,
                )
            })
            .collect();
        let permanent = self
            .run_ok(self.request(&["--permanent", "--list-all-zones"]))
            .await?;
        let (permanent, permanent_degraded) = parse::parse_list_all_zones(&permanent);
        degraded.extend(permanent_degraded.into_iter().map(|message| {
            DegradedSection::new(
                SnapshotSection::Zones,
                Some(ConfigurationTarget::Permanent),
                message,
            )
        }));
        Ok((active, runtime, permanent, degraded))
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
        let status = observe_section(RefreshSection::Status, self.probe()).await?;
        if !status.daemon_running && !self.is_offline() {
            return Err(FirewallError::DaemonNotRunning);
        }

        let (default_zone, active, runtime, permanent, zone_degraded) =
            self.fetch_zone_overview().await?;
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
                let (available_services, services_err) =
                    observe_section(RefreshSection::Services, self.available_services()).await;
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
        degraded.extend(zone_degraded);

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
        let (definitions, definition_degraded) = observe_section(
            RefreshSection::Services,
            self.service_definitions(snapshot.referenced_services()),
        )
        .await;
        snapshot.service_definitions = definitions;
        snapshot.degraded.extend(definition_degraded);
        Ok(snapshot)
    }

    async fn snapshot_observed(&self) -> SnapshotRead {
        let recorder = Arc::new(RefreshRecorder::default());
        let started = Instant::now();
        let result = REFRESH_RECORDER
            .scope(Arc::clone(&recorder), self.snapshot())
            .await;
        SnapshotRead {
            result,
            observation: recorder.finish(started.elapsed()),
        }
    }

    async fn snapshot_overview(&self, _priority: &RefreshPrioritySource) -> OverviewRead {
        let recorder = Arc::new(RefreshRecorder::default());
        let started = Instant::now();
        let result = REFRESH_RECORDER
            .scope(Arc::clone(&recorder), self.refresh_overview())
            .await
            .map(|overview| Some(Arc::new(overview)));
        OverviewRead {
            result,
            observation: recorder.finish(started.elapsed()),
        }
    }

    async fn snapshot_hydrated(
        &self,
        overview: Option<Arc<RefreshOverview>>,
        priority: &RefreshPrioritySource,
    ) -> SnapshotRead {
        let Some(overview) = overview else {
            return self.snapshot_observed().await;
        };
        let recorder = Arc::new(RefreshRecorder::default());
        let started = Instant::now();
        let result = REFRESH_RECORDER
            .scope(
                Arc::clone(&recorder),
                self.hydrate_overview(overview, priority),
            )
            .await;
        SnapshotRead {
            result,
            observation: recorder.finish(started.elapsed()),
        }
    }

    async fn snapshot_fresh(&self) -> Result<FirewallSnapshot, FirewallError> {
        // Mutation preconditions must observe every section now; reusing a
        // tiered heavy-section cache could miss an external policy/ipset edit.
        self.heavy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .age = None;
        self.snapshot().await
    }

    async fn apply(&self, operation: &FirewallOperation) -> OperationOutcome {
        // Any mutation invalidates the tiered heavy-section cache: the very
        // next refresh refetches ipsets/policies/direct rules.
        self.heavy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .age = None;
        if matches!(
            operation,
            FirewallOperation::CreateService { .. }
                | FirewallOperation::DeleteService { .. }
                | FirewallOperation::AddServicePort { .. }
                | FirewallOperation::RemoveServicePort { .. }
        ) {
            self.definitions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
        }
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
