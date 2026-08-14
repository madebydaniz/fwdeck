//! `CliBackend` tests with a fake runner: exact executables, exact argument
//! order, timeout propagation, and fixture-driven error mapping — no real
//! processes involved.

#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fwdeck::application::ports::{FirewallBackend, FirewallError, OperationOutcome};
use fwdeck::application::{RefreshPriority, refresh_priority_channel};
use fwdeck::domain::{
    ConfigurationTarget, FirewallOperation, PolicyName, RefreshSection, ServiceName,
    SnapshotSection, ZoneName,
};
use fwdeck::infrastructure::firewalld::CliBackend;
use fwdeck::infrastructure::process::{
    CommandOutput, CommandRequest, CommandRunner, DEFAULT_TIMEOUT, ProcessError,
};
use tokio::sync::{Notify, Semaphore};

const LIST_ALL_RUNTIME: &str = include_str!("fixtures/firewall_cmd/list_all_zones_runtime.txt");
const LIST_ALL_PERMANENT: &str = include_str!("fixtures/firewall_cmd/list_all_zones_permanent.txt");
const ACTIVE_ZONES: &str = include_str!("fixtures/firewall_cmd/active_zones.txt");
const PERM_DENIED_STDERR: &str = include_str!("fixtures/firewall_cmd/perm_denied_stderr.txt");
const INFO_IPSET: &str = include_str!("fixtures/firewall_cmd/info_ipset.txt");
const INFO_SERVICE: &str = include_str!("fixtures/firewall_cmd/info_service.txt");
const INFO_POLICY: &str = include_str!("fixtures/firewall_cmd/info_policy.txt");
const DIRECT_RULES: &str = include_str!("fixtures/firewall_cmd/direct_rules.txt");

#[derive(Clone, Default)]
struct FakeRunner {
    queue: Arc<Mutex<VecDeque<Result<CommandOutput, ProcessError>>>>,
    seen: Arc<Mutex<Vec<CommandRequest>>>,
}

impl FakeRunner {
    fn push(&self, response: Result<CommandOutput, ProcessError>) {
        self.queue.lock().unwrap().push_back(response);
    }

    fn push_ok(&self, stdout: &str) {
        self.push(Ok(output(Some(0), stdout, "")));
    }

    fn seen_args(&self) -> Vec<Vec<String>> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.args.clone())
            .collect()
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

impl CommandRunner for FakeRunner {
    async fn run(&self, request: CommandRequest) -> Result<CommandOutput, ProcessError> {
        assert_eq!(request.program, "firewall-cmd");
        assert_eq!(request.timeout, DEFAULT_TIMEOUT);
        self.seen.lock().unwrap().push(request);
        self.queue
            .lock()
            .unwrap()
            .pop_front()
            .expect("backend issued an unexpected extra command")
    }
}

#[derive(Clone)]
struct StagedFixtureRunner {
    control: Arc<StagedFixtureControl>,
}

struct StagedFixtureControl {
    background_detail_started: AtomicBool,
    background_detail_waiting: Notify,
    release_background_detail: Semaphore,
    seen: Mutex<Vec<Vec<String>>>,
}

impl StagedFixtureControl {
    async fn wait_for_background_detail(&self) {
        loop {
            let notified = self.background_detail_waiting.notified();
            if self.background_detail_started.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }

    fn background_detail_started(&self) -> bool {
        self.background_detail_started.load(Ordering::SeqCst)
    }

    fn release_background_detail(&self) {
        self.release_background_detail.add_permits(1);
    }

    fn detail_commands(&self) -> Vec<Vec<String>> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|args| {
                args.iter().any(|arg| {
                    arg.starts_with("--info-service=") || arg.starts_with("--info-policy=")
                })
            })
            .cloned()
            .collect()
    }
}

fn staged_backend_fixture() -> (CliBackend<StagedFixtureRunner>, Arc<StagedFixtureControl>) {
    let control = Arc::new(StagedFixtureControl {
        background_detail_started: AtomicBool::new(false),
        background_detail_waiting: Notify::new(),
        release_background_detail: Semaphore::new(0),
        seen: Mutex::new(Vec::new()),
    });
    (
        CliBackend::new(StagedFixtureRunner {
            control: Arc::clone(&control),
        }),
        control,
    )
}

fn staged_fixture_zones(zones: &str) -> String {
    zones.replace(
        "services: cockpit dhcpv6-client ssh",
        "services: background cockpit dhcpv6-client ssh",
    )
}

impl CommandRunner for StagedFixtureRunner {
    async fn run(&self, request: CommandRequest) -> Result<CommandOutput, ProcessError> {
        assert_eq!(request.program, "firewall-cmd");
        assert_eq!(request.timeout, DEFAULT_TIMEOUT);
        self.control.seen.lock().unwrap().push(request.args.clone());
        let stdout = match request.args.as_slice() {
            [state] if state == "--state" => "running\n".to_owned(),
            [version] if version == "--version" => "2.3.2\n".to_owned(),
            [log_denied] if log_denied == "--get-log-denied" => "off\n".to_owned(),
            [panic] if panic == "--query-panic" => {
                return Ok(output(Some(1), "no\n", ""));
            }
            [default_zone] if default_zone == "--get-default-zone" => "public\n".to_owned(),
            [active] if active == "--get-active-zones" => ACTIVE_ZONES.to_owned(),
            [zones] if zones == "--list-all-zones" => staged_fixture_zones(LIST_ALL_RUNTIME),
            [permanent, zones] if permanent == "--permanent" && zones == "--list-all-zones" => {
                staged_fixture_zones(LIST_ALL_PERMANENT)
            }
            [ipsets] if ipsets == "--get-ipsets" => "blocklist\n".to_owned(),
            [ipset] if ipset == "--info-ipset=blocklist" => INFO_IPSET.to_owned(),
            [permanent, ipsets] if permanent == "--permanent" && ipsets == "--get-ipsets" => {
                "blocklist\n".to_owned()
            }
            [permanent, ipset]
                if permanent == "--permanent" && ipset == "--info-ipset=blocklist" =>
            {
                INFO_IPSET.to_owned()
            }
            [direct, rules] if direct == "--direct" && rules == "--get-all-rules" => {
                DIRECT_RULES.to_owned()
            }
            [services] if services == "--get-services" => "ssh http https\n".to_owned(),
            [policies] if policies == "--get-policies" => {
                "alpha-policy fwdeck-fixture\n".to_owned()
            }
            [policy] if policy.starts_with("--info-policy=") => INFO_POLICY.to_owned(),
            [permanent, policies] if permanent == "--permanent" && policies == "--get-policies" => {
                "alpha-policy fwdeck-fixture\n".to_owned()
            }
            [permanent, policy]
                if permanent == "--permanent" && policy.starts_with("--info-policy=") =>
            {
                INFO_POLICY.to_owned()
            }
            [service] if service == "--info-service=background" => {
                self.control
                    .background_detail_started
                    .store(true, Ordering::SeqCst);
                self.control.background_detail_waiting.notify_waiters();
                match self.control.release_background_detail.acquire().await {
                    Ok(permit) => {
                        permit.forget();
                        INFO_SERVICE.to_owned()
                    }
                    Err(_) => {
                        return Err(ProcessError::Io("background detail gate closed".to_owned()));
                    }
                }
            }
            [service] if service.starts_with("--info-service=") => INFO_SERVICE.to_owned(),
            unexpected => panic!("unexpected fixture command: {unexpected:?}"),
        };
        Ok(output(Some(0), &stdout, ""))
    }
}

#[tokio::test]
async fn staged_cli_read_returns_zone_overview_before_background_details() {
    let (backend, control) = staged_backend_fixture();
    let (_publisher, priority) = refresh_priority_channel();

    let overview = backend.snapshot_overview(&priority).await;
    let overview = overview.result.unwrap().unwrap();
    assert_eq!(overview.default_zone.as_str(), "public");
    assert!(
        overview
            .runtime
            .contains_key(&ZoneName::parse("public").unwrap())
    );
    assert!(!control.background_detail_started());
    assert!(
        control.detail_commands().is_empty(),
        "overview must not request policy or service details"
    );

    let hydration = backend.snapshot_hydrated(Some(overview), &priority);
    tokio::pin!(hydration);
    assert!(futures_util::poll!(&mut hydration).is_pending());
    control.wait_for_background_detail().await;
    control.release_background_detail();
    assert!(hydration.await.result.is_ok());
}

#[tokio::test]
async fn staged_cli_final_snapshot_matches_complete_snapshot() {
    let (staged_backend, staged_control) = staged_backend_fixture();
    let (_publisher, priority) = refresh_priority_channel();
    let overview = staged_backend
        .snapshot_overview(&priority)
        .await
        .result
        .unwrap()
        .unwrap();
    let hydration = staged_backend.snapshot_hydrated(Some(overview), &priority);
    tokio::pin!(hydration);
    assert!(futures_util::poll!(&mut hydration).is_pending());
    staged_control.wait_for_background_detail().await;
    staged_control.release_background_detail();
    let staged = hydration.await.result.unwrap();

    let (complete_backend, complete_control) = staged_backend_fixture();
    complete_control.release_background_detail();
    let complete = complete_backend.snapshot().await.unwrap();

    assert_eq!(staged, complete);
}

#[tokio::test]
async fn staged_priority_changes_only_reorder_unstarted_details() {
    let (backend, control) = staged_backend_fixture();
    let (publisher, priority) = refresh_priority_channel();
    let overview = backend
        .snapshot_overview(&priority)
        .await
        .result
        .unwrap()
        .unwrap();
    let hydration = backend.snapshot_hydrated(Some(overview), &priority);
    tokio::pin!(hydration);

    assert!(futures_util::poll!(&mut hydration).is_pending());
    control.wait_for_background_detail().await;
    assert_eq!(
        control.detail_commands().len(),
        8,
        "only the active bounded batch may start before its gate opens"
    );
    let first_batch = control.detail_commands();
    publisher.publish(RefreshPriority {
        zone: None,
        service: None,
        policy: Some(PolicyName::parse("fwdeck-fixture").unwrap()),
    });
    control.release_background_detail();

    assert!(hydration.await.result.is_ok());
    let details = control.detail_commands();
    assert_eq!(details.len(), 12);
    assert_eq!(&details[..8], first_batch.as_slice());
    assert_eq!(details[8], vec!["--info-policy=fwdeck-fixture"]);
}

#[tokio::test]
async fn snapshot_issues_exact_commands_in_order() {
    let runner = FakeRunner::default();
    runner.push_ok("running\n");
    runner.push_ok("2.3.2\n");
    runner.push_ok("off\n");
    runner.push(Ok(output(Some(1), "no\n", ""))); // --query-panic: off
    runner.push_ok("public\n");
    runner.push_ok(ACTIVE_ZONES);
    runner.push_ok(LIST_ALL_RUNTIME);
    runner.push_ok(LIST_ALL_PERMANENT);
    runner.push_ok("blocklist\n"); // --get-ipsets
    runner.push_ok(INFO_IPSET);
    runner.push_ok("blocklist\n"); // --permanent --get-ipsets
    runner.push_ok(INFO_IPSET);
    runner.push_ok(DIRECT_RULES);
    runner.push_ok("ssh http https\n"); // --get-services
    runner.push_ok("fwdeck-fixture\n");
    runner.push_ok("fwdeck-fixture\n");
    runner.push_ok(INFO_POLICY);
    runner.push_ok(INFO_POLICY);
    // One --info-service per referenced service (sorted union across configs).
    for _ in 0..7 {
        runner.push_ok(INFO_SERVICE);
    }

    let backend = CliBackend::new(runner.clone());
    let read = backend.snapshot_observed().await;
    let snapshot = read.result.unwrap();

    assert_eq!(
        runner.seen_args(),
        vec![
            vec!["--state".to_owned()],
            vec!["--version".to_owned()],
            vec!["--get-log-denied".to_owned()],
            vec!["--query-panic".to_owned()],
            vec!["--get-default-zone".to_owned()],
            vec!["--get-active-zones".to_owned()],
            vec!["--list-all-zones".to_owned()],
            vec!["--permanent".to_owned(), "--list-all-zones".to_owned()],
            vec!["--get-ipsets".to_owned()],
            vec!["--info-ipset=blocklist".to_owned()],
            vec!["--permanent".to_owned(), "--get-ipsets".to_owned()],
            vec![
                "--permanent".to_owned(),
                "--info-ipset=blocklist".to_owned(),
            ],
            vec!["--direct".to_owned(), "--get-all-rules".to_owned()],
            vec!["--get-services".to_owned()],
            vec!["--get-policies".to_owned()],
            vec!["--permanent".to_owned(), "--get-policies".to_owned()],
            vec!["--info-policy=fwdeck-fixture".to_owned()],
            vec![
                "--permanent".to_owned(),
                "--info-policy=fwdeck-fixture".to_owned(),
            ],
            vec!["--info-service=cockpit".to_owned()],
            vec!["--info-service=dhcpv6-client".to_owned()],
            vec!["--info-service=http".to_owned()],
            vec!["--info-service=https".to_owned()],
            vec!["--info-service=mdns".to_owned()],
            vec!["--info-service=samba-client".to_owned()],
            vec!["--info-service=ssh".to_owned()],
        ]
    );

    assert_eq!(snapshot.default_zone.as_str(), "public");
    assert_eq!(snapshot.status.version.as_deref(), Some("2.3.2"));
    assert!(snapshot.status.daemon_running);
    assert!(!snapshot.status.panic_mode);
    assert_eq!(snapshot.runtime.len(), 11);
    assert_eq!(snapshot.active.len(), 2);
    assert!(!snapshot.all_synced(), "seeded drift must be detected");
    let ipset = snapshot.ipsets.runtime.keys().next().unwrap();
    assert_eq!(ipset.as_str(), "blocklist");
    assert_eq!(snapshot.ipsets.runtime, snapshot.ipsets.permanent);
    assert_eq!(snapshot.policies.runtime, snapshot.policies.permanent);
    assert!(
        snapshot
            .policies
            .runtime
            .keys()
            .any(|name| name.as_str() == "fwdeck-fixture")
    );
    assert_eq!(snapshot.direct_rules.len(), 1);
    assert_eq!(snapshot.service_definitions.len(), 7);
    assert_eq!(snapshot.available_services.len(), 3);

    assert_eq!(read.observation.process_count, Some(25));
    let section_count = |section| {
        read.observation
            .sections
            .iter()
            .find(|entry| entry.section == section)
            .map(|entry| entry.process_count)
    };
    assert_eq!(section_count(RefreshSection::Status), Some(4));
    assert_eq!(section_count(RefreshSection::Zones), Some(4));
    assert_eq!(section_count(RefreshSection::IpSets), Some(4));
    assert_eq!(section_count(RefreshSection::Services), Some(8));
    assert_eq!(section_count(RefreshSection::Policies), Some(4));
    assert_eq!(section_count(RefreshSection::DirectRules), Some(1));
}

#[tokio::test]
async fn service_definitions_are_cached_across_snapshots() {
    let runner = FakeRunner::default();
    let push_round = |runner: &FakeRunner| {
        runner.push_ok("running\n");
        runner.push_ok("2.3.2\n");
        runner.push_ok("off\n");
        runner.push(Ok(output(Some(1), "no\n", "")));
        runner.push_ok("public\n");
        runner.push_ok(ACTIVE_ZONES);
        runner.push_ok(LIST_ALL_RUNTIME);
        runner.push_ok(LIST_ALL_PERMANENT);
        runner.push_ok("\n"); // no ipsets
        runner.push_ok("\n"); // no permanent ipsets
        runner.push_ok(DIRECT_RULES);
        runner.push_ok("ssh http https\n"); // --get-services
        runner.push_ok("\n"); // --get-policies
        runner.push_ok("\n"); // --permanent --get-policies
    };

    push_round(&runner);
    // Definitions queued ONCE only: the second snapshot must hit the cache.
    for _ in 0..7 {
        runner.push_ok(INFO_SERVICE);
    }
    runner.push_ok("running\n");
    runner.push_ok("2.3.2\n");
    runner.push_ok("off\n");
    runner.push(Ok(output(Some(1), "no\n", "")));
    runner.push_ok("public\n");
    runner.push_ok(ACTIVE_ZONES);
    runner.push_ok(LIST_ALL_RUNTIME);
    runner.push_ok(LIST_ALL_PERMANENT);
    runner.push_ok("ssh http https\n"); // cached heavy sections; service catalog still refreshes

    let backend = CliBackend::new(runner.clone());
    let first = backend.snapshot().await.unwrap();
    assert_eq!(first.service_definitions.len(), 7);
    let second = backend.snapshot().await.unwrap();
    assert_eq!(
        second.service_definitions.len(),
        7,
        "cache must serve the second snapshot"
    );
    let info_calls = runner
        .seen_args()
        .iter()
        .filter(|args| args[0].starts_with("--info-service="))
        .count();
    assert_eq!(info_calls, 7, "no repeat fetches");
}

#[tokio::test]
async fn ipset_object_failure_is_reported_with_scope_and_identity() {
    let runner = FakeRunner::default();
    runner.push_ok("running\n");
    runner.push_ok("2.3.2\n");
    runner.push_ok("off\n");
    runner.push(Ok(output(Some(1), "no\n", "")));
    runner.push_ok("public\n");
    runner.push_ok(ACTIVE_ZONES);
    runner.push_ok(LIST_ALL_RUNTIME);
    runner.push_ok(LIST_ALL_PERMANENT);
    runner.push_ok("blocklist\n");
    runner.push(Ok(output(Some(13), "", "object read failed")));
    runner.push_ok("\n");
    runner.push_ok(DIRECT_RULES);
    runner.push_ok("ssh http https\n");
    runner.push_ok("\n");
    runner.push_ok("\n");
    for _ in 0..7 {
        runner.push_ok(INFO_SERVICE);
    }

    let snapshot = CliBackend::new(runner).snapshot().await.unwrap();
    assert!(snapshot.ipsets.runtime.is_empty());
    let failure = snapshot
        .degraded
        .iter()
        .find(|failure| failure.section == SnapshotSection::IpSets)
        .expect("ipset failure must remain visible");
    assert_eq!(failure.target, Some(ConfigurationTarget::Runtime));
    assert_eq!(failure.object.as_deref(), Some("blocklist"));
    assert!(failure.reason.contains("object read failed"));
}

#[tokio::test]
async fn service_mutation_invalidates_definition_cache() {
    let runner = FakeRunner::default();
    let push_full_snapshot = |runner: &FakeRunner| {
        runner.push_ok("running\n");
        runner.push_ok("2.3.2\n");
        runner.push_ok("off\n");
        runner.push(Ok(output(Some(1), "no\n", "")));
        runner.push_ok("public\n");
        runner.push_ok(ACTIVE_ZONES);
        runner.push_ok(LIST_ALL_RUNTIME);
        runner.push_ok(LIST_ALL_PERMANENT);
        runner.push_ok("\n");
        runner.push_ok("\n");
        runner.push_ok(DIRECT_RULES);
        runner.push_ok("ssh http https\n");
        runner.push_ok("\n");
        runner.push_ok("\n");
        for _ in 0..7 {
            runner.push_ok(INFO_SERVICE);
        }
    };
    push_full_snapshot(&runner);
    runner.push_ok("success\n");
    push_full_snapshot(&runner);

    let backend = CliBackend::new(runner.clone());
    backend.snapshot().await.unwrap();
    let outcome = backend
        .apply(&FirewallOperation::AddServicePort {
            service: ServiceName::parse("ssh").unwrap(),
            port: "2222/tcp".parse().unwrap(),
        })
        .await;
    assert!(matches!(outcome, OperationOutcome::Applied { .. }));
    backend.snapshot().await.unwrap();

    let info_calls = runner
        .seen_args()
        .iter()
        .filter(|args| args[0].starts_with("--info-service="))
        .count();
    assert_eq!(info_calls, 14, "definitions must refetch after mutation");
}

#[tokio::test]
async fn mutation_preflight_snapshot_bypasses_the_heavy_section_cache() {
    let runner = FakeRunner::default();
    let push_full_snapshot = |runner: &FakeRunner| {
        runner.push_ok("running\n");
        runner.push_ok("2.3.2\n");
        runner.push_ok("off\n");
        runner.push(Ok(output(Some(1), "no\n", "")));
        runner.push_ok("public\n");
        runner.push_ok(ACTIVE_ZONES);
        runner.push_ok(LIST_ALL_RUNTIME);
        runner.push_ok(LIST_ALL_PERMANENT);
        runner.push_ok("\n");
        runner.push_ok("\n");
        runner.push_ok(DIRECT_RULES);
        runner.push_ok("ssh http https\n");
        runner.push_ok("\n");
        runner.push_ok("\n");
        for _ in 0..7 {
            runner.push_ok(INFO_SERVICE);
        }
    };
    push_full_snapshot(&runner);
    push_full_snapshot(&runner);

    let backend = CliBackend::new(runner.clone());
    backend.snapshot().await.unwrap();
    backend.snapshot_fresh().await.unwrap();

    let direct_reads = runner
        .seen_args()
        .iter()
        .filter(|args| args.as_slice() == ["--direct", "--get-all-rules"])
        .count();
    assert_eq!(
        direct_reads, 2,
        "mutation preflight must not reuse a cached heavy section"
    );
}

#[tokio::test]
async fn daemon_down_is_a_status_for_probe_and_an_error_for_snapshot() {
    let runner = FakeRunner::default();
    runner.push(Ok(output(Some(252), "not running\n", "")));
    runner.push_ok("2.3.2\n"); // --version works without the daemon

    let backend = CliBackend::new(runner.clone());
    let status = backend.probe().await.unwrap();
    assert!(!status.daemon_running);

    runner.push(Ok(output(Some(252), "not running\n", "")));
    runner.push_ok("2.3.2\n");
    let read = backend.snapshot_observed().await;
    assert_eq!(read.result.unwrap_err(), FirewallError::DaemonNotRunning);
    assert_eq!(read.observation.process_count, Some(2));
    assert_eq!(read.observation.sections[0].section, RefreshSection::Status);
}

#[tokio::test]
async fn polkit_denial_maps_to_permission_denied() {
    let runner = FakeRunner::default();
    runner.push_ok("running\n");
    runner.push_ok("2.3.2\n");
    // Real captured stderr: exit 253, dbus NotAuthorizedException traceback.
    runner.push(Ok(output(Some(253), "", PERM_DENIED_STDERR)));

    let backend = CliBackend::new(runner);
    match backend.probe().await.unwrap_err() {
        FirewallError::PermissionDenied { detail } => {
            assert!(detail.contains("Authorization failed"), "detail: {detail}");
        }
        other => panic!("expected PermissionDenied, got {other:?}"),
    }
}

#[tokio::test]
async fn missing_binary_maps_to_not_installed() {
    let runner = FakeRunner::default();
    runner.push(Err(ProcessError::NotFound("firewall-cmd")));
    let backend = CliBackend::new(runner);
    assert_eq!(
        backend.probe().await.unwrap_err(),
        FirewallError::NotInstalled
    );
}

#[tokio::test]
async fn timeouts_are_reported_as_timeouts() {
    let runner = FakeRunner::default();
    runner.push(Err(ProcessError::Timeout(Duration::from_secs(5))));
    let backend = CliBackend::new(runner);
    assert_eq!(
        backend.probe().await.unwrap_err(),
        FirewallError::Timeout(Duration::from_secs(5))
    );
}

#[tokio::test]
async fn unknown_failures_keep_exit_code_and_stderr() {
    let runner = FakeRunner::default();
    runner.push(Ok(output(Some(13), "", "COMMAND_FAILED: something odd")));
    let backend = CliBackend::new(runner);
    match backend.probe().await.unwrap_err() {
        FirewallError::CommandFailed { code, stderr } => {
            assert_eq!(code, 13);
            assert!(stderr.contains("something odd"));
        }
        other => panic!("expected CommandFailed, got {other:?}"),
    }
}

fn add_service_op() -> FirewallOperation {
    FirewallOperation::AddService {
        zone: ZoneName::parse("public").unwrap(),
        service: ServiceName::parse("https").unwrap(),
        target: ConfigurationTarget::RuntimeAndPermanent,
    }
}

#[tokio::test]
async fn apply_runs_runtime_then_permanent() {
    let runner = FakeRunner::default();
    runner.push_ok("success\n");
    runner.push_ok("success\n");
    let backend = CliBackend::new(runner.clone());

    let outcome = backend.apply(&add_service_op()).await;
    assert!(matches!(outcome, OperationOutcome::Applied { .. }));
    assert_eq!(
        runner.seen_args(),
        vec![
            vec!["--zone=public".to_owned(), "--add-service=https".to_owned()],
            vec![
                "--permanent".to_owned(),
                "--zone=public".to_owned(),
                "--add-service=https".to_owned(),
            ],
        ]
    );
}

#[tokio::test]
async fn permanent_failure_reports_partial_with_rollback_hint() {
    let runner = FakeRunner::default();
    runner.push_ok("success\n");
    runner.push(Ok(output(Some(253), "", PERM_DENIED_STDERR)));
    let backend = CliBackend::new(runner);

    match backend.apply(&add_service_op()).await {
        OperationOutcome::PartiallyApplied {
            steps,
            rollback_hint,
            ..
        } => {
            assert!(steps[0].succeeded());
            assert!(!steps[1].succeeded());
            match rollback_hint {
                Some(FirewallOperation::RemoveService { target, .. }) => {
                    assert_eq!(target, ConfigurationTarget::Runtime);
                }
                other => panic!("expected runtime-scoped inverse, got {other:?}"),
            }
        }
        other => panic!("expected PartiallyApplied, got {other:?}"),
    }
}

#[tokio::test]
async fn first_step_failure_is_clean_and_stops_the_plan() {
    let runner = FakeRunner::default();
    runner.push(Ok(output(Some(253), "", PERM_DENIED_STDERR)));
    // No second response queued: a second command would panic the fake runner.
    let backend = CliBackend::new(runner.clone());

    match backend.apply(&add_service_op()).await {
        OperationOutcome::Failed { steps, .. } => {
            assert_eq!(steps.len(), 1);
            assert!(matches!(
                steps[0].result,
                Err(FirewallError::PermissionDenied { .. })
            ));
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert_eq!(runner.seen_args().len(), 1, "permanent step must not run");
}

#[tokio::test]
async fn reload_is_a_single_global_invocation() {
    let runner = FakeRunner::default();
    runner.push_ok("success\n");
    let backend = CliBackend::new(runner.clone());
    let outcome = backend.apply(&FirewallOperation::Reload).await;
    assert!(matches!(outcome, OperationOutcome::Applied { .. }));
    assert_eq!(runner.seen_args(), vec![vec!["--reload".to_owned()]]);
}

#[tokio::test]
async fn a_timeout_during_apply_is_indeterminate_not_failed() {
    // A lost response is not a failure: the daemon may have applied the change
    // after the reply timed out. The outcome must be Indeterminate so the UI
    // never auto-inverts (which would double-apply if it did land).
    let runner = FakeRunner::default();
    runner.push(Err(ProcessError::Timeout(DEFAULT_TIMEOUT)));
    let backend = CliBackend::new(runner);

    match backend.apply(&add_service_op()).await {
        OperationOutcome::Indeterminate { steps, .. } => {
            assert_eq!(steps.len(), 1);
            assert!(matches!(steps[0].result, Err(FirewallError::Timeout(_))));
        }
        other => panic!("expected Indeterminate, got {other:?}"),
    }
}

#[tokio::test]
async fn offline_backend_fails_operations_with_no_offline_equivalent() {
    // Reload needs a running daemon; offline mode has none, so the plan is
    // empty. An empty plan is a loud Failed — never a silent success, never a
    // permanent change the operator never asked for.
    let runner = FakeRunner::default();
    let backend = CliBackend::offline(runner.clone());

    match backend.apply(&FirewallOperation::Reload).await {
        OperationOutcome::Failed { steps, .. } => {
            assert_eq!(steps.len(), 1);
            assert_eq!(steps[0].target, "offline");
            assert!(matches!(steps[0].result, Err(FirewallError::Process(_))));
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert!(
        runner.seen_args().is_empty(),
        "no command may run when there is no offline equivalent"
    );
}
