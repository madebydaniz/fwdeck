//! Optional integration tests against a real firewalld daemon. Ignored by
//! default: they must only run inside the dev container (or a disposable VM),
//! never on a developer machine.
//!
//! ```sh
//! docker compose run --rm dev cargo test --test real_firewalld -- --ignored
//! ```
//!
//! Several tests MUTATE firewalld (create/delete zones, add/remove services,
//! reload). They share one daemon, so they serialize on [`FIREWALL_LOCK`] —
//! `--test-threads=1` is then belt-and-suspenders, not a correctness
//! requirement. Each mutating test cleans up after itself.

// The serial lock is acquired first in each test (before the per-test `use`
// imports), which is intentional — hold it for the whole test body.
#![allow(clippy::unwrap_used, clippy::panic, clippy::items_after_statements)]

use fwdeck::application::ports::FirewallBackend;
use fwdeck::domain::{ConfigurationTarget, PortSpec, ServiceName};
use fwdeck::infrastructure::firewalld::CliBackend;
use fwdeck::infrastructure::process::{CommandOutput, CommandRequest, CommandRunner, TokioRunner};

const DISPOSABLE_MARKER: &str = "/run/fwdeck-disposable-firewalld";
const DISPOSABLE_ENV: &str = "FWDECK_REAL_FIREWALLD_TEST";

/// The real-daemon tests share one firewalld, so a `reload` in one test can
/// flip another's runtime view (a permanent-only zone becomes active mid-test).
/// This process-wide lock serializes them even when the runner forgets
/// `--test-threads=1`.
static FIREWALL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn disposable_environment_allowed(
    env_value: Option<&str>,
    marker_exists: bool,
    docker_identity_exists: bool,
) -> bool {
    env_value == Some("1") && marker_exists && docker_identity_exists
}

fn assert_disposable_environment() {
    let env_value = std::env::var(DISPOSABLE_ENV).ok();
    let marker_exists = std::path::Path::new(DISPOSABLE_MARKER).is_file();
    let docker_identity_exists = std::path::Path::new("/.dockerenv").is_file();
    assert!(
        disposable_environment_allowed(env_value.as_deref(), marker_exists, docker_identity_exists,),
        "real-firewalld tests require the FWDeck disposable container entrypoint"
    );
}

async fn guarded_firewall_lock() -> tokio::sync::MutexGuard<'static, ()> {
    assert_disposable_environment();
    FIREWALL_LOCK.lock().await
}

async fn firewall_output(args: &[&str]) -> CommandOutput {
    TokioRunner
        .run(CommandRequest {
            program: "firewall-cmd",
            args: args.iter().map(|arg| (*arg).to_owned()).collect(),
            timeout: std::time::Duration::from_secs(5),
        })
        .await
        .unwrap()
}

async fn firewall_ok(args: &[&str]) -> String {
    let output = firewall_output(args).await;
    assert_eq!(
        output.exit_code,
        Some(0),
        "firewall-cmd {args:?} failed: {}",
        output.stderr.trim()
    );
    output.stdout.trim().to_owned()
}

fn sorted_owned(mut items: Vec<String>) -> Vec<String> {
    items.sort();
    items
}

fn sorted_strings<T: std::fmt::Display>(items: &[T]) -> Vec<String> {
    sorted_owned(items.iter().map(ToString::to_string).collect())
}

async fn firewall_words(args: &[&str]) -> Vec<String> {
    sorted_owned(
        firewall_ok(args)
            .await
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
    )
}

async fn firewall_i16(args: &[&str]) -> i16 {
    firewall_ok(args).await.parse().unwrap()
}

async fn firewall_zone_info_i16(zone: &str, key: &str) -> i16 {
    let zone_argument = format!("--zone={zone}");
    let info = firewall_ok(&[&zone_argument, "--list-all"]).await;
    info.lines()
        .find_map(|line| {
            let (candidate, value) = line.trim_start().split_once(':')?;
            (candidate.trim() == key).then(|| value.trim().parse().unwrap())
        })
        .unwrap_or_else(|| panic!("missing `{key}` in runtime zone `{zone}`"))
}

async fn firewall_info_values(service: &str, key: &str) -> Vec<String> {
    let argument = format!("--info-service={service}");
    let info = firewall_ok(&["--permanent", &argument]).await;
    let values = info
        .lines()
        .find_map(|line| {
            let (candidate, values) = line.trim_start().split_once(':')?;
            (candidate.trim() == key).then_some(values)
        })
        .unwrap_or_else(|| panic!("missing `{key}` in service `{service}`"));
    sorted_owned(values.split_whitespace().map(str::to_owned).collect())
}

async fn ensure_reviewed_zone_runtime_seed() {
    let query = ["--zone=fwdeck-observe", "--query-service=https"];
    if firewall_output(&query).await.exit_code != Some(0) {
        let output = firewall_output(&["--zone=fwdeck-observe", "--add-service=https"]).await;
        assert_eq!(
            output.exit_code,
            Some(0),
            "failed to restore reviewed runtime service: {}",
            output.stderr.trim()
        );
    }
    assert_eq!(
        firewall_output(&query).await.exit_code,
        Some(0),
        "reviewed runtime service must be enabled"
    );
}

#[tokio::test]
#[ignore = "requires a running firewalld (use the dev container)"]
async fn probe_and_snapshot_against_real_daemon() {
    let _serial = guarded_firewall_lock().await;

    let backend = CliBackend::new(TokioRunner);

    let status = backend.probe().await.unwrap();
    assert!(
        status.daemon_running,
        "container entrypoint starts firewalld"
    );
    assert!(status.version.is_some());

    let snapshot = backend.snapshot().await.unwrap();
    assert!(!snapshot.runtime.is_empty());
    assert!(!snapshot.permanent.is_empty());
    assert!(
        snapshot.runtime.contains_key(&snapshot.default_zone),
        "default zone must exist in the runtime set"
    );
    assert!(!snapshot.available_services.is_empty());
    let blocklist = fwdeck::domain::IpSetName::parse("blocklist").unwrap();
    assert!(snapshot.ipsets.runtime.contains_key(&blocklist));
    assert!(snapshot.ipsets.permanent.contains_key(&blocklist));
    // Drift is intentionally NOT asserted here: it depends on seed state other
    // integration tests may disturb. `cli_parsing.rs` covers drift on fixtures.
}

#[tokio::test]
#[ignore = "MUTATES firewalld — dev container only"]
async fn add_and_remove_service_round_trip() {
    let _serial = guarded_firewall_lock().await;

    use fwdeck::application::ports::OperationOutcome;
    use fwdeck::domain::{ConfigurationTarget, FirewallOperation, ServiceName, ZoneName};

    let backend = CliBackend::new(TokioRunner);
    let zone = ZoneName::parse("public").unwrap();
    let service = ServiceName::parse("pop3").unwrap(); // unused by the seed data

    let add = FirewallOperation::AddService {
        zone: zone.clone(),
        service: service.clone(),
        target: ConfigurationTarget::RuntimeAndPermanent,
    };
    let outcome = backend.apply(&add).await;
    assert!(
        matches!(outcome, OperationOutcome::Applied { .. }),
        "{outcome:?}"
    );

    let snapshot = backend.snapshot().await.unwrap();
    assert!(snapshot.runtime[&zone].services.contains(&service));
    assert!(snapshot.permanent[&zone].services.contains(&service));

    let remove = FirewallOperation::RemoveService {
        zone: zone.clone(),
        service: service.clone(),
        target: ConfigurationTarget::RuntimeAndPermanent,
    };
    let outcome = backend.apply(&remove).await;
    assert!(
        matches!(outcome, OperationOutcome::Applied { .. }),
        "{outcome:?}"
    );

    let snapshot = backend.snapshot().await.unwrap();
    assert!(!snapshot.runtime[&zone].services.contains(&service));
    assert!(!snapshot.permanent[&zone].services.contains(&service));
}

#[tokio::test]
#[ignore = "MUTATES firewalld — dev container only"]
async fn create_and_delete_zone_round_trip() {
    let _serial = guarded_firewall_lock().await;

    use fwdeck::application::ports::OperationOutcome;
    use fwdeck::domain::{FirewallOperation, ZoneName};

    let backend = CliBackend::new(TokioRunner);
    let zone = ZoneName::parse("fwdeck-it").unwrap();

    let outcome = backend
        .apply(&FirewallOperation::CreateZone { zone: zone.clone() })
        .await;
    assert!(
        matches!(outcome, OperationOutcome::Applied { .. }),
        "{outcome:?}"
    );

    // Permanent-only: visible in the permanent map, absent from runtime.
    let snapshot = backend.snapshot().await.unwrap();
    assert!(snapshot.permanent.contains_key(&zone));
    assert!(!snapshot.runtime.contains_key(&zone));

    // Configuring the not-yet-active zone works with a permanent target
    // (the UI narrows to this automatically).
    let outcome = backend
        .apply(&FirewallOperation::AddService {
            zone: zone.clone(),
            service: ServiceName::parse("https").unwrap(),
            target: ConfigurationTarget::Permanent,
        })
        .await;
    assert!(
        matches!(outcome, OperationOutcome::Applied { .. }),
        "{outcome:?}"
    );
    let snapshot = backend.snapshot().await.unwrap();
    assert!(
        snapshot.permanent[&zone]
            .services
            .iter()
            .any(|s| s.as_str() == "https")
    );

    let outcome = backend
        .apply(&FirewallOperation::DeleteZone { zone: zone.clone() })
        .await;
    assert!(
        matches!(outcome, OperationOutcome::Applied { .. }),
        "{outcome:?}"
    );

    let snapshot = backend.snapshot().await.unwrap();
    assert!(!snapshot.permanent.contains_key(&zone));
}

#[tokio::test]
#[ignore = "MUTATES firewalld — dev container only"]
async fn custom_service_round_trip() {
    let _serial = guarded_firewall_lock().await;

    use fwdeck::application::ports::OperationOutcome;
    use fwdeck::domain::FirewallOperation;

    let backend = CliBackend::new(TokioRunner);
    let service = ServiceName::parse("fwdeck-it-svc").unwrap();
    let port: PortSpec = "9200/tcp".parse().unwrap();

    let ops = [
        FirewallOperation::CreateService {
            service: service.clone(),
        },
        FirewallOperation::AddServicePort {
            service: service.clone(),
            port,
        },
    ];
    for op in &ops {
        let outcome = backend.apply(op).await;
        assert!(
            matches!(outcome, OperationOutcome::Applied { .. }),
            "{outcome:?}"
        );
    }

    // The new service appears in the catalog after a reload.
    let _ = backend.apply(&FirewallOperation::Reload).await;
    let snapshot = backend.snapshot().await.unwrap();
    assert!(snapshot.available_services.contains(&service));

    let outcome = backend
        .apply(&FirewallOperation::DeleteService {
            service: service.clone(),
        })
        .await;
    assert!(
        matches!(outcome, OperationOutcome::Applied { .. }),
        "{outcome:?}"
    );
}

#[tokio::test]
#[ignore = "MUTATES firewalld — dev container only"]
async fn policy_round_trip() {
    let _serial = guarded_firewall_lock().await;

    use fwdeck::application::ports::OperationOutcome;
    use fwdeck::domain::{FirewallOperation, PolicyName, PolicyTarget};

    let backend = CliBackend::new(TokioRunner);
    let policy = PolicyName::parse("fwdeck-it-pol").unwrap();

    let ops = [
        FirewallOperation::CreatePolicy {
            policy: policy.clone(),
        },
        FirewallOperation::AddPolicyIngressZone {
            policy: policy.clone(),
            zone: "public".to_owned(),
        },
        FirewallOperation::AddPolicyEgressZone {
            policy: policy.clone(),
            zone: "ANY".to_owned(),
        },
        FirewallOperation::SetPolicyTarget {
            policy: policy.clone(),
            policy_target: PolicyTarget::Drop,
        },
    ];
    for op in &ops {
        let outcome = backend.apply(op).await;
        assert!(
            matches!(outcome, OperationOutcome::Applied { .. }),
            "{outcome:?}"
        );
    }

    let outcome = backend
        .apply(&FirewallOperation::DeletePolicy { policy })
        .await;
    assert!(
        matches!(outcome, OperationOutcome::Applied { .. }),
        "{outcome:?}"
    );
}

#[tokio::test]
#[ignore = "MUTATES firewalld — dev container only"]
async fn direct_rule_migration_creates_additive_policy_replacement() {
    let _serial = guarded_firewall_lock().await;

    use fwdeck::application::ports::OperationOutcome;
    use fwdeck::domain::{FirewallOperation, PolicyName, translate_direct_rule};

    let backend = CliBackend::new(TokioRunner);
    let snapshot = backend.snapshot().await.unwrap();
    let source_rule = "ipv4 filter INPUT 9 -p tcp --dport 12345 -j ACCEPT";
    assert!(snapshot.direct_rules.iter().any(|rule| rule == source_rule));

    let policy = PolicyName::parse_user_created("fwdeck-it-mig").unwrap();
    let migration = translate_direct_rule(source_rule)
        .unwrap()
        .into_migration(policy.clone());
    let outcome = backend
        .apply(&FirewallOperation::MigrateDirectRule {
            migration: migration.clone(),
        })
        .await;
    let migrated_snapshot = backend.snapshot().await;
    let cleanup = backend
        .apply(&FirewallOperation::DeletePolicy {
            policy: policy.clone(),
        })
        .await;

    assert!(
        matches!(outcome, OperationOutcome::Applied { .. }),
        "{outcome:?}"
    );
    let migrated_snapshot = migrated_snapshot.unwrap();
    let replacement = &migrated_snapshot.policies.permanent[&policy];
    assert!(
        replacement
            .ingress_zones
            .iter()
            .any(|zone| zone == migration.ingress_zone())
    );
    assert!(
        replacement
            .egress_zones
            .iter()
            .any(|zone| zone == migration.egress_zone())
    );
    assert!(replacement.rich_rules.contains(migration.rich_rule()));
    assert!(
        migrated_snapshot
            .direct_rules
            .iter()
            .any(|rule| rule == source_rule),
        "migration must never remove the legacy rule"
    );
    assert!(
        matches!(cleanup, OperationOutcome::Applied { .. }),
        "{cleanup:?}"
    );
}

#[tokio::test]
#[ignore = "MUTATES firewalld policy sets — dev container only"]
async fn policy_set_gateway_enable_disable_round_trip() {
    let _serial = guarded_firewall_lock().await;

    use fwdeck::application::ports::OperationOutcome;
    use fwdeck::domain::{
        FeatureSupport, FirewallOperation, FirewalldFeature, PolicySetDetails, PolicySetName,
        PolicySetState,
    };

    let backend = CliBackend::new(TokioRunner);
    let status = backend.probe().await.unwrap();
    if matches!(
        FirewalldFeature::PolicySets.support_for(status.version.as_deref()),
        FeatureSupport::Unsupported
    ) {
        return;
    }
    assert_eq!(
        FirewalldFeature::PolicySets.support_for(status.version.as_deref()),
        FeatureSupport::Supported,
        "policy-set support must be known before mutating the real daemon"
    );

    let policy_set = PolicySetName::parse("gateway").unwrap();
    let initial =
        PolicySetDetails::from_snapshot(&backend.snapshot().await.unwrap(), policy_set.clone());
    assert_eq!(initial.runtime.state, PolicySetState::Disabled);
    assert_eq!(initial.permanent.state, PolicySetState::Disabled);

    let enable = FirewallOperation::SetPolicySetEnabled {
        policy_set: policy_set.clone(),
        enabled: true,
        target: ConfigurationTarget::RuntimeAndPermanent,
    };
    let enable_outcome = backend.apply(&enable).await;
    let enabled_snapshot = backend.snapshot().await;

    let disable = FirewallOperation::SetPolicySetEnabled {
        policy_set: policy_set.clone(),
        enabled: false,
        target: ConfigurationTarget::RuntimeAndPermanent,
    };
    let disable_outcome = backend.apply(&disable).await;
    let restored_snapshot = backend.snapshot().await;

    assert!(
        matches!(enable_outcome, OperationOutcome::Applied { .. }),
        "{enable_outcome:?}"
    );
    let enabled = PolicySetDetails::from_snapshot(&enabled_snapshot.unwrap(), policy_set.clone());
    assert_eq!(enabled.runtime.state, PolicySetState::Enabled);
    assert_eq!(enabled.permanent.state, PolicySetState::Enabled);

    assert!(
        matches!(disable_outcome, OperationOutcome::Applied { .. }),
        "{disable_outcome:?}"
    );
    let restored = PolicySetDetails::from_snapshot(&restored_snapshot.unwrap(), policy_set);
    assert_eq!(restored.runtime.state, PolicySetState::Disabled);
    assert_eq!(restored.permanent.state, PolicySetState::Disabled);
}

#[cfg(feature = "dbus")]
fn sorted<T: Clone + Ord>(items: &[T]) -> Vec<T> {
    let mut items = items.to_vec();
    items.sort();
    items
}

#[cfg(feature = "dbus")]
fn assert_zone_parity(cli: &fwdeck::domain::ZoneDetails, dbus: &fwdeck::domain::ZoneDetails) {
    assert_eq!(dbus.target, cli.target, "zone targets must match");
    assert_eq!(dbus.ingress_priority, cli.ingress_priority);
    assert_eq!(dbus.egress_priority, cli.egress_priority);
    assert_eq!(sorted(&dbus.services), sorted(&cli.services));
    assert_eq!(sorted(&dbus.ports), sorted(&cli.ports));
    assert_eq!(sorted(&dbus.forward_ports), sorted(&cli.forward_ports));
    assert_eq!(sorted(&dbus.rich_rules), sorted(&cli.rich_rules));
    assert_eq!(sorted(&dbus.interfaces), sorted(&cli.interfaces));
    assert_eq!(sorted(&dbus.sources), sorted(&cli.sources));
    assert_eq!(sorted(&dbus.icmp_blocks), sorted(&cli.icmp_blocks));
    assert_eq!(dbus.masquerade, cli.masquerade);
}

#[cfg(feature = "dbus")]
fn assert_applied_method(outcome: &fwdeck::application::ports::OperationOutcome, expected: &str) {
    use fwdeck::application::ports::OperationOutcome;

    let OperationOutcome::Applied { steps, .. } = outcome else {
        panic!("expected applied outcome, got {outcome:?}");
    };
    assert_eq!(steps.len(), 1, "D-Bus operations report one step");
    assert_eq!(steps[0].target, "runtime");
    assert_eq!(
        steps[0].invocation.first().map(String::as_str),
        Some(expected)
    );
    assert!(steps[0].result.is_ok());
}

#[cfg(feature = "dbus")]
fn assert_cleanup_applied(
    primary: &fwdeck::application::ports::OperationOutcome,
    cleanup: &fwdeck::application::ports::OperationOutcome,
    expected: &str,
) {
    if !matches!(
        cleanup,
        fwdeck::application::ports::OperationOutcome::Applied { .. }
    ) {
        panic!("cleanup {expected} failed after primary outcome {primary:?}: {cleanup:?}");
    }
    assert_applied_method(cleanup, expected);
}

#[cfg(feature = "dbus")]
#[tokio::test]
#[ignore = "requires a running firewalld + D-Bus (dev container)"]
async fn dbus_backend_agrees_with_cli_on_read_path() {
    let _serial = guarded_firewall_lock().await;

    use fwdeck::domain::{FeatureSupport, FirewalldFeature, SnapshotSection};
    use fwdeck::infrastructure::firewalld::dbus::DbusBackend;

    let cli = CliBackend::new(TokioRunner);
    let dbus = DbusBackend::connect().await.unwrap();

    let cli_status = cli.probe().await.unwrap();
    let dbus_status = dbus.probe().await.unwrap();
    assert_eq!(cli_status.daemon_running, dbus_status.daemon_running);
    assert_eq!(cli_status.version, dbus_status.version);
    assert_eq!(cli_status.log_denied, dbus_status.log_denied);
    assert_eq!(cli_status.panic_mode, dbus_status.panic_mode);

    let cli_snap = cli.snapshot().await.unwrap();
    let dbus_snap = dbus.snapshot().await.unwrap();
    assert_eq!(cli_snap.default_zone, dbus_snap.default_zone);
    // Same zone set and supported zone fields (order-normalized).
    assert_eq!(cli_snap.zone_names(), dbus_snap.zone_names());
    let zone = &cli_snap.default_zone;
    assert_zone_parity(&cli_snap.runtime[zone], &dbus_snap.runtime[zone]);
    assert_zone_parity(&cli_snap.permanent[zone], &dbus_snap.permanent[zone]);
    if FirewalldFeature::ZonePriorities.support_for(cli_status.version.as_deref())
        == FeatureSupport::Supported
    {
        assert!(
            !dbus_snap.degraded.iter().any(|degraded| {
                degraded.section == SnapshotSection::Zones
                    && degraded.object.as_deref() == Some(zone.as_str())
            }),
            "supported zone priorities must have complete D-Bus evidence"
        );
    }
    // The D-Bus adapter intentionally omits these resource families. Its
    // aggregate drift value is therefore not comparable to the full CLI
    // snapshot, but the missing capabilities must be reported honestly.
    for section in [
        SnapshotSection::IpSets,
        SnapshotSection::Policies,
        SnapshotSection::DirectRules,
        SnapshotSection::ServiceDefinitions,
    ] {
        assert!(
            dbus_snap
                .degraded
                .iter()
                .any(|degraded| degraded.section == section),
            "{section:?} must be marked degraded"
        );
    }
}

#[cfg(feature = "dbus")]
#[tokio::test]
#[ignore = "MUTATES firewalld via D-Bus — dev container only"]
async fn dbus_backend_add_and_remove_service_runtime() {
    let _serial = guarded_firewall_lock().await;

    use fwdeck::domain::{ConfigurationTarget, FirewallOperation, ServiceName, ZoneName};
    use fwdeck::infrastructure::firewalld::dbus::DbusBackend;

    let backend = DbusBackend::connect().await.unwrap();
    let zone = ZoneName::parse("public").unwrap();
    let service = ServiceName::parse("pop3").unwrap(); // unused by the seed data

    // The D-Bus backend is runtime-only.
    let add = FirewallOperation::AddService {
        zone: zone.clone(),
        service: service.clone(),
        target: ConfigurationTarget::Runtime,
    };
    let initial = backend.snapshot().await.unwrap();
    if initial.runtime[&zone].services.contains(&service) {
        let preclean = backend
            .apply(&FirewallOperation::RemoveService {
                zone: zone.clone(),
                service: service.clone(),
                target: ConfigurationTarget::Runtime,
            })
            .await;
        assert_applied_method(&preclean, "removeService");
    }

    let add_outcome = backend.apply(&add).await;
    let added_snapshot = backend.snapshot().await;

    let remove = FirewallOperation::RemoveService {
        zone: zone.clone(),
        service: service.clone(),
        target: ConfigurationTarget::Runtime,
    };
    let remove_outcome = backend.apply(&remove).await;
    let restored_snapshot = backend.snapshot().await;

    assert_cleanup_applied(&add_outcome, &remove_outcome, "removeService");
    assert_applied_method(&add_outcome, "addService");
    assert!(
        added_snapshot.unwrap().runtime[&zone]
            .services
            .contains(&service),
        "service must be present after add"
    );
    assert!(
        !restored_snapshot.unwrap().runtime[&zone]
            .services
            .contains(&service),
        "service must be absent after cleanup"
    );
}

#[cfg(feature = "dbus")]
#[tokio::test]
#[ignore = "requires firewalld + D-Bus — dev container only"]
async fn dbus_backend_refuses_permanent_scope_honestly() {
    let _serial = guarded_firewall_lock().await;

    use fwdeck::application::ports::OperationOutcome;
    use fwdeck::domain::{ConfigurationTarget, FirewallOperation, ServiceName, ZoneName};
    use fwdeck::infrastructure::firewalld::dbus::DbusBackend;

    let backend = DbusBackend::connect().await.unwrap();
    let op = FirewallOperation::AddService {
        zone: ZoneName::parse("public").unwrap(),
        service: ServiceName::parse("pop3").unwrap(),
        target: ConfigurationTarget::RuntimeAndPermanent,
    };
    // Anything wider than runtime is refused (Failed) before mutating — never
    // half-applied-and-claimed-success.
    let outcome = backend.apply(&op).await;
    let OperationOutcome::Failed { steps, .. } = outcome else {
        panic!("expected permanent-scope refusal, got {outcome:?}");
    };
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].target, "runtime");
    assert_eq!(
        steps[0].invocation.first().map(String::as_str),
        Some("addService")
    );
    assert!(steps[0].result.is_err());
}

#[cfg(feature = "dbus")]
#[tokio::test]
#[ignore = "MUTATES firewalld via D-Bus — dev container only"]
async fn dbus_backend_add_and_remove_port_runtime() {
    let _serial = guarded_firewall_lock().await;

    use fwdeck::domain::{FirewallOperation, ZoneName};
    use fwdeck::infrastructure::firewalld::dbus::DbusBackend;

    let backend = DbusBackend::connect().await.unwrap();
    let zone = ZoneName::parse("public").unwrap();
    let port: PortSpec = "49152/tcp".parse().unwrap();

    let initial = backend.snapshot().await.unwrap();
    if initial.runtime[&zone].ports.contains(&port) {
        let preclean = backend
            .apply(&FirewallOperation::RemovePort {
                zone: zone.clone(),
                port,
                target: ConfigurationTarget::Runtime,
            })
            .await;
        assert_applied_method(&preclean, "removePort");
    }

    let add_outcome = backend
        .apply(&FirewallOperation::AddPort {
            zone: zone.clone(),
            port,
            target: ConfigurationTarget::Runtime,
        })
        .await;
    let added_snapshot = backend.snapshot().await;
    let remove_outcome = backend
        .apply(&FirewallOperation::RemovePort {
            zone: zone.clone(),
            port,
            target: ConfigurationTarget::Runtime,
        })
        .await;
    let restored_snapshot = backend.snapshot().await;

    assert_cleanup_applied(&add_outcome, &remove_outcome, "removePort");
    assert_applied_method(&add_outcome, "addPort");
    assert!(
        added_snapshot.unwrap().runtime[&zone].ports.contains(&port),
        "port must be present after add"
    );
    assert!(
        !restored_snapshot.unwrap().runtime[&zone]
            .ports
            .contains(&port),
        "port must be absent after cleanup"
    );
}

#[cfg(feature = "dbus")]
#[tokio::test]
#[ignore = "MUTATES firewalld via D-Bus — dev container only"]
async fn dbus_backend_restores_masquerade_runtime_state() {
    let _serial = guarded_firewall_lock().await;

    use fwdeck::domain::{FirewallOperation, ZoneName};
    use fwdeck::infrastructure::firewalld::dbus::DbusBackend;

    let backend = DbusBackend::connect().await.unwrap();
    let zone = ZoneName::parse("public").unwrap();
    let initial = backend.snapshot().await.unwrap().runtime[&zone].masquerade;
    let toggled = !initial;
    let toggle_method = if toggled {
        "addMasquerade"
    } else {
        "removeMasquerade"
    };
    let restore_method = if initial {
        "addMasquerade"
    } else {
        "removeMasquerade"
    };

    let toggle_outcome = backend
        .apply(&FirewallOperation::SetMasquerade {
            zone: zone.clone(),
            enabled: toggled,
            target: ConfigurationTarget::Runtime,
        })
        .await;
    let toggled_snapshot = backend.snapshot().await;
    let restore_outcome = backend
        .apply(&FirewallOperation::SetMasquerade {
            zone: zone.clone(),
            enabled: initial,
            target: ConfigurationTarget::Runtime,
        })
        .await;
    let restored_snapshot = backend.snapshot().await;

    assert_cleanup_applied(&toggle_outcome, &restore_outcome, restore_method);
    assert_applied_method(&toggle_outcome, toggle_method);
    assert_eq!(
        toggled_snapshot.unwrap().runtime[&zone].masquerade,
        toggled,
        "masquerade must change after toggle"
    );
    assert_eq!(
        restored_snapshot.unwrap().runtime[&zone].masquerade,
        initial,
        "masquerade must return to its initial state"
    );
}

#[tokio::test]
#[ignore = "MUTATES permanent config offline — dev container only"]
async fn offline_backend_reads_and_writes_permanent_config() {
    let _serial = guarded_firewall_lock().await;

    use fwdeck::application::ports::OperationOutcome;
    use fwdeck::domain::{ConfigurationTarget, FirewallOperation, SnapshotSection};

    // Offline backend works even though the container's daemon IS running —
    // firewall-offline-cmd edits the permanent config directly.
    let backend = CliBackend::offline(TokioRunner);

    let status = backend.probe().await.unwrap();
    assert!(!status.daemon_running, "offline reports no daemon");
    assert!(status.version.is_some());

    let snapshot = backend.snapshot().await.unwrap();
    assert!(snapshot.runtime.is_empty());
    assert!(!snapshot.permanent.is_empty());
    assert!(snapshot.degraded.iter().any(|degraded| {
        degraded.section == SnapshotSection::Zones
            && degraded.target == Some(ConfigurationTarget::Runtime)
    }));

    let zone = snapshot.default_zone.clone();
    let service = ServiceName::parse("imap").unwrap();
    let outcome = backend
        .apply(&FirewallOperation::AddService {
            zone: zone.clone(),
            service: service.clone(),
            target: ConfigurationTarget::Permanent,
        })
        .await;
    assert!(
        matches!(outcome, OperationOutcome::Applied { .. }),
        "{outcome:?}"
    );

    let snapshot = backend.snapshot().await.unwrap();
    assert!(snapshot.permanent[&zone].services.contains(&service));

    // Clean up.
    let _ = backend
        .apply(&FirewallOperation::RemoveService {
            zone,
            service,
            target: ConfigurationTarget::Permanent,
        })
        .await;
}

/// Verifies the nft-counter parser against **real** `nft -j list ruleset`
/// output (the fixture the JSON parser is really tested against — the unit
/// test's sample only pins the shape). Read-only.
#[tokio::test]
#[ignore = "requires nftables + root (use the dev container)"]
async fn nft_counters_parse_against_real_ruleset() {
    let _serial = guarded_firewall_lock().await;

    // Reads via the real `nft` binary; on the nftables backend this must return
    // Ok (possibly empty — firewalld counters only some rules), never a parse
    // error, which would mean the libnftables JSON shape drifted.
    match fwdeck::infrastructure::counters::read().await {
        Ok(counters) => {
            // If the daemon has any countered rules, they are firewalld chains.
            for c in &counters {
                assert!(!c.chain.is_empty(), "chain names are populated");
            }
        }
        Err(err) => panic!("nft counter read/parse failed on a real ruleset: {err}"),
    }
}

#[derive(Debug, serde::Deserialize)]
struct ReviewedZoneDocument {
    zones: Vec<ReviewedZone>,
}

#[derive(Debug, serde::Deserialize)]
struct ReviewedZone {
    name: String,
    runtime: ReviewedZoneScope,
    permanent: ReviewedZoneScope,
}

#[derive(Debug, serde::Deserialize)]
struct ReviewedZoneScope {
    ingress_priority: i16,
    egress_priority: i16,
    services: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ReviewedServiceDocument {
    complete_case: ReviewedServiceCase,
}

#[derive(Debug, serde::Deserialize)]
struct ReviewedServiceCase {
    root: String,
    definitions: Vec<ReviewedServiceDefinition>,
}

#[derive(Debug, serde::Deserialize)]
struct ReviewedServiceDefinition {
    name: String,
    ports: Vec<String>,
    protocols: Vec<String>,
    source_ports: Vec<String>,
    destinations: Vec<ReviewedDestination>,
    includes: Vec<String>,
    helpers: Vec<String>,
    modules: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ReviewedDestination {
    family: String,
    address: String,
}

fn reviewed_destinations(definition: &ReviewedServiceDefinition) -> Vec<String> {
    sorted_owned(
        definition
            .destinations
            .iter()
            .map(|destination| format!("{}:{}", destination.family, destination.address))
            .collect(),
    )
}

fn observed_destinations(definition: &fwdeck::domain::ServiceDefinition) -> Vec<String> {
    sorted_owned(
        definition
            .destinations
            .iter()
            .map(|destination| format!("{}:{}", destination.family.as_str(), destination.address))
            .collect(),
    )
}

fn assert_service_definition(
    observed: &fwdeck::domain::ServiceDefinition,
    reviewed: &ReviewedServiceDefinition,
) {
    assert_eq!(
        sorted_strings(&observed.ports),
        sorted_owned(reviewed.ports.clone())
    );
    assert_eq!(
        sorted_strings(&observed.protocols),
        sorted_owned(reviewed.protocols.clone())
    );
    assert_eq!(
        sorted_strings(&observed.source_ports),
        sorted_owned(reviewed.source_ports.clone())
    );
    assert_eq!(
        observed_destinations(observed),
        reviewed_destinations(reviewed)
    );
    assert_eq!(
        sorted_strings(&observed.includes),
        sorted_owned(reviewed.includes.clone())
    );
    assert_eq!(
        sorted_strings(&observed.helpers),
        sorted_owned(reviewed.helpers.clone())
    );
    assert_eq!(
        sorted_strings(&observed.modules),
        sorted_owned(reviewed.modules.clone())
    );
}

fn reviewed_zone() -> ReviewedZone {
    let document: ReviewedZoneDocument = serde_json::from_str(include_str!(
        "fixtures/traffic_testing/observation/zone-observation.json"
    ))
    .unwrap();
    document
        .zones
        .into_iter()
        .find(|zone| zone.name == "public")
        .unwrap()
}

fn reviewed_service() -> ReviewedServiceCase {
    let document: ReviewedServiceDocument = serde_json::from_str(include_str!(
        "fixtures/traffic_testing/observation/service-evidence.json"
    ))
    .unwrap();
    document.complete_case
}

async fn assert_reviewed_priorities(
    runtime: &fwdeck::domain::ZoneDetails,
    permanent: &fwdeck::domain::ZoneDetails,
    reviewed: &ReviewedZone,
    version: &str,
) {
    use fwdeck::domain::{FeatureSupport, FirewalldFeature};

    match FirewalldFeature::ZonePriorities.support_for(Some(version.trim())) {
        FeatureSupport::Supported => {
            assert_eq!(
                runtime.ingress_priority.get(),
                reviewed.permanent.ingress_priority
            );
            assert_eq!(
                runtime.egress_priority.get(),
                reviewed.permanent.egress_priority
            );
            assert_eq!(
                permanent.ingress_priority.get(),
                reviewed.permanent.ingress_priority
            );
            assert_eq!(
                permanent.egress_priority.get(),
                reviewed.permanent.egress_priority
            );
            assert_eq!(
                firewall_zone_info_i16("fwdeck-observe", "ingress-priority").await,
                reviewed.permanent.ingress_priority
            );
            assert_eq!(
                firewall_zone_info_i16("fwdeck-observe", "egress-priority").await,
                reviewed.permanent.egress_priority
            );
            assert_eq!(
                firewall_i16(&[
                    "--permanent",
                    "--zone=fwdeck-observe",
                    "--get-ingress-priority",
                ])
                .await,
                reviewed.permanent.ingress_priority
            );
            assert_eq!(
                firewall_i16(&[
                    "--permanent",
                    "--zone=fwdeck-observe",
                    "--get-egress-priority",
                ])
                .await,
                reviewed.permanent.egress_priority
            );
        }
        FeatureSupport::Unsupported => {
            assert_ne!(
                firewall_output(&[
                    "--permanent",
                    "--zone=fwdeck-observe",
                    "--get-ingress-priority",
                ])
                .await
                .exit_code,
                Some(0),
                "pre-2.0 firewalld must not be treated as priority-capable"
            );
        }
        FeatureSupport::Unknown => panic!("unusable firewalld version `{version}`"),
    }
}

async fn assert_reviewed_zone(
    snapshot: &fwdeck::domain::FirewallSnapshot,
    reviewed: &ReviewedZone,
    version: &str,
) -> fwdeck::domain::ZoneName {
    let zone = fwdeck::domain::ZoneName::parse("fwdeck-observe").unwrap();
    let runtime = &snapshot.runtime[&zone];
    let permanent = &snapshot.permanent[&zone];

    assert_eq!(
        sorted_strings(&runtime.services),
        sorted_owned(reviewed.runtime.services.clone())
    );
    assert_eq!(
        sorted_strings(&permanent.services),
        sorted_owned(reviewed.permanent.services.clone())
    );
    assert_eq!(
        firewall_words(&["--zone=fwdeck-observe", "--list-services"]).await,
        sorted_owned(reviewed.runtime.services.clone())
    );
    assert_eq!(
        firewall_words(&["--permanent", "--zone=fwdeck-observe", "--list-services"]).await,
        sorted_owned(reviewed.permanent.services.clone())
    );
    assert_reviewed_priorities(runtime, permanent, reviewed, version).await;
    zone
}

async fn assert_reviewed_service_definition(
    snapshot: &fwdeck::domain::FirewallSnapshot,
    reviewed: &ReviewedServiceCase,
) {
    let root = reviewed
        .definitions
        .iter()
        .find(|definition| definition.name == reviewed.root)
        .unwrap();
    let service = ServiceName::parse(&reviewed.root).unwrap();
    assert_service_definition(&snapshot.service_definitions[&service], root);
    assert_eq!(
        firewall_words(&["--permanent", "--service=admin-stack", "--get-ports"]).await,
        sorted_owned(root.ports.clone())
    );
    assert_eq!(
        firewall_words(&["--permanent", "--service=admin-stack", "--get-protocols"]).await,
        sorted_owned(root.protocols.clone())
    );
    assert_eq!(
        firewall_words(&["--permanent", "--service=admin-stack", "--get-source-ports",]).await,
        sorted_owned(root.source_ports.clone())
    );
    assert_eq!(
        firewall_words(&["--permanent", "--service=admin-stack", "--get-destinations"]).await,
        reviewed_destinations(root)
    );
    assert_eq!(
        firewall_words(&["--permanent", "--service=admin-stack", "--get-includes"]).await,
        sorted_owned(root.includes.clone())
    );
    assert_eq!(
        firewall_words(&[
            "--permanent",
            "--service=admin-stack",
            "--get-service-helpers",
        ])
        .await,
        sorted_owned(root.helpers.clone())
    );
    assert_eq!(
        firewall_info_values("admin-stack", "modules").await,
        sorted_owned(root.modules.clone())
    );
}

#[cfg(feature = "dbus")]
async fn assert_semantic_dbus_parity(
    cli: &fwdeck::domain::FirewallSnapshot,
    zone: &fwdeck::domain::ZoneName,
) {
    use fwdeck::domain::SnapshotSection;
    use fwdeck::infrastructure::firewalld::dbus::DbusBackend;

    let dbus = DbusBackend::connect().await.unwrap();
    let dbus_snapshot = dbus.snapshot().await.unwrap();
    assert_zone_parity(&cli.runtime[zone], &dbus_snapshot.runtime[zone]);
    assert_zone_parity(&cli.permanent[zone], &dbus_snapshot.permanent[zone]);
    assert!(
        dbus_snapshot
            .degraded
            .iter()
            .any(|degraded| degraded.section == SnapshotSection::ServiceDefinitions)
    );
}

fn reviewed_host_ingress_context() -> fwdeck::domain::EvaluationContext {
    fwdeck::domain::EvaluationContext {
        run_id: fwdeck::domain::TrafficTestRunId::new(1).unwrap(),
        suite_id: fwdeck::domain::TrafficSuiteId::parse("real-firewalld-host-ingress").unwrap(),
        suite_revision: fwdeck::domain::TrafficSuiteRevision::new(1).unwrap(),
        phase: fwdeck::domain::EvaluationPhase::Current,
        target: fwdeck::domain::EvaluationTarget::Runtime,
        authoritative_snapshot: fwdeck::domain::EvaluationSnapshotIdentity::new(1, 1).unwrap(),
        base_snapshot: None,
        mutation_intent_id: None,
        plan_id: None,
        candidate_identity: None,
    }
}

fn reviewed_https_host_ingress() -> fwdeck::domain::TrafficScenario {
    fwdeck::domain::TrafficScenario {
        id: fwdeck::domain::TrafficScenarioId::parse("real-firewalld-https").unwrap(),
        name: "Reviewed HTTPS host ingress".to_owned(),
        enabled: true,
        direction: fwdeck::domain::TrafficDirection::ToHost,
        source: fwdeck::domain::SourceAddress::parse("192.0.2.10").unwrap(),
        ingress_interface: None,
        ingress_zone: Some(fwdeck::domain::ZoneName::parse("fwdeck-observe").unwrap()),
        destination: fwdeck::domain::TrafficDestination::LocalHost,
        egress_interface: None,
        egress_zone: None,
        transport: fwdeck::domain::TrafficTransport::Tcp,
        destination_port: Some("443".parse().unwrap()),
        source_port: None,
        connection_state: fwdeck::domain::TrafficConnectionState::New,
        expectation: fwdeck::domain::TrafficExpectation::Allow,
        severity: fwdeck::domain::TrafficSeverity::Critical,
        required_safety_gate: true,
        note: Some("compared with firewall-cmd query-service evidence".to_owned()),
    }
}

fn predict_reviewed_https(
    snapshot: fwdeck::domain::FirewallSnapshot,
) -> fwdeck::domain::TrafficTestResult {
    let index = fwdeck::domain::TrafficEvaluationIndex::new(
        std::sync::Arc::new(snapshot),
        fwdeck::domain::EvaluationTarget::Runtime,
    );
    fwdeck::domain::evaluate_scenario(
        &index,
        &reviewed_https_host_ingress(),
        &reviewed_host_ingress_context(),
    )
    .unwrap()
}

#[test]
fn disposable_real_daemon_guard_rejects_host_like_processes() {
    assert!(!disposable_environment_allowed(None, false, false));
    assert!(!disposable_environment_allowed(Some("1"), false, true));
    assert!(!disposable_environment_allowed(Some("1"), true, false));
    assert!(disposable_environment_allowed(Some("1"), true, true));
}

#[tokio::test]
#[ignore = "requires a seeded disposable firewalld container"]
async fn semantic_observation_matches_reviewed_seed_and_daemon_oracle() {
    let _serial = guarded_firewall_lock().await;
    let reviewed_zone = reviewed_zone();
    let reviewed_service = reviewed_service();
    let version = firewall_ok(&["--version"]).await;
    eprintln!("firewalld-version={}", version.trim());

    // Earlier integration tests may reload the shared daemon and clear
    // runtime-only seeds. Restore this test's reviewed precondition so it is
    // independent of suite order while remaining idempotent in isolation.
    ensure_reviewed_zone_runtime_seed().await;

    let backend = CliBackend::new(TokioRunner);
    let snapshot = backend.snapshot().await.unwrap();
    let zone = assert_reviewed_zone(&snapshot, &reviewed_zone, &version).await;
    assert_reviewed_service_definition(&snapshot, &reviewed_service).await;

    #[cfg(feature = "dbus")]
    assert_semantic_dbus_parity(&snapshot, &zone).await;
    #[cfg(not(feature = "dbus"))]
    let _ = zone;
}

#[tokio::test]
#[ignore = "requires a seeded disposable firewalld container"]
async fn cli_host_ingress_prediction_matches_daemon_query_evidence() {
    let _serial = guarded_firewall_lock().await;
    ensure_reviewed_zone_runtime_seed().await;

    let query = firewall_output(&["--zone=fwdeck-observe", "--query-service=https"]).await;
    assert_eq!(
        query.exit_code,
        Some(0),
        "reviewed daemon query must prove HTTPS enabled"
    );
    let direct = firewall_output(&[
        "--direct",
        "--query-rule",
        "ipv4",
        "filter",
        "INPUT",
        "9",
        "-p",
        "tcp",
        "--dport",
        "12345",
        "-j",
        "ACCEPT",
    ])
    .await;
    assert_eq!(
        direct.exit_code,
        Some(0),
        "reviewed direct-rule seed must exist"
    );
    let snapshot = CliBackend::new(TokioRunner).snapshot().await.unwrap();
    let result = predict_reviewed_https(snapshot);
    assert_eq!(
        result.decision(),
        fwdeck::domain::FirewallDecision::Unknown,
        "seeded external direct rule must prevent a false positive: {result:?}"
    );
    assert_eq!(
        result.unknown_reason(),
        Some(fwdeck::domain::UnknownReason::ExternalRulesOutsideModel)
    );
}

#[tokio::test]
#[ignore = "MUTATES reviewed direct seed temporarily — dev container only"]
#[allow(clippy::too_many_lines)]
async fn cli_host_ingress_positive_prediction_matches_daemon_query_evidence() {
    let _serial = guarded_firewall_lock().await;
    ensure_reviewed_zone_runtime_seed().await;
    let runtime_remove = firewall_output(&[
        "--direct",
        "--remove-rule",
        "ipv4",
        "filter",
        "INPUT",
        "9",
        "-p",
        "tcp",
        "--dport",
        "12345",
        "-j",
        "ACCEPT",
    ])
    .await;
    let permanent_remove = firewall_output(&[
        "--permanent",
        "--direct",
        "--remove-rule",
        "ipv4",
        "filter",
        "INPUT",
        "9",
        "-p",
        "tcp",
        "--dport",
        "12345",
        "-j",
        "ACCEPT",
    ])
    .await;
    let policy_seed =
        firewall_output(&["--policy=allow-host-ipv6", "--query-ingress-zone=ANY"]).await;
    let policy_remove =
        firewall_output(&["--policy=allow-host-ipv6", "--remove-ingress-zone=ANY"]).await;
    let query = firewall_output(&["--zone=fwdeck-observe", "--query-service=https"]).await;
    let observed = CliBackend::new(TokioRunner).snapshot().await;

    let policy_restore =
        firewall_output(&["--policy=allow-host-ipv6", "--add-ingress-zone=ANY"]).await;
    let runtime_restore = firewall_output(&[
        "--direct",
        "--add-rule",
        "ipv4",
        "filter",
        "INPUT",
        "9",
        "-p",
        "tcp",
        "--dport",
        "12345",
        "-j",
        "ACCEPT",
    ])
    .await;
    let permanent_restore = firewall_output(&[
        "--permanent",
        "--direct",
        "--add-rule",
        "ipv4",
        "filter",
        "INPUT",
        "9",
        "-p",
        "tcp",
        "--dport",
        "12345",
        "-j",
        "ACCEPT",
    ])
    .await;

    assert_eq!(
        runtime_remove.exit_code,
        Some(0),
        "runtime direct seed removal failed"
    );
    assert_eq!(
        permanent_remove.exit_code,
        Some(0),
        "permanent direct seed removal failed"
    );
    assert_eq!(
        runtime_restore.exit_code,
        Some(0),
        "runtime direct seed restore failed"
    );
    assert_eq!(
        permanent_restore.exit_code,
        Some(0),
        "permanent direct seed restore failed"
    );
    assert_eq!(
        policy_remove.exit_code,
        Some(0),
        "built-in policy isolation failed"
    );
    assert_eq!(
        policy_seed.exit_code,
        Some(0),
        "built-in policy seed must own ANY before isolation"
    );
    assert_eq!(
        policy_restore.exit_code,
        Some(0),
        "built-in policy restore failed"
    );
    assert_eq!(query.exit_code, Some(0), "daemon HTTPS query must succeed");
    let snapshot = observed.unwrap();
    let degraded = snapshot.degraded.clone();
    let result = predict_reviewed_https(snapshot);
    assert_eq!(
        result.decision(),
        fwdeck::domain::FirewallDecision::Allow,
        "CLI prediction disagrees with daemon evidence: result={result:?} degraded={degraded:?}"
    );
    assert_eq!(result.status(), fwdeck::domain::TrafficTestStatus::Pass);
}

#[cfg(feature = "dbus")]
#[tokio::test]
#[ignore = "requires a seeded disposable firewalld container with system D-Bus"]
async fn dbus_host_ingress_prediction_preserves_unknown_when_snapshot_is_incomplete() {
    use fwdeck::infrastructure::firewalld::dbus::DbusBackend;

    let _serial = guarded_firewall_lock().await;
    ensure_reviewed_zone_runtime_seed().await;
    let query = firewall_output(&["--zone=fwdeck-observe", "--query-service=https"]).await;
    assert_eq!(
        query.exit_code,
        Some(0),
        "daemon query must prove HTTPS enabled"
    );

    let snapshot = DbusBackend::connect()
        .await
        .unwrap()
        .snapshot()
        .await
        .unwrap();
    let result = predict_reviewed_https(snapshot);
    assert_eq!(result.decision(), fwdeck::domain::FirewallDecision::Unknown);
    assert_eq!(
        result.status(),
        fwdeck::domain::TrafficTestStatus::Indeterminate
    );
    assert_eq!(
        result.unknown_reason(),
        Some(fwdeck::domain::UnknownReason::IncompleteSnapshot)
    );
}
