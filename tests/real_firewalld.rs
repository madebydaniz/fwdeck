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
use fwdeck::infrastructure::process::TokioRunner;

/// The real-daemon tests share one firewalld, so a `reload` in one test can
/// flip another's runtime view (a permanent-only zone becomes active mid-test).
/// This process-wide lock serializes them even when the runner forgets
/// `--test-threads=1`.
static FIREWALL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
#[ignore = "requires a running firewalld (use the dev container)"]
async fn probe_and_snapshot_against_real_daemon() {
    let _serial = FIREWALL_LOCK.lock().await;

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
    let _serial = FIREWALL_LOCK.lock().await;

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
    let _serial = FIREWALL_LOCK.lock().await;

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
    let _serial = FIREWALL_LOCK.lock().await;

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
    let _serial = FIREWALL_LOCK.lock().await;

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
    let _serial = FIREWALL_LOCK.lock().await;

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
    let _serial = FIREWALL_LOCK.lock().await;

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
    let _serial = FIREWALL_LOCK.lock().await;

    use fwdeck::domain::SnapshotSection;
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
    let _serial = FIREWALL_LOCK.lock().await;

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
    let _serial = FIREWALL_LOCK.lock().await;

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
    let _serial = FIREWALL_LOCK.lock().await;

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
    let _serial = FIREWALL_LOCK.lock().await;

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
    let _serial = FIREWALL_LOCK.lock().await;

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
