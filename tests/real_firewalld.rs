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

#[cfg(feature = "dbus")]
#[tokio::test]
#[ignore = "requires a running firewalld + D-Bus (dev container)"]
async fn dbus_backend_agrees_with_cli_on_read_path() {
    let _serial = FIREWALL_LOCK.lock().await;

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
    // Same zone set and, for the default zone, the same services (order-normalized).
    assert_eq!(cli_snap.zone_names(), dbus_snap.zone_names());
    let zone = &cli_snap.default_zone;
    let mut cli_services: Vec<_> = cli_snap.runtime[zone]
        .services
        .iter()
        .map(|s| s.as_str().to_owned())
        .collect();
    let mut dbus_services: Vec<_> = dbus_snap.runtime[zone]
        .services
        .iter()
        .map(|s| s.as_str().to_owned())
        .collect();
    cli_services.sort();
    dbus_services.sort();
    assert_eq!(cli_services, dbus_services, "runtime services must match");
    // Both must see the seeded runtime/permanent drift identically.
    assert_eq!(cli_snap.all_synced(), dbus_snap.all_synced());
}

#[tokio::test]
#[ignore = "MUTATES permanent config offline — dev container only"]
async fn offline_backend_reads_and_writes_permanent_config() {
    let _serial = FIREWALL_LOCK.lock().await;

    use fwdeck::application::ports::OperationOutcome;
    use fwdeck::domain::{ConfigurationTarget, FirewallOperation};

    // Offline backend works even though the container's daemon IS running —
    // firewall-offline-cmd edits the permanent config directly.
    let backend = CliBackend::offline(TokioRunner);

    let status = backend.probe().await.unwrap();
    assert!(!status.daemon_running, "offline reports no daemon");
    assert!(status.version.is_some());

    let snapshot = backend.snapshot().await.unwrap();
    assert!(!snapshot.runtime.is_empty());
    // Offline has a single config mirrored into both maps → no drift possible.
    assert!(snapshot.all_synced());

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
#[test]
#[ignore = "requires nftables + root (use the dev container)"]
fn nft_counters_parse_against_real_ruleset() {
    // Reads via the real `nft` binary; on the nftables backend this must return
    // Ok (possibly empty — firewalld counters only some rules), never a parse
    // error, which would mean the libnftables JSON shape drifted.
    match fwdeck::infrastructure::counters::read() {
        Ok(counters) => {
            // If the daemon has any countered rules, they are firewalld chains.
            for c in &counters {
                assert!(!c.chain.is_empty(), "chain names are populated");
            }
        }
        Err(err) => panic!("nft counter read/parse failed on a real ruleset: {err}"),
    }
}
