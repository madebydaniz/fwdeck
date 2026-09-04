#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use super::*;
use crate::domain::{
    FirewallStatus, LogDenied, NetfilterBackend, PolicyTarget, Scoped, TrafficDimension, ZoneTarget,
};

fn zone() -> ZoneName {
    ZoneName::parse("public").unwrap()
}

fn policy() -> PolicyName {
    PolicyName::parse("policy").unwrap()
}

fn snapshot() -> FirewallSnapshot {
    let mut zone_details = ZoneDetails::empty(zone());
    zone_details.target = ZoneTarget::Accept;
    let mut policy_details = PolicyDetails::empty(policy());
    policy_details.target = PolicyTarget::Continue;
    FirewallSnapshot {
        status: FirewallStatus {
            daemon_running: true,
            version: Some("2.4.0".to_owned()),
            backend: NetfilterBackend::Nftables,
            log_denied: LogDenied::Off,
            panic_mode: false,
        },
        default_zone: zone(),
        active: BTreeMap::new(),
        runtime: BTreeMap::from([(zone(), zone_details.clone())]),
        permanent: BTreeMap::from([(zone(), zone_details)]),
        ipsets: Scoped::default(),
        service_definitions: BTreeMap::new(),
        available_services: Vec::new(),
        policies: Scoped {
            runtime: BTreeMap::from([(policy(), policy_details.clone())]),
            permanent: BTreeMap::from([(policy(), policy_details)]),
        },
        direct_rules: Vec::new(),
        degraded: Vec::new(),
    }
}

fn marker() -> ProjectionUnknownEffect {
    ProjectionUnknownEffect {
        operation_index: 0,
        reason: UnsupportedOperationReason::IpSetSemantics,
        object: AffectedObject::Global,
        dimensions: vec![TrafficDimension::IpSet],
    }
}

#[test]
fn private_target_copy_and_requirement_invariants_are_explicit() {
    let mut state = ProjectionState::new(&snapshot());
    state.unknown_permanent.push(marker());
    state.mark_unknown(OperationTargetSequence::RuntimeFromPermanent, marker());
    assert_eq!(state.unknown_runtime, state.unknown_permanent);
    state.unknown_runtime.push(marker());
    state.mark_unknown(OperationTargetSequence::PermanentFromRuntime, marker());
    assert_eq!(state.unknown_permanent, state.unknown_runtime);

    for target in [
        ConfigurationTarget::Runtime,
        ConfigurationTarget::Permanent,
        ConfigurationTarget::RuntimeAndPermanent,
    ] {
        assert!(state.require_zone(target, &zone()).is_ok());
        assert!(state.require_policy(target, &policy()).is_ok());
    }
    let missing_zone = ZoneName::parse("missing-zone").unwrap();
    let missing_policy = PolicyName::parse("missing-policy").unwrap();
    assert!(
        state
            .require_zone(ConfigurationTarget::RuntimeAndPermanent, &missing_zone)
            .is_err()
    );
    assert!(
        state
            .require_policy(ConfigurationTarget::RuntimeAndPermanent, &missing_policy)
            .is_err()
    );
}

#[test]
fn private_active_zone_cleanup_handles_a_removed_runtime_object() {
    let mut state = ProjectionState::new(&snapshot());
    state.snapshot.active.insert(
        zone(),
        ActiveZone {
            interfaces: Vec::new(),
            sources: Vec::new(),
        },
    );
    state.snapshot.runtime.remove(&zone());
    state.sync_active_zone(&zone());
    assert!(!state.snapshot.active.contains_key(&zone()));
}

#[test]
#[should_panic(expected = "handled by effect metadata")]
fn exact_dispatch_rejects_global_operations() {
    let mut state = ProjectionState::new(&snapshot());
    let _ = state.apply_exact(&FirewallOperation::Reload);
}

#[test]
#[should_panic(expected = "global effect metadata")]
fn global_dispatch_rejects_non_global_operations() {
    let mut state = ProjectionState::new(&snapshot());
    state.apply_global(&FirewallOperation::SetPanicMode { enabled: true });
}
