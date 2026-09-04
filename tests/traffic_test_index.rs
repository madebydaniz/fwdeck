#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::Arc;

use fwdeck::domain::{
    ConfigurationTarget, DegradedSection, EvaluationTarget, FirewallSnapshot, FirewallStatus,
    IndexedZoneBindingKind, InterfaceName, LogDenied, NetfilterBackend, PolicyDetails, PolicyName,
    PolicyTarget, RulePriority, Scoped, ServiceDefinition, ServiceName, SnapshotSection,
    SourceAddress, TrafficEvaluationIndex, ZoneDetails, ZoneName,
};

fn zone(name: &str, priority: i32) -> ZoneDetails {
    let name = ZoneName::parse(name).unwrap();
    let mut zone = ZoneDetails::empty(name);
    zone.ingress_priority = RulePriority::new(priority).unwrap();
    zone
}

fn policy(name: &str, priority: i32, service: &str) -> PolicyDetails {
    let name = PolicyName::parse(name).unwrap();
    let mut policy = PolicyDetails::empty(name);
    policy.active = true;
    policy.priority = priority;
    policy.target = PolicyTarget::Continue;
    policy.ingress_zones = vec!["ANY".to_owned()];
    policy.egress_zones = vec!["HOST".to_owned()];
    policy.services = vec![ServiceName::parse(service).unwrap()];
    policy
}

#[allow(clippy::too_many_lines)]
fn snapshot() -> FirewallSnapshot {
    let mut runtime_public = zone("public", 100);
    runtime_public.interfaces = vec![InterfaceName::parse("eth0").unwrap()];
    runtime_public.sources = vec![SourceAddress::parse("192.0.2.0/24").unwrap()];
    runtime_public.services = vec![ServiceName::parse("web-stack").unwrap()];

    let mut runtime_home = zone("home", -10);
    runtime_home.sources = vec![SourceAddress::parse("10.0.0.0/8").unwrap()];
    runtime_home.services = vec![ServiceName::parse("missing-root").unwrap()];

    let mut permanent_public = zone("public", -20);
    permanent_public.interfaces = vec![InterfaceName::parse("eth9").unwrap()];
    permanent_public.services = vec![ServiceName::parse("ssh").unwrap()];

    let root = ServiceDefinition {
        ports: vec!["80/tcp".parse().unwrap()],
        includes: vec![ServiceName::parse("tls").unwrap()],
        ..ServiceDefinition::default()
    };
    let tls = ServiceDefinition {
        ports: vec!["443/tcp".parse().unwrap()],
        ..ServiceDefinition::default()
    };
    let ssh = ServiceDefinition {
        ports: vec!["22/tcp".parse().unwrap()],
        ..ServiceDefinition::default()
    };

    FirewallSnapshot {
        status: FirewallStatus {
            daemon_running: true,
            version: Some("2.4.0".to_owned()),
            backend: NetfilterBackend::Nftables,
            log_denied: LogDenied::Off,
            panic_mode: false,
        },
        default_zone: ZoneName::parse("public").unwrap(),
        active: BTreeMap::new(),
        runtime: BTreeMap::from([
            (ZoneName::parse("public").unwrap(), runtime_public),
            (ZoneName::parse("home").unwrap(), runtime_home),
        ]),
        permanent: BTreeMap::from([(ZoneName::parse("public").unwrap(), permanent_public)]),
        ipsets: Scoped::default(),
        service_definitions: BTreeMap::from([
            (ServiceName::parse("web-stack").unwrap(), root),
            (ServiceName::parse("tls").unwrap(), tls),
            (ServiceName::parse("ssh").unwrap(), ssh),
        ]),
        available_services: vec![
            ServiceName::parse("ssh").unwrap(),
            ServiceName::parse("tls").unwrap(),
            ServiceName::parse("web-stack").unwrap(),
        ],
        policies: Scoped {
            runtime: BTreeMap::from([
                (
                    PolicyName::parse("late").unwrap(),
                    policy("late", 100, "ssh"),
                ),
                (
                    PolicyName::parse("first-b").unwrap(),
                    policy("first-b", -10, "web-stack"),
                ),
                (
                    PolicyName::parse("first-a").unwrap(),
                    policy("first-a", -10, "web-stack"),
                ),
            ]),
            permanent: BTreeMap::new(),
        },
        direct_rules: vec!["ipv4 filter INPUT 0 -j ACCEPT".to_owned()],
        degraded: vec![DegradedSection::new(
            SnapshotSection::Services,
            Some(ConfigurationTarget::Runtime),
            "runtime service listing incomplete",
        )],
    }
}

#[test]
fn runtime_and_permanent_indexes_are_target_isolated_and_share_the_snapshot() {
    let snapshot = Arc::new(snapshot());
    let runtime = TrafficEvaluationIndex::new(Arc::clone(&snapshot), EvaluationTarget::Runtime);
    let permanent = TrafficEvaluationIndex::new(Arc::clone(&snapshot), EvaluationTarget::Permanent);

    assert!(Arc::ptr_eq(runtime.snapshot_arc(), &snapshot));
    assert!(Arc::ptr_eq(permanent.snapshot_arc(), &snapshot));
    assert_eq!(
        runtime
            .zones()
            .get(&ZoneName::parse("public").unwrap())
            .unwrap()
            .ingress_priority
            .get(),
        100
    );
    assert_eq!(
        permanent
            .zones()
            .get(&ZoneName::parse("public").unwrap())
            .unwrap()
            .ingress_priority
            .get(),
        -20
    );
    assert_eq!(runtime.zones().len(), 2);
    assert_eq!(permanent.zones().len(), 1);
}

#[test]
fn zones_bindings_and_policies_have_deterministic_semantic_order() {
    let index = TrafficEvaluationIndex::new(Arc::new(snapshot()), EvaluationTarget::Runtime);
    assert_eq!(
        index
            .zone_order()
            .iter()
            .map(ZoneName::as_str)
            .collect::<Vec<_>>(),
        vec!["home", "public"]
    );
    assert_eq!(
        index
            .policy_order()
            .iter()
            .map(PolicyName::as_str)
            .collect::<Vec<_>>(),
        vec!["first-a", "first-b", "late"]
    );
    assert!(index.zone_bindings().iter().any(|binding| {
        binding.zone().as_str() == "public"
            && matches!(
                binding.kind(),
                IndexedZoneBindingKind::Interface(interface) if interface.as_str() == "eth0"
            )
    }));
}

#[test]
fn referenced_services_are_preexpanded_with_typed_failures() {
    let index = TrafficEvaluationIndex::new(Arc::new(snapshot()), EvaluationTarget::Runtime);
    let web = index
        .service(&ServiceName::parse("web-stack").unwrap())
        .unwrap();
    assert!(web.failures.is_empty());
    assert_eq!(
        web.effective
            .ports
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        vec!["80/tcp", "443/tcp"]
    );

    let missing = index
        .service(&ServiceName::parse("missing-root").unwrap())
        .unwrap();
    assert_eq!(missing.failures.len(), 1);
}

#[test]
fn completeness_and_external_rule_evidence_remain_target_specific() {
    let snapshot = Arc::new(snapshot());
    let runtime = TrafficEvaluationIndex::new(Arc::clone(&snapshot), EvaluationTarget::Runtime);
    let permanent = TrafficEvaluationIndex::new(snapshot, EvaluationTarget::Permanent);

    assert!(!runtime.section_is_complete(SnapshotSection::Services));
    assert!(permanent.section_is_complete(SnapshotSection::Services));
    assert_eq!(runtime.direct_rules().len(), 1);
    assert!(runtime.has_direct_rules());
}
