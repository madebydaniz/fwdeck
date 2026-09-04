#![allow(clippy::too_many_lines, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::Arc;

use fwdeck::domain::{
    AddressFamily, ConfigurationTarget, DegradedSection, EvaluationContext, EvaluationPhase,
    EvaluationSnapshotIdentity, EvaluationTarget, FirewallDecision, FirewallSnapshot,
    FirewallStatus, IcmpType, InterfaceName, IpProtocol, LogDenied, NetfilterBackend,
    PolicyDetails, PolicyName, PolicyTarget, PortSelector, RichRule, RulePriority, Scoped,
    ServiceDefinition, ServiceDestination, ServiceName, SnapshotSection, SourceAddress,
    TrafficConnectionState, TrafficDestination, TrafficDirection, TrafficExpectation,
    TrafficScenario, TrafficScenarioId, TrafficSeverity, TrafficSuiteId, TrafficSuiteRevision,
    TrafficTestRunId, TrafficTestStatus, TrafficTraceOutcome, TrafficTraceStage, TrafficTransport,
    UnknownReason, ZoneDetails, ZoneName, ZoneTarget, evaluate_scenario,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    reviewed_on: String,
    reviewed_against: String,
    sources: Vec<String>,
    cases: Vec<Case>,
    policy_cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    setup: String,
    source: String,
    #[serde(default)]
    direction: Option<TrafficDirection>,
    #[serde(default)]
    ingress_interface: Option<String>,
    #[serde(default)]
    ingress_zone: Option<String>,
    destination: String,
    transport: String,
    #[serde(default)]
    destination_port: Option<String>,
    #[serde(default)]
    source_port: Option<String>,
    #[serde(default)]
    connection_state: Option<TrafficConnectionState>,
    expectation: TrafficExpectation,
    expected_decision: FirewallDecision,
    expected_status: TrafficTestStatus,
    expected_reason: Option<UnknownReason>,
    expected_zone: Option<String>,
}

fn zone(name: &str, priority: i32, target: ZoneTarget) -> ZoneDetails {
    let mut zone = ZoneDetails::empty(ZoneName::parse(name).unwrap());
    zone.ingress_priority = RulePriority::new(priority).unwrap();
    zone.target = target;
    zone
}

fn snapshot(setup: &str) -> FirewallSnapshot {
    let mut trusted = zone("trusted", -10, ZoneTarget::Accept);
    trusted.sources = vec![SourceAddress::parse("10.10.0.0/16").unwrap()];

    let mut management = zone("management", -10, ZoneTarget::Default);
    management.sources = vec![SourceAddress::parse("10.10.20.0/24").unwrap()];
    management.services = vec![ServiceName::parse("ssh").unwrap()];

    let mut ambiguous_a = zone("ambiguous-a", 20, ZoneTarget::Accept);
    ambiguous_a.sources = vec![SourceAddress::parse("172.16.0.0/16").unwrap()];
    let mut ambiguous_b = zone("ambiguous-b", 20, ZoneTarget::Drop);
    ambiguous_b.sources = vec![SourceAddress::parse("172.16.0.0/16").unwrap()];

    let mut public = zone("public", 0, ZoneTarget::Default);
    public.interfaces = vec![InterfaceName::parse("eth0").unwrap()];
    public.ports = vec!["8080/tcp".parse().unwrap(), "5353/udp".parse().unwrap()];
    public.source_ports = vec!["40000-40100/udp".parse().unwrap()];
    public.protocols = vec![IpProtocol::parse("gre").unwrap()];
    public.services = vec![ServiceName::parse("destination-web").unwrap()];
    public.icmp_blocks = vec![IcmpType::parse("echo-request").unwrap()];

    let mut inverted = zone("icmp-inverted", 0, ZoneTarget::Default);
    inverted.icmp_blocks = vec![IcmpType::parse("echo-request").unwrap()];
    inverted.icmp_block_inversion = true;

    let drop_zone = zone("drop-zone", 0, ZoneTarget::Drop);

    let mut degraded = Vec::new();
    let mut direct_rules = Vec::new();
    let panic_mode = setup == "panic";
    if setup == "incomplete_zones" {
        degraded.push(DegradedSection::new(
            SnapshotSection::Zones,
            Some(ConfigurationTarget::Runtime),
            "fixture intentionally omits runtime zone evidence",
        ));
    }
    if setup == "direct_rule" {
        direct_rules.push("ipv4 filter INPUT 0 -j ACCEPT".to_owned());
    }

    let mut snapshot = FirewallSnapshot {
        status: FirewallStatus {
            daemon_running: true,
            version: Some("2.4.0".to_owned()),
            backend: NetfilterBackend::Nftables,
            log_denied: LogDenied::Off,
            panic_mode,
        },
        default_zone: ZoneName::parse("public").unwrap(),
        active: BTreeMap::new(),
        runtime: [
            trusted,
            management,
            ambiguous_a,
            ambiguous_b,
            public,
            inverted,
            drop_zone,
        ]
        .into_iter()
        .map(|zone| (zone.name.clone(), zone))
        .collect(),
        permanent: BTreeMap::new(),
        ipsets: Scoped::default(),
        service_definitions: BTreeMap::from([
            (
                ServiceName::parse("ssh").unwrap(),
                ServiceDefinition {
                    ports: vec!["22/tcp".parse().unwrap()],
                    ..ServiceDefinition::default()
                },
            ),
            (
                ServiceName::parse("destination-web").unwrap(),
                ServiceDefinition {
                    ports: vec!["8443/tcp".parse().unwrap()],
                    destinations: vec![ServiceDestination {
                        family: AddressFamily::Ipv4,
                        address: SourceAddress::parse("192.0.2.10").unwrap(),
                    }],
                    ..ServiceDefinition::default()
                },
            ),
            (
                ServiceName::parse("admin-api").unwrap(),
                ServiceDefinition {
                    ports: vec!["9443/tcp".parse().unwrap()],
                    ..ServiceDefinition::default()
                },
            ),
        ]),
        available_services: vec![
            ServiceName::parse("admin-api").unwrap(),
            ServiceName::parse("destination-web").unwrap(),
            ServiceName::parse("ssh").unwrap(),
        ],
        policies: Scoped::default(),
        direct_rules,
        degraded,
    };
    configure_policy_case(&mut snapshot, setup);
    snapshot
}

fn policy(name: &str, priority: i32, target: PolicyTarget) -> PolicyDetails {
    let mut policy = PolicyDetails::empty(PolicyName::parse(name).unwrap());
    policy.active = true;
    policy.priority = priority;
    policy.target = target;
    policy.ingress_zones = vec!["public".to_owned()];
    policy.egress_zones = vec!["HOST".to_owned()];
    policy
}

fn add_runtime_policy(snapshot: &mut FirewallSnapshot, policy: PolicyDetails) {
    snapshot
        .policies
        .runtime
        .insert(policy.name.clone(), policy);
}

fn configure_policy_case(snapshot: &mut FirewallSnapshot, setup: &str) {
    let mut configured = match setup {
        "policy_port" => {
            let mut policy = policy("allow-port", -100, PolicyTarget::Continue);
            policy.ports = vec!["2222/tcp".parse().unwrap()];
            vec![policy]
        }
        "policy_service" => {
            let mut policy = policy("allow-ssh", -100, PolicyTarget::Continue);
            policy.services = vec![ServiceName::parse("ssh").unwrap()];
            vec![policy]
        }
        "policy_protocol" => {
            let mut policy = policy("allow-gre", -100, PolicyTarget::Continue);
            policy.protocols = vec![IpProtocol::parse("gre").unwrap()];
            vec![policy]
        }
        "policy_source_port" => {
            let mut policy = policy("allow-source", -100, PolicyTarget::Continue);
            policy.source_ports = vec!["45000/udp".parse().unwrap()];
            vec![policy]
        }
        "policy_icmp_block" => {
            let mut policy = policy("block-ping", -100, PolicyTarget::Continue);
            policy.icmp_blocks = vec![IcmpType::parse("destination-unreachable").unwrap()];
            vec![policy]
        }
        "policy_accept_target" => vec![policy("accept-all", -100, PolicyTarget::Accept)],
        "policy_reject_target" => vec![policy("reject-all", -100, PolicyTarget::Reject)],
        "policy_drop_target" => vec![policy("drop-all", -100, PolicyTarget::Drop)],
        "policy_continue" => vec![policy("continue", -100, PolicyTarget::Continue)],
        "policy_disabled" => {
            let mut policy = policy("disabled", -100, PolicyTarget::Accept);
            policy.disabled = true;
            vec![policy]
        }
        "policy_inactive" => {
            let mut policy = policy("inactive", -100, PolicyTarget::Accept);
            policy.active = false;
            vec![policy]
        }
        "policy_any_ingress" => {
            let mut policy = policy("any-ingress", -100, PolicyTarget::Accept);
            policy.ingress_zones = vec!["ANY".to_owned()];
            vec![policy]
        }
        "policy_any_egress" => {
            let mut policy = policy("any-egress", -100, PolicyTarget::Accept);
            policy.egress_zones = vec!["ANY".to_owned()];
            vec![policy]
        }
        "policy_positive" => {
            let mut policy = policy("late-allow", 100, PolicyTarget::Continue);
            policy.ports = vec!["65000/tcp".parse().unwrap()];
            vec![policy]
        }
        "policy_negative_preempts_zone" => vec![policy("early-drop", -100, PolicyTarget::Drop)],
        "policy_zero_priority" => vec![policy("reserved", 0, PolicyTarget::Accept)],
        "policy_masquerade" => {
            let mut policy = policy("masquerade", -100, PolicyTarget::Continue);
            policy.masquerade = true;
            vec![policy]
        }
        "policy_forward_port" => {
            let mut policy = policy("forward-port", -100, PolicyTarget::Continue);
            policy.forward_ports = vec!["port=65000:proto=tcp:toport=22".parse().unwrap()];
            vec![policy]
        }
        "policy_equal_conflict" => vec![
            policy("allow-same-priority", -100, PolicyTarget::Accept),
            policy("drop-same-priority", -100, PolicyTarget::Drop),
        ],
        "policy_rich_allow" => {
            let mut policy = policy("rich-allow", -100, PolicyTarget::Continue);
            policy.rich_rules = vec![RichRule::parse(
                r#"rule family="ipv4" source address="203.0.113.0/24" port port="65000" protocol="tcp" accept"#,
            )
            .unwrap()];
            vec![policy]
        }
        "policy_rich_service" => {
            let mut policy = policy("rich-service", -100, PolicyTarget::Continue);
            policy.rich_rules = vec![RichRule::parse(
                r#"rule family="ipv4" source address="203.0.113.0/24" service name="admin-api" accept"#,
            )
            .unwrap()];
            vec![policy]
        }
        "policy_rich_unsupported" => {
            let mut policy = policy("rich-unsupported", -100, PolicyTarget::Continue);
            policy.rich_rules =
                vec![RichRule::parse(r#"rule family="ipv4" source ipset="blocked" drop"#).unwrap()];
            vec![policy]
        }
        "zone_rich_negative" => {
            snapshot
                .runtime
                .get_mut(&ZoneName::parse("public").unwrap())
                .unwrap()
                .rich_rules = vec![
                RichRule::parse(r#"rule priority="-10" port port="8080" protocol="tcp" drop"#)
                    .unwrap(),
            ];
            Vec::new()
        }
        "zone_rich_positive" => {
            snapshot
                .runtime
                .get_mut(&ZoneName::parse("public").unwrap())
                .unwrap()
                .rich_rules = vec![
                RichRule::parse(r#"rule priority="10" port port="65000" protocol="tcp" accept"#)
                    .unwrap(),
            ];
            Vec::new()
        }
        "zone_rich_zero_deny_before_allow" => {
            snapshot
                .runtime
                .get_mut(&ZoneName::parse("public").unwrap())
                .unwrap()
                .rich_rules = vec![
                RichRule::parse(r#"rule port port="65000" protocol="tcp" accept"#).unwrap(),
                RichRule::parse(r#"rule port port="65000" protocol="tcp" drop"#).unwrap(),
            ];
            Vec::new()
        }
        "zone_rich_reject" => {
            snapshot
                .runtime
                .get_mut(&ZoneName::parse("public").unwrap())
                .unwrap()
                .rich_rules =
                vec![RichRule::parse(r#"rule port port="65000" protocol="tcp" reject"#).unwrap()];
            Vec::new()
        }
        "zone_rich_source_destination_source_port" => {
            snapshot
                .runtime
                .get_mut(&ZoneName::parse("public").unwrap())
                .unwrap()
                .rich_rules = vec![RichRule::parse(
                r#"rule family="ipv4" source address="203.0.113.0/24" destination address="192.0.2.10" source-port port="45000" protocol="udp" accept"#,
            )
            .unwrap()];
            Vec::new()
        }
        "zone_rich_equal_conflict" => {
            snapshot
                .runtime
                .get_mut(&ZoneName::parse("public").unwrap())
                .unwrap()
                .rich_rules = vec![
                RichRule::parse(r#"rule priority="5" port port="65000" protocol="tcp" accept"#)
                    .unwrap(),
                RichRule::parse(r#"rule priority="5" port port="65000" protocol="tcp" drop"#)
                    .unwrap(),
            ];
            Vec::new()
        }
        "zone_rich_unsupported" => {
            snapshot
                .runtime
                .get_mut(&ZoneName::parse("public").unwrap())
                .unwrap()
                .rich_rules =
                vec![RichRule::parse(r#"rule family="ipv4" source ipset="blocked" drop"#).unwrap()];
            Vec::new()
        }
        _ => Vec::new(),
    };

    if setup == "incomplete_policies" {
        snapshot.degraded.push(DegradedSection::new(
            SnapshotSection::Policies,
            Some(ConfigurationTarget::Runtime),
            "fixture intentionally omits runtime policy evidence",
        ));
    }
    if setup == "incomplete_policy_service" {
        let mut policy = policy("incomplete-service", -100, PolicyTarget::Continue);
        policy.services = vec![ServiceName::parse("ssh").unwrap()];
        configured.push(policy);
        snapshot.degraded.push(DegradedSection::new(
            SnapshotSection::ServiceDefinitions,
            Some(ConfigurationTarget::Runtime),
            "fixture intentionally omits service definition evidence",
        ));
    }
    for policy in configured.drain(..) {
        add_runtime_policy(snapshot, policy);
    }
}

fn scenario(case: &Case) -> TrafficScenario {
    let destination = if case.destination == "local" {
        TrafficDestination::LocalHost
    } else {
        TrafficDestination::Address(SourceAddress::parse(&case.destination).unwrap())
    };
    let transport = if case.transport == "tcp" {
        TrafficTransport::Tcp
    } else if case.transport == "udp" {
        TrafficTransport::Udp
    } else if let Some(raw) = case.transport.strip_prefix("raw:") {
        TrafficTransport::RawProtocol {
            protocol: IpProtocol::parse(raw).unwrap(),
        }
    } else if let Some(raw) = case.transport.strip_prefix("icmp:") {
        TrafficTransport::Icmp {
            icmp_type: IcmpType::parse(raw).unwrap(),
        }
    } else {
        assert_eq!(case.transport, "tcp", "fixture transport must be reviewed");
        TrafficTransport::Tcp
    };

    TrafficScenario {
        id: TrafficScenarioId::parse(&case.id).unwrap(),
        name: case.id.clone(),
        enabled: true,
        direction: case.direction.unwrap_or(TrafficDirection::ToHost),
        source: SourceAddress::parse(&case.source).unwrap(),
        ingress_interface: case
            .ingress_interface
            .as_deref()
            .map(InterfaceName::parse)
            .transpose()
            .unwrap(),
        ingress_zone: case
            .ingress_zone
            .as_deref()
            .map(ZoneName::parse)
            .transpose()
            .unwrap(),
        destination,
        egress_interface: None,
        egress_zone: None,
        transport,
        destination_port: case
            .destination_port
            .as_deref()
            .map(str::parse::<PortSelector>)
            .transpose()
            .unwrap(),
        source_port: case
            .source_port
            .as_deref()
            .map(str::parse::<PortSelector>)
            .transpose()
            .unwrap(),
        connection_state: case.connection_state.unwrap_or_default(),
        expectation: case.expectation,
        severity: TrafficSeverity::Critical,
        required_safety_gate: true,
        note: None,
    }
}

fn context() -> EvaluationContext {
    EvaluationContext {
        run_id: TrafficTestRunId::new(1).unwrap(),
        suite_id: TrafficSuiteId::parse("host-ingress-fixture").unwrap(),
        suite_revision: TrafficSuiteRevision::new(1).unwrap(),
        phase: EvaluationPhase::Current,
        target: EvaluationTarget::Runtime,
        authoritative_snapshot: EvaluationSnapshotIdentity::new(7, 1).unwrap(),
        base_snapshot: None,
        mutation_intent_id: None,
        plan_id: None,
        candidate_identity: None,
    }
}

fn basic_scenario(id: &str) -> TrafficScenario {
    TrafficScenario {
        id: TrafficScenarioId::parse(id).unwrap(),
        name: id.to_owned(),
        enabled: true,
        direction: TrafficDirection::ToHost,
        source: SourceAddress::parse("192.0.2.10").unwrap(),
        ingress_interface: None,
        ingress_zone: Some(ZoneName::parse("public").unwrap()),
        destination: TrafficDestination::LocalHost,
        egress_interface: None,
        egress_zone: None,
        transport: TrafficTransport::Tcp,
        destination_port: Some("65000".parse().unwrap()),
        source_port: None,
        connection_state: TrafficConnectionState::New,
        expectation: TrafficExpectation::Block,
        severity: TrafficSeverity::Critical,
        required_safety_gate: true,
        note: None,
    }
}

fn evaluate_with(
    snapshot: FirewallSnapshot,
    scenario: &TrafficScenario,
) -> fwdeck::domain::TrafficTestResult {
    let index =
        fwdeck::domain::TrafficEvaluationIndex::new(Arc::new(snapshot), EvaluationTarget::Runtime);
    evaluate_scenario(&index, scenario, &context()).unwrap()
}

#[test]
fn incomplete_path_and_capability_boundaries_are_typed() {
    let mut missing_zone_scenario = basic_scenario("missing-explicit-zone");
    missing_zone_scenario.ingress_zone = Some(ZoneName::parse("absent").unwrap());
    assert_eq!(
        evaluate_with(snapshot("default"), &missing_zone_scenario).unknown_reason(),
        Some(UnknownReason::IncompleteSnapshot)
    );

    let mut incomplete_direct = snapshot("default");
    incomplete_direct.degraded.push(DegradedSection::new(
        SnapshotSection::DirectRules,
        Some(ConfigurationTarget::Runtime),
        "missing direct evidence",
    ));
    assert_eq!(
        evaluate_with(incomplete_direct, &basic_scenario("incomplete-direct")).unknown_reason(),
        Some(UnknownReason::IncompleteSnapshot)
    );

    let mut missing_default = snapshot("default");
    missing_default.default_zone = ZoneName::parse("absent").unwrap();
    let mut implicit = basic_scenario("missing-default");
    implicit.ingress_zone = None;
    assert_eq!(
        evaluate_with(missing_default, &implicit).unknown_reason(),
        Some(UnknownReason::IncompleteSnapshot)
    );

    let mut ipset_binding = snapshot("default");
    ipset_binding
        .runtime
        .get_mut(&ZoneName::parse("public").unwrap())
        .unwrap()
        .sources
        .push(SourceAddress::parse("ipset:blocked").unwrap());
    assert_eq!(
        evaluate_with(ipset_binding, &implicit).unknown_reason(),
        Some(UnknownReason::CapabilityUnavailable)
    );

    for (version, expected) in [
        (Some("1.0.0"), UnknownReason::VersionUnsupported),
        (None, UnknownReason::CapabilityUnavailable),
    ] {
        let mut observed = snapshot("default");
        observed.status.version = version.map(str::to_owned);
        observed
            .runtime
            .get_mut(&ZoneName::parse("trusted").unwrap())
            .unwrap()
            .ingress_priority = RulePriority::new(-20).unwrap();
        let mut overlapping = basic_scenario("priority-capability");
        overlapping.source = SourceAddress::parse("10.10.20.10").unwrap();
        overlapping.ingress_zone = None;
        assert_eq!(
            evaluate_with(observed, &overlapping).unknown_reason(),
            Some(expected)
        );
    }
}

#[test]
fn rich_rule_and_service_non_match_boundaries_remain_conservative() {
    let rich_snapshot = snapshot("zone_rich_source_destination_source_port");

    let mut wrong_family = basic_scenario("rich-wrong-family");
    wrong_family.source = SourceAddress::parse("2001:db8::10").unwrap();
    wrong_family.destination =
        TrafficDestination::Address(SourceAddress::parse("2001:db8::20").unwrap());
    wrong_family.transport = TrafficTransport::Udp;
    wrong_family.source_port = Some("45000".parse().unwrap());
    assert_eq!(
        evaluate_with(rich_snapshot.clone(), &wrong_family).decision(),
        FirewallDecision::Block
    );

    let mut missing_destination = basic_scenario("rich-missing-destination");
    missing_destination.source = SourceAddress::parse("203.0.113.10").unwrap();
    missing_destination.transport = TrafficTransport::Udp;
    missing_destination.source_port = Some("45000".parse().unwrap());
    assert_eq!(
        evaluate_with(rich_snapshot.clone(), &missing_destination).unknown_reason(),
        Some(UnknownReason::CapabilityUnavailable)
    );

    let mut inverted_source_miss = missing_destination.clone();
    inverted_source_miss.id = TrafficScenarioId::parse("rich-source-miss").unwrap();
    inverted_source_miss.source = SourceAddress::parse("198.51.100.10").unwrap();
    inverted_source_miss.destination =
        TrafficDestination::Address(SourceAddress::parse("192.0.2.10").unwrap());
    assert_eq!(
        evaluate_with(rich_snapshot.clone(), &inverted_source_miss).decision(),
        FirewallDecision::Block
    );

    let mut destination_miss = missing_destination.clone();
    destination_miss.id = TrafficScenarioId::parse("rich-destination-miss").unwrap();
    destination_miss.destination =
        TrafficDestination::Address(SourceAddress::parse("198.51.100.10").unwrap());
    assert_eq!(
        evaluate_with(rich_snapshot, &destination_miss).decision(),
        FirewallDecision::Block
    );

    let mut service_snapshot = snapshot("default");
    service_snapshot
        .service_definitions
        .get_mut(&ServiceName::parse("destination-web").unwrap())
        .unwrap()
        .modules
        .push(fwdeck::domain::ServiceModuleName::parse("nf_conntrack_ftp").unwrap());
    let mut service_scenario = basic_scenario("service-module");
    service_scenario.destination_port = Some("8443".parse().unwrap());
    assert_eq!(
        evaluate_with(service_snapshot, &service_scenario).unknown_reason(),
        Some(UnknownReason::UnsupportedServiceFeature)
    );
}

#[test]
fn service_and_rich_service_completeness_is_never_assumed() {
    let service = ServiceName::parse("destination-web").unwrap();
    let mut scenario = basic_scenario("missing-service-definition");
    scenario.destination_port = Some("8443".parse().unwrap());

    let mut missing = snapshot("default");
    missing.service_definitions.remove(&service);
    assert_eq!(
        evaluate_with(missing, &scenario).unknown_reason(),
        Some(UnknownReason::IncompleteServiceDefinition)
    );

    let mut incomplete = snapshot("default");
    incomplete.degraded.push(DegradedSection::new(
        SnapshotSection::Services,
        Some(ConfigurationTarget::Runtime),
        "service catalog incomplete",
    ));
    assert_eq!(
        evaluate_with(incomplete, &scenario).unknown_reason(),
        Some(UnknownReason::IncompleteSnapshot)
    );

    let mut rich_service = snapshot("default");
    rich_service
        .runtime
        .get_mut(&ZoneName::parse("public").unwrap())
        .unwrap()
        .rich_rules = vec![RichRule::parse(r#"rule service name="missing" accept"#).unwrap()];
    assert_eq!(
        evaluate_with(rich_service, &scenario).unknown_reason(),
        Some(UnknownReason::IncompleteServiceDefinition)
    );
}

#[test]
fn rich_protocol_matching_covers_transport_families() {
    let mut observed = snapshot("default");
    observed
        .runtime
        .get_mut(&ZoneName::parse("public").unwrap())
        .unwrap()
        .rich_rules = vec![RichRule::parse(r#"rule protocol value="gre" accept"#).unwrap()];

    let mut raw = basic_scenario("rich-raw-protocol");
    raw.transport = TrafficTransport::RawProtocol {
        protocol: IpProtocol::parse("gre").unwrap(),
    };
    raw.destination_port = None;
    raw.expectation = TrafficExpectation::Allow;
    assert_eq!(
        evaluate_with(observed.clone(), &raw).decision(),
        FirewallDecision::Allow
    );

    let tcp = basic_scenario("rich-protocol-miss");
    assert_eq!(
        evaluate_with(observed, &tcp).decision(),
        FirewallDecision::Block
    );
}

#[test]
fn policy_and_rich_priority_capabilities_fail_closed_by_version() {
    for (setup, version, expected) in [
        (
            "policy_accept_target",
            Some("0.1.0"),
            UnknownReason::VersionUnsupported,
        ),
        (
            "policy_accept_target",
            None,
            UnknownReason::CapabilityUnavailable,
        ),
        (
            "zone_rich_positive",
            Some("0.1.0"),
            UnknownReason::VersionUnsupported,
        ),
        (
            "zone_rich_positive",
            None,
            UnknownReason::CapabilityUnavailable,
        ),
    ] {
        let mut observed = snapshot(setup);
        observed.status.version = version.map(str::to_owned);
        assert_eq!(
            evaluate_with(observed, &basic_scenario("version-gated-priority")).unknown_reason(),
            Some(expected),
            "setup={setup} version={version:?}"
        );
    }
}

#[test]
fn invalid_scenario_error_is_typed_and_displayable() {
    let mut invalid = basic_scenario("invalid-scenario");
    invalid.name.clear();
    let index = fwdeck::domain::TrafficEvaluationIndex::new(
        Arc::new(snapshot("default")),
        EvaluationTarget::Runtime,
    );
    let error = evaluate_scenario(&index, &invalid, &context()).unwrap_err();
    assert!(error.to_string().starts_with("invalid traffic scenario:"));
    let report_error = fwdeck::domain::TrafficEvaluationError::Report(
        fwdeck::domain::TrafficReportError::ZeroRunId,
    );
    assert!(
        report_error
            .to_string()
            .starts_with("invalid traffic evaluation contract:")
    );
}

#[test]
fn host_ingress_reviewed_cases_are_deterministic_and_fail_closed() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "fixtures/traffic_testing/evaluation/host-ingress-v1.json"
    ))
    .unwrap();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.reviewed_on, "2026-09-04");
    assert_eq!(
        fixture.reviewed_against,
        "FWDeck host-ingress Phase 1 contract"
    );
    assert_eq!(fixture.sources.len(), 4);
    assert!(
        fixture
            .sources
            .iter()
            .all(|source| source.starts_with("https://firewalld.org/"))
    );

    for case in fixture.cases {
        let scenario = scenario(&case);
        scenario.validate().unwrap();
        let index = fwdeck::domain::TrafficEvaluationIndex::new(
            Arc::new(snapshot(&case.setup)),
            EvaluationTarget::Runtime,
        );
        let first = evaluate_scenario(&index, &scenario, &context()).unwrap();
        let second = evaluate_scenario(&index, &scenario, &context()).unwrap();

        assert_eq!(first, second, "{} must be deterministic", case.id);
        assert_eq!(first.decision(), case.expected_decision, "{}", case.id);
        assert_eq!(first.status(), case.expected_status, "{}", case.id);
        assert_eq!(first.unknown_reason(), case.expected_reason, "{}", case.id);

        let stages: Vec<TrafficTraceStage> = first
            .trace()
            .iter()
            .map(fwdeck::domain::TrafficTraceStep::stage)
            .collect();
        assert_eq!(
            stages.first(),
            Some(&TrafficTraceStage::ScenarioNormalization),
            "{}",
            case.id
        );
        assert_eq!(
            stages.get(1),
            Some(&TrafficTraceStage::IdentityCheck),
            "{}",
            case.id
        );
        assert_eq!(
            stages.iter().rev().nth(2),
            Some(&TrafficTraceStage::Decision),
            "{}",
            case.id
        );
        assert_eq!(
            stages.iter().rev().nth(1),
            Some(&TrafficTraceStage::ExpectationComparison),
            "{}",
            case.id
        );
        assert_eq!(
            stages.last(),
            Some(&TrafficTraceStage::Status),
            "{}",
            case.id
        );

        let selected_zone = first.trace().iter().find_map(|step| {
            if step.stage() == TrafficTraceStage::IngressResolution
                && step.outcome() == TrafficTraceOutcome::Selected
                && let Some(fwdeck::domain::TraceObjectRef::Zone(zone)) = step.object()
            {
                return Some(zone.as_str());
            }
            None
        });
        assert_eq!(selected_zone, case.expected_zone.as_deref(), "{}", case.id);
    }
}

#[test]
fn host_ingress_context_target_mismatch_is_unknown_not_a_false_decision() {
    let index = fwdeck::domain::TrafficEvaluationIndex::new(
        Arc::new(snapshot("standard")),
        EvaluationTarget::Runtime,
    );
    let case: Case = serde_json::from_str(
        r#"{"id":"target-mismatch","setup":"standard","source":"203.0.113.10","destination":"local","transport":"tcp","destination_port":"8080","expectation":"allow","expected_decision":"unknown","expected_status":"indeterminate","expected_reason":"stale_snapshot","expected_zone":null}"#,
    )
    .unwrap();
    let mut context = context();
    context.target = EvaluationTarget::Permanent;

    let result = evaluate_scenario(&index, &scenario(&case), &context).unwrap();

    assert_eq!(result.decision(), FirewallDecision::Unknown);
    assert_eq!(result.unknown_reason(), Some(UnknownReason::StaleSnapshot));
}

#[test]
fn ingress_to_host_policy_cases_are_ordered_and_fail_closed() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "fixtures/traffic_testing/evaluation/host-ingress-v1.json"
    ))
    .unwrap();
    assert_eq!(fixture.policy_cases.len(), 31);

    for case in fixture.policy_cases {
        let scenario = scenario(&case);
        scenario.validate().unwrap();
        let index = fwdeck::domain::TrafficEvaluationIndex::new(
            Arc::new(snapshot(&case.setup)),
            EvaluationTarget::Runtime,
        );
        let first = evaluate_scenario(&index, &scenario, &context()).unwrap();
        let second = evaluate_scenario(&index, &scenario, &context()).unwrap();

        assert_eq!(first, second, "{} must be deterministic", case.id);
        assert_eq!(first.decision(), case.expected_decision, "{}", case.id);
        assert_eq!(first.status(), case.expected_status, "{}", case.id);
        assert_eq!(first.unknown_reason(), case.expected_reason, "{}", case.id);
        if case.id == "policy-rich-allow" {
            assert!(first.trace().iter().any(|step| {
                matches!(
                    step.object(),
                    Some(fwdeck::domain::TraceObjectRef::PolicyRichRule { index: 0, .. })
                ) && step.outcome() == TrafficTraceOutcome::Decision(FirewallDecision::Allow)
            }));
        }
        if case.id == "policy-rich-unsupported" {
            assert!(first.trace().iter().any(|step| {
                matches!(
                    step.object(),
                    Some(fwdeck::domain::TraceObjectRef::PolicyRichRule { index: 0, .. })
                ) && step.outcome()
                    == TrafficTraceOutcome::Unknown(UnknownReason::UnsupportedRichRule)
            }));
        }
    }
}

#[test]
fn permanent_policy_evaluation_ignores_the_runtime_active_marker() {
    let mut snapshot = snapshot("policy_inactive");
    snapshot.permanent = snapshot.runtime.clone();
    snapshot.policies.permanent = snapshot.policies.runtime.clone();
    let index = fwdeck::domain::TrafficEvaluationIndex::new(
        Arc::new(snapshot),
        EvaluationTarget::Permanent,
    );
    let case: Case = serde_json::from_str(
        r#"{"id":"permanent-inactive-marker","setup":"policy_inactive","source":"203.0.113.10","destination":"local","transport":"tcp","destination_port":"65000","expectation":"allow","expected_decision":"allow","expected_status":"pass","expected_reason":null,"expected_zone":"public"}"#,
    )
    .unwrap();
    let mut evaluation_context = context();
    evaluation_context.target = EvaluationTarget::Permanent;

    let result = evaluate_scenario(&index, &scenario(&case), &evaluation_context).unwrap();

    assert_eq!(result.decision(), FirewallDecision::Allow);
    assert_eq!(result.status(), TrafficTestStatus::Pass);
}

#[test]
fn partial_rich_selectors_and_source_zone_bindings_are_unknown() {
    let mut observed = snapshot("default");
    observed.runtime.get_mut(&public_zone()).unwrap().target = ZoneTarget::Accept;
    observed.runtime.get_mut(&public_zone()).unwrap().rich_rules =
        vec![RichRule::parse(r#"rule family="ipv4" source address="192.0.2.0/25" drop"#).unwrap()];
    let mut partial_source = basic_scenario("partial-rich-source");
    partial_source.source = SourceAddress::parse("192.0.2.0/24").unwrap();
    assert_eq!(
        evaluate_with(observed.clone(), &partial_source).unknown_reason(),
        Some(UnknownReason::CapabilityUnavailable)
    );

    observed.runtime.get_mut(&public_zone()).unwrap().rich_rules = vec![
        RichRule::parse(r#"rule family="ipv4" source invert="true" address="192.0.2.0/25" drop"#)
            .unwrap(),
    ];
    partial_source.id = TrafficScenarioId::parse("partial-inverted-rich-source").unwrap();
    assert_eq!(
        evaluate_with(observed, &partial_source).unknown_reason(),
        Some(UnknownReason::CapabilityUnavailable)
    );

    let mut observed = snapshot("default");
    observed.runtime.get_mut(&public_zone()).unwrap().target = ZoneTarget::Accept;
    observed.runtime.get_mut(&public_zone()).unwrap().rich_rules = vec![
        RichRule::parse(r#"rule family="ipv4" destination address="198.51.100.0/25" drop"#)
            .unwrap(),
    ];
    let mut partial_destination = basic_scenario("partial-rich-destination");
    partial_destination.destination =
        TrafficDestination::Address(SourceAddress::parse("198.51.100.0/24").unwrap());
    assert_eq!(
        evaluate_with(observed, &partial_destination).unknown_reason(),
        Some(UnknownReason::CapabilityUnavailable)
    );

    let mut binding_snapshot = snapshot("default");
    binding_snapshot
        .runtime
        .get_mut(&public_zone())
        .unwrap()
        .target = ZoneTarget::Accept;
    let mut subset = zone("source-subset", -20, ZoneTarget::Drop);
    subset.sources = vec![SourceAddress::parse("192.0.2.0/25").unwrap()];
    binding_snapshot.runtime.insert(subset.name.clone(), subset);
    let mut partial_binding = basic_scenario("partial-source-zone-binding");
    partial_binding.ingress_zone = None;
    partial_binding.source = SourceAddress::parse("192.0.2.0/24").unwrap();
    assert_eq!(
        evaluate_with(binding_snapshot, &partial_binding).unknown_reason(),
        Some(UnknownReason::CapabilityUnavailable)
    );
}

#[test]
fn partial_and_missing_port_evidence_is_unknown() {
    let mut observed = snapshot("default");
    let public = observed.runtime.get_mut(&public_zone()).unwrap();
    public.target = ZoneTarget::Accept;
    public.rich_rules =
        vec![RichRule::parse(r#"rule port port="22" protocol="tcp" drop"#).unwrap()];
    let mut partial = basic_scenario("partial-rich-port");
    partial.destination_port = Some("22-23".parse().unwrap());
    assert_eq!(
        evaluate_with(observed.clone(), &partial).unknown_reason(),
        Some(UnknownReason::CapabilityUnavailable)
    );

    let public = observed.runtime.get_mut(&public_zone()).unwrap();
    public.rich_rules.clear();
    public.ports = vec!["22/tcp".parse().unwrap()];
    partial.id = TrafficScenarioId::parse("partial-zone-port").unwrap();
    assert_eq!(
        evaluate_with(observed.clone(), &partial).unknown_reason(),
        Some(UnknownReason::CapabilityUnavailable)
    );

    let public = observed.runtime.get_mut(&public_zone()).unwrap();
    public.ports.clear();
    public.source_ports = vec!["45000/tcp".parse().unwrap()];
    let missing_source_port = basic_scenario("missing-zone-source-port");
    assert_eq!(
        evaluate_with(observed.clone(), &missing_source_port).unknown_reason(),
        Some(UnknownReason::CapabilityUnavailable)
    );

    let public = observed.runtime.get_mut(&public_zone()).unwrap();
    public.source_ports.clear();
    public.rich_rules = vec![RichRule::parse(
        r#"rule family="ipv4" source address="192.0.2.0/24" source-port port="45000" protocol="tcp" drop"#,
    )
    .unwrap()];
    let missing_rich_source_port = basic_scenario("missing-rich-source-port");
    assert_eq!(
        evaluate_with(observed, &missing_rich_source_port).unknown_reason(),
        Some(UnknownReason::CapabilityUnavailable)
    );
}

#[test]
fn included_service_definitions_keep_ports_bound_to_their_destinations() {
    let root = ServiceName::parse("root-service").unwrap();
    let included = ServiceName::parse("included-service").unwrap();
    let mut observed = snapshot("default");
    observed.runtime.get_mut(&public_zone()).unwrap().services = vec![root.clone()];
    observed.service_definitions.insert(
        root.clone(),
        ServiceDefinition {
            ports: vec!["80/tcp".parse().unwrap()],
            destinations: vec![ServiceDestination {
                family: AddressFamily::Ipv4,
                address: SourceAddress::parse("192.0.2.10").unwrap(),
            }],
            includes: vec![included.clone()],
            ..ServiceDefinition::default()
        },
    );
    observed.service_definitions.insert(
        included,
        ServiceDefinition {
            ports: vec!["443/tcp".parse().unwrap()],
            destinations: vec![ServiceDestination {
                family: AddressFamily::Ipv4,
                address: SourceAddress::parse("192.0.2.20").unwrap(),
            }],
            ..ServiceDefinition::default()
        },
    );
    let mut scenario = basic_scenario("included-service-destination-association");
    scenario.destination_port = Some("80".parse().unwrap());
    scenario.destination = TrafficDestination::Address(SourceAddress::parse("192.0.2.20").unwrap());

    assert_eq!(
        evaluate_with(observed, &scenario).decision(),
        FirewallDecision::Block
    );
}

#[test]
fn service_destinations_do_not_disappear_when_the_scenario_family_differs() {
    let mut scenario = basic_scenario("service-destination-family-mismatch");
    scenario.source = SourceAddress::parse("2001:db8::10").unwrap();
    scenario.destination =
        TrafficDestination::Address(SourceAddress::parse("2001:db8::20").unwrap());
    scenario.destination_port = Some("8443".parse().unwrap());

    assert_eq!(
        evaluate_with(snapshot("default"), &scenario).decision(),
        FirewallDecision::Block
    );
}

#[test]
fn service_port_source_port_and_destination_uncertainty_is_preserved() {
    let service = ServiceName::parse("bounded-service").unwrap();
    let mut observed = snapshot("default");
    let public = observed.runtime.get_mut(&public_zone()).unwrap();
    public.target = ZoneTarget::Accept;
    public.ports.clear();
    public.source_ports.clear();
    public.protocols.clear();
    public.services = vec![service.clone()];
    observed.service_definitions.insert(
        service.clone(),
        ServiceDefinition {
            ports: vec!["22/tcp".parse().unwrap()],
            ..ServiceDefinition::default()
        },
    );
    let mut partial_port = basic_scenario("partial-service-port");
    partial_port.destination_port = Some("22-23".parse().unwrap());
    assert_eq!(
        evaluate_with(observed.clone(), &partial_port).unknown_reason(),
        Some(UnknownReason::CapabilityUnavailable)
    );

    observed.service_definitions.insert(
        service.clone(),
        ServiceDefinition {
            source_ports: vec!["45000/tcp".parse().unwrap()],
            ..ServiceDefinition::default()
        },
    );
    let missing_source_port = basic_scenario("missing-service-source-port");
    assert_eq!(
        evaluate_with(observed.clone(), &missing_source_port).unknown_reason(),
        Some(UnknownReason::CapabilityUnavailable)
    );

    observed.service_definitions.insert(
        service,
        ServiceDefinition {
            ports: vec!["65000/tcp".parse().unwrap()],
            destinations: vec![ServiceDestination {
                family: AddressFamily::Ipv4,
                address: SourceAddress::parse("198.51.100.0/25").unwrap(),
            }],
            ..ServiceDefinition::default()
        },
    );
    let mut partial_destination = basic_scenario("partial-service-destination");
    partial_destination.destination =
        TrafficDestination::Address(SourceAddress::parse("198.51.100.0/24").unwrap());
    assert_eq!(
        evaluate_with(observed, &partial_destination).unknown_reason(),
        Some(UnknownReason::CapabilityUnavailable)
    );
}

#[test]
fn relevant_zone_forward_ports_are_unknown_but_disjoint_ports_continue() {
    let mut observed = snapshot("default");
    let public = observed.runtime.get_mut(&public_zone()).unwrap();
    public.target = ZoneTarget::Drop;
    public.forward_ports = vec!["port=22:proto=tcp:toport=2222".parse().unwrap()];

    let mut relevant = basic_scenario("relevant-zone-forward-port");
    relevant.destination_port = Some("22".parse().unwrap());
    assert_eq!(
        evaluate_with(observed.clone(), &relevant).unknown_reason(),
        Some(UnknownReason::CapabilityUnavailable)
    );

    let mut disjoint = basic_scenario("disjoint-zone-forward-port");
    disjoint.destination_port = Some("23".parse().unwrap());
    assert_eq!(
        evaluate_with(observed, &disjoint).decision(),
        FirewallDecision::Block
    );
}

#[test]
fn mac_zone_bindings_require_verified_ingress_evidence() {
    let mut observed = snapshot("default");
    observed.runtime.get_mut(&public_zone()).unwrap().target = ZoneTarget::Accept;
    let mut mac_zone = zone("mac-drop", -20, ZoneTarget::Drop);
    mac_zone.sources = vec![SourceAddress::parse("aa:bb:cc:dd:ee:ff").unwrap()];
    observed.runtime.insert(mac_zone.name.clone(), mac_zone);
    let mut scenario = basic_scenario("mac-binding-without-evidence");
    scenario.ingress_zone = None;

    assert_eq!(
        evaluate_with(observed, &scenario).unknown_reason(),
        Some(UnknownReason::CapabilityUnavailable)
    );
}

#[test]
fn protocol_primitives_cover_transport_families_and_numeric_ids() {
    let mut zone_protocol = snapshot("default");
    let public = zone_protocol.runtime.get_mut(&public_zone()).unwrap();
    public.target = ZoneTarget::Drop;
    public.protocols = vec![IpProtocol::parse("tcp").unwrap()];
    let mut tcp = basic_scenario("zone-tcp-protocol");
    tcp.destination_port = Some("22".parse().unwrap());
    assert_eq!(
        evaluate_with(zone_protocol, &tcp).decision(),
        FirewallDecision::Allow
    );

    let mut policy_protocol = snapshot("default");
    let mut policy = policy("numeric-tcp", -100, PolicyTarget::Continue);
    policy.protocols = vec![IpProtocol::parse("6").unwrap()];
    add_runtime_policy(&mut policy_protocol, policy);
    assert_eq!(
        evaluate_with(policy_protocol, &tcp).decision(),
        FirewallDecision::Allow
    );

    let service = ServiceName::parse("udp-protocol-service").unwrap();
    let mut service_protocol = snapshot("default");
    service_protocol
        .runtime
        .get_mut(&public_zone())
        .unwrap()
        .services = vec![service.clone()];
    service_protocol
        .runtime
        .get_mut(&public_zone())
        .unwrap()
        .source_ports
        .clear();
    service_protocol.service_definitions.insert(
        service,
        ServiceDefinition {
            protocols: vec![IpProtocol::parse("17").unwrap()],
            ..ServiceDefinition::default()
        },
    );
    let mut udp = basic_scenario("service-udp-protocol");
    udp.transport = TrafficTransport::Udp;
    udp.destination_port = Some("53".parse().unwrap());
    assert_eq!(
        evaluate_with(service_protocol, &udp).decision(),
        FirewallDecision::Allow
    );

    let mut rich_protocol = snapshot("default");
    rich_protocol
        .runtime
        .get_mut(&public_zone())
        .unwrap()
        .rich_rules = vec![RichRule::parse(r#"rule protocol value="58" accept"#).unwrap()];
    rich_protocol
        .runtime
        .get_mut(&public_zone())
        .unwrap()
        .icmp_blocks
        .clear();
    let mut icmpv6 = basic_scenario("rich-numeric-icmpv6-protocol");
    icmpv6.source = SourceAddress::parse("2001:db8::10").unwrap();
    icmpv6.transport = TrafficTransport::Icmp {
        icmp_type: IcmpType::parse("echo-request").unwrap(),
    };
    icmpv6.destination_port = None;
    assert_eq!(
        evaluate_with(rich_protocol, &icmpv6).decision(),
        FirewallDecision::Allow
    );

    let mut unknown_alias = snapshot("default");
    unknown_alias
        .runtime
        .get_mut(&public_zone())
        .unwrap()
        .protocols = vec![IpProtocol::parse("site-protocol").unwrap()];
    assert_eq!(
        evaluate_with(unknown_alias, &tcp).unknown_reason(),
        Some(UnknownReason::CapabilityUnavailable)
    );
}

#[test]
fn raw_transport_aliases_needing_subtype_evidence_are_unknown() {
    let mut forward = snapshot("default");
    forward
        .runtime
        .get_mut(&public_zone())
        .unwrap()
        .forward_ports = vec!["port=22:proto=tcp:toport=2222".parse().unwrap()];
    let mut raw_tcp = basic_scenario("raw-tcp-forward-port");
    raw_tcp.transport = TrafficTransport::RawProtocol {
        protocol: IpProtocol::parse("6").unwrap(),
    };
    raw_tcp.destination_port = None;
    assert_eq!(
        evaluate_with(forward, &raw_tcp).unknown_reason(),
        Some(UnknownReason::CapabilityUnavailable)
    );

    let mut raw_icmp = basic_scenario("raw-icmp-without-type");
    raw_icmp.transport = TrafficTransport::RawProtocol {
        protocol: IpProtocol::parse("icmp").unwrap(),
    };
    raw_icmp.destination_port = None;
    assert_eq!(
        evaluate_with(snapshot("default"), &raw_icmp).unknown_reason(),
        Some(UnknownReason::CapabilityUnavailable)
    );

    let mut unresolved = basic_scenario("raw-unresolved-alias");
    unresolved.transport = TrafficTransport::RawProtocol {
        protocol: IpProtocol::parse("site-protocol").unwrap(),
    };
    unresolved.destination_port = None;
    assert_eq!(
        evaluate_with(snapshot("default"), &unresolved).unknown_reason(),
        Some(UnknownReason::CapabilityUnavailable)
    );

    let mut gre = basic_scenario("raw-gre-remains-supported");
    gre.transport = TrafficTransport::RawProtocol {
        protocol: IpProtocol::parse("gre").unwrap(),
    };
    gre.destination_port = None;
    assert_eq!(
        evaluate_with(snapshot("default"), &gre).decision(),
        FirewallDecision::Allow
    );
}

fn public_zone() -> ZoneName {
    ZoneName::parse("public").unwrap()
}
