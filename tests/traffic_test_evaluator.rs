#![allow(clippy::too_many_lines, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::Arc;

use fwdeck::domain::{
    AddressFamily, ConfigurationTarget, DegradedSection, EvaluationContext, EvaluationPhase,
    EvaluationSnapshotIdentity, EvaluationTarget, FirewallDecision, FirewallSnapshot,
    FirewallStatus, IcmpType, InterfaceName, IpProtocol, LogDenied, NetfilterBackend, PortSelector,
    RulePriority, Scoped, ServiceDefinition, ServiceDestination, ServiceName, SnapshotSection,
    SourceAddress, TrafficConnectionState, TrafficDestination, TrafficDirection,
    TrafficExpectation, TrafficScenario, TrafficScenarioId, TrafficSeverity, TrafficSuiteId,
    TrafficSuiteRevision, TrafficTestRunId, TrafficTestStatus, TrafficTraceOutcome,
    TrafficTraceStage, TrafficTransport, UnknownReason, ZoneDetails, ZoneName, ZoneTarget,
    evaluate_scenario,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    reviewed_on: String,
    reviewed_against: String,
    sources: Vec<String>,
    cases: Vec<Case>,
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

    FirewallSnapshot {
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
        ]),
        available_services: vec![
            ServiceName::parse("destination-web").unwrap(),
            ServiceName::parse("ssh").unwrap(),
        ],
        policies: Scoped::default(),
        direct_rules,
        degraded,
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
