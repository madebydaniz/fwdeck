#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fwdeck::domain::{
    CandidateProjector, ConfigurationTarget, EvaluationContext, EvaluationPhase,
    EvaluationSnapshotIdentity, EvaluationTarget, FirewallDecision, FirewallOperation,
    FirewallSnapshot, FirewallStatus, LogDenied, MAX_SCENARIOS_PER_SUITE, MAX_TRACE_STEPS,
    MAX_TRAFFIC_REPORT_BYTES, MutationIntentId, NetfilterBackend, PolicyDetails, PolicyName,
    PolicyTarget, PortSpec, RichRule, Scoped, ServiceDefinition, ServiceName, SourceAddress,
    TrafficConnectionState, TrafficDestination, TrafficDirection, TrafficEvaluationIndex,
    TrafficExpectation, TrafficScenario, TrafficScenarioId, TrafficSeverity, TrafficSuite,
    TrafficSuiteId, TrafficSuiteRevision, TrafficTestReport, TrafficTestRunId, TrafficTestStatus,
    TrafficTransport, ZoneDetails, ZoneName, ZoneTarget, evaluate_scenario,
};

fn public() -> ZoneName {
    ZoneName::parse("public").unwrap()
}

fn snapshot() -> FirewallSnapshot {
    let mut runtime = ZoneDetails::empty(public());
    runtime.target = ZoneTarget::Accept;
    let mut permanent = ZoneDetails::empty(public());
    permanent.target = ZoneTarget::Drop;
    FirewallSnapshot {
        status: FirewallStatus {
            daemon_running: true,
            version: Some("2.4.0".to_owned()),
            backend: NetfilterBackend::Nftables,
            log_denied: LogDenied::Off,
            panic_mode: false,
        },
        default_zone: public(),
        active: BTreeMap::new(),
        runtime: BTreeMap::from([(public(), runtime)]),
        permanent: BTreeMap::from([(public(), permanent)]),
        ipsets: Scoped::default(),
        service_definitions: BTreeMap::new(),
        available_services: Vec::new(),
        policies: Scoped::default(),
        direct_rules: Vec::new(),
        degraded: Vec::new(),
    }
}

fn context(run_id: u64, target: EvaluationTarget) -> EvaluationContext {
    EvaluationContext {
        run_id: TrafficTestRunId::new(run_id).unwrap(),
        suite_id: TrafficSuiteId::parse("phase-1-evidence").unwrap(),
        suite_revision: TrafficSuiteRevision::new(1).unwrap(),
        phase: EvaluationPhase::Current,
        target,
        authoritative_snapshot: EvaluationSnapshotIdentity::new(17, 3).unwrap(),
        base_snapshot: None,
        mutation_intent_id: None,
        plan_id: None,
        candidate_identity: None,
    }
}

fn candidate_context(
    run_id: u64,
    identity: fwdeck::domain::CandidateIdentity,
) -> EvaluationContext {
    let base = EvaluationSnapshotIdentity::new(17, 3).unwrap();
    EvaluationContext {
        run_id: TrafficTestRunId::new(run_id).unwrap(),
        suite_id: TrafficSuiteId::parse("phase-1-evidence").unwrap(),
        suite_revision: TrafficSuiteRevision::new(1).unwrap(),
        phase: EvaluationPhase::StagedCandidate,
        target: EvaluationTarget::Runtime,
        authoritative_snapshot: base,
        base_snapshot: Some(base),
        mutation_intent_id: Some(MutationIntentId::new(8).unwrap()),
        plan_id: None,
        candidate_identity: Some(identity),
    }
}

fn scenario(index: usize, expectation: TrafficExpectation) -> TrafficScenario {
    TrafficScenario {
        id: TrafficScenarioId::parse(&format!("reviewed-{index:04}")).unwrap(),
        name: format!("Reviewed scenario {index:04}"),
        enabled: true,
        direction: TrafficDirection::ToHost,
        source: SourceAddress::parse("192.0.2.10").unwrap(),
        ingress_interface: None,
        ingress_zone: Some(public()),
        destination: TrafficDestination::LocalHost,
        egress_interface: None,
        egress_zone: None,
        transport: TrafficTransport::Tcp,
        destination_port: Some("22".parse().unwrap()),
        source_port: None,
        connection_state: TrafficConnectionState::New,
        expectation,
        severity: TrafficSeverity::Critical,
        required_safety_gate: true,
        note: Some("reviewed phase-1 performance corpus".to_owned()),
    }
}

#[test]
fn cross_component_evidence_is_isolated_deterministic_bounded_and_non_mutating() {
    let mut base = snapshot();
    base.runtime.get_mut(&public()).unwrap().target = ZoneTarget::Drop;
    let authoritative = Arc::new(base);
    let authoritative_before = serde_json::to_vec(authoritative.as_ref()).unwrap();
    let operation = FirewallOperation::AddPort {
        zone: public(),
        port: "22/tcp".parse::<PortSpec>().unwrap(),
        target: ConfigurationTarget::Runtime,
    };
    let projection = CandidateProjector::project(
        &authoritative,
        EvaluationSnapshotIdentity::new(17, 3).unwrap(),
        MutationIntentId::new(8).unwrap(),
        None,
        EvaluationTarget::Runtime,
        &[operation],
    )
    .unwrap();

    assert_eq!(projection.snapshot().permanent, authoritative.permanent);
    assert_ne!(projection.snapshot().runtime, authoritative.runtime);

    let runtime_context = candidate_context(1, projection.identity());
    let permanent_context = context(2, EvaluationTarget::Permanent);
    let runtime_index = TrafficEvaluationIndex::new(
        Arc::clone(projection.snapshot_arc()),
        EvaluationTarget::Runtime,
    );
    let before_runtime_index =
        TrafficEvaluationIndex::new(Arc::clone(&authoritative), EvaluationTarget::Runtime);
    let permanent_index =
        TrafficEvaluationIndex::new(Arc::clone(&authoritative), EvaluationTarget::Permanent);
    let scenarios = [
        scenario(2, TrafficExpectation::Allow),
        scenario(1, TrafficExpectation::Allow),
        scenario(3, TrafficExpectation::Allow),
    ];
    let runtime_results = scenarios
        .iter()
        .map(|item| evaluate_scenario(&runtime_index, item, &runtime_context).unwrap())
        .collect::<Vec<_>>();
    let before_runtime_results = scenarios
        .iter()
        .map(|item| {
            evaluate_scenario(
                &before_runtime_index,
                item,
                &context(3, EvaluationTarget::Runtime),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let permanent_results = scenarios
        .iter()
        .map(|item| evaluate_scenario(&permanent_index, item, &permanent_context).unwrap())
        .collect::<Vec<_>>();

    assert!(
        runtime_results
            .iter()
            .all(|result| result.status() == TrafficTestStatus::Pass)
    );
    assert!(
        before_runtime_results
            .iter()
            .all(|result| result.decision() == FirewallDecision::Block)
    );
    assert!(
        permanent_results
            .iter()
            .all(|result| result.status() == TrafficTestStatus::Fail)
    );
    assert_eq!(
        runtime_results
            .iter()
            .map(|result| result.scenario_id().as_str())
            .collect::<Vec<_>>(),
        ["reviewed-0002", "reviewed-0001", "reviewed-0003"]
    );

    let report = TrafficTestReport::new(runtime_context.clone(), runtime_results.clone()).unwrap();
    let repeated = TrafficTestReport::new(runtime_context, runtime_results).unwrap();
    assert_eq!(
        serde_json::to_vec(&report).unwrap(),
        serde_json::to_vec(&repeated).unwrap()
    );
    assert!(report.serialized_len() <= MAX_TRAFFIC_REPORT_BYTES);
    assert_eq!(
        report.context().candidate_identity,
        Some(projection.identity())
    );
    assert!(
        report
            .results()
            .iter()
            .all(|result| result.trace().len() <= MAX_TRACE_STEPS)
    );
    assert_eq!(
        serde_json::to_vec(authoritative.as_ref()).unwrap(),
        authoritative_before
    );
}

fn benchmark_snapshot() -> FirewallSnapshot {
    let mut snapshot = snapshot();
    let zone = snapshot.runtime.get_mut(&public()).unwrap();
    zone.target = ZoneTarget::Default;
    zone.ports.push("22/tcp".parse().unwrap());
    zone.services.push(ServiceName::parse("https").unwrap());
    zone.rich_rules.push(
        RichRule::parse(r#"rule family="ipv4" port port="8443" protocol="tcp" accept"#).unwrap(),
    );
    snapshot.service_definitions.insert(
        ServiceName::parse("https").unwrap(),
        ServiceDefinition {
            ports: vec!["443/tcp".parse().unwrap()],
            ..ServiceDefinition::default()
        },
    );
    let policy_name = PolicyName::parse("admin").unwrap();
    let mut policy = PolicyDetails::empty(policy_name.clone());
    policy.active = true;
    policy.priority = -100;
    policy.target = PolicyTarget::Continue;
    policy.ingress_zones = vec!["public".to_owned()];
    policy.egress_zones = vec!["HOST".to_owned()];
    policy.ports.push("9443/tcp".parse().unwrap());
    snapshot.policies.runtime.insert(policy_name, policy);
    snapshot
}

fn benchmark_scenario(index: usize) -> TrafficScenario {
    let (port, expectation) = match index % 5 {
        0 => ("22", TrafficExpectation::Allow),
        1 => ("443", TrafficExpectation::Allow),
        2 => ("8443", TrafficExpectation::Allow),
        3 => ("9443", TrafficExpectation::Allow),
        _ => ("65000", TrafficExpectation::Block),
    };
    let mut scenario = scenario(index, expectation);
    scenario.destination_port = Some(port.parse().unwrap());
    scenario
}

#[test]
fn traffic_test_1000_scenarios_meets_deadline() {
    let authoritative = Arc::new(benchmark_snapshot());
    let index = TrafficEvaluationIndex::new(authoritative, EvaluationTarget::Runtime);
    let context = context(9, EvaluationTarget::Runtime);
    let suite = TrafficSuite {
        id: context.suite_id.clone(),
        name: "Reviewed 1000-scenario benchmark".to_owned(),
        revision: context.suite_revision,
        scenarios: (0..MAX_SCENARIOS_PER_SUITE)
            .map(benchmark_scenario)
            .collect(),
    };
    suite.validate().unwrap();

    let started = Instant::now();
    let results = suite
        .scenarios
        .iter()
        .map(|scenario| evaluate_scenario(&index, scenario, &context).unwrap())
        .collect::<Vec<_>>();
    let report = TrafficTestReport::new(context, results).unwrap();
    let elapsed = started.elapsed();
    eprintln!("traffic-test-1000 elapsed_ms={}", elapsed.as_millis());

    assert_eq!(report.results().len(), MAX_SCENARIOS_PER_SUITE);
    assert_eq!(report.summary().passed as usize, MAX_SCENARIOS_PER_SUITE);
    assert_eq!(
        report
            .results()
            .iter()
            .filter(|result| result.decision() == FirewallDecision::Allow)
            .count(),
        800
    );
    assert_eq!(
        report
            .results()
            .iter()
            .filter(|result| result.decision() == FirewallDecision::Block)
            .count(),
        200
    );
    assert!(
        report
            .results()
            .iter()
            .all(|result| result.trace().len() <= MAX_TRACE_STEPS)
    );
    assert!(report.serialized_len() <= MAX_TRAFFIC_REPORT_BYTES);
    if std::env::var("FWDECK_ENFORCE_TRAFFIC_TEST_DEADLINE").as_deref() == Ok("1") {
        assert!(
            elapsed <= Duration::from_secs(2),
            "1000 scenarios took {elapsed:?}"
        );
    }
}
