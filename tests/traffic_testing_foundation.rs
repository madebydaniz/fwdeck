#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;

use fwdeck::domain::{
    AddressFamily, ConfigurationTarget, DegradedSection, FirewallOperation, FirewallSnapshot,
    FirewallStatus, FirewalldFeature, IpProtocol, IpSetName, LogDenied, NetfilterBackend,
    OperationEffectSupport, OperationTargetSequence, PartialApplicationPolicy, RichRule,
    RichRuleAnalysis, RulePriority, Scoped, SemanticCapabilityKind, ServiceDefinition,
    ServiceDestination, ServiceModuleName, ServiceName, ServiceResolutionFailure, SnapshotSection,
    SourceAddress, TemporalBehavior, TrafficDimension, TrafficIrrelevanceProof,
    UnsupportedOperationReason, ZoneDetails, ZoneName, resolve_service_includes,
};
use serde::Deserialize;
use serde::de::DeserializeOwned;

fn load_fixture<T: DeserializeOwned>(name: &str) -> T {
    let raw = match name {
        "capability_thresholds.json" => {
            include_str!("fixtures/traffic_testing/capability_thresholds.json")
        }
        "zone-observation.json" => {
            include_str!("fixtures/traffic_testing/observation/zone-observation.json")
        }
        "service-evidence.json" => {
            include_str!("fixtures/traffic_testing/observation/service-evidence.json")
        }
        "semantic-classification.json" => {
            include_str!("fixtures/traffic_testing/observation/semantic-classification.json")
        }
        other => panic!("unknown reviewed fixture {other}"),
    };
    serde_json::from_str(raw).expect("reviewed traffic-testing fixture must match its schema")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureMetadata {
    schema_version: u32,
    fixture_version: String,
    reviewed_on: String,
    sources: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ZoneDocument {
    #[serde(flatten)]
    metadata: FixtureMetadata,
    firewalld_version: String,
    zones: Vec<ZoneFixture>,
    degraded_evidence: Vec<DegradedFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ZoneFixture {
    name: String,
    runtime: ZoneScopeFixture,
    permanent: ZoneScopeFixture,
    expected_drift: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ZoneScopeFixture {
    ingress_priority: i32,
    egress_priority: i32,
    services: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DegradedFixture {
    section: String,
    target: Option<String>,
    object: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceDocument {
    #[serde(flatten)]
    metadata: FixtureMetadata,
    complete_case: ServiceCase,
    missing_include_case: ServiceCase,
    cycle_case: ServiceCase,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceCase {
    root: String,
    definitions: Vec<ServiceDefinitionFixture>,
    expected_services: Vec<String>,
    expected_ports: Vec<String>,
    expected_protocols: Vec<String>,
    expected_source_ports: Vec<String>,
    expected_helpers: Vec<String>,
    expected_modules: Vec<String>,
    expected_failure: Option<ServiceFailureFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceDefinitionFixture {
    name: String,
    ports: Vec<String>,
    protocols: Vec<String>,
    source_ports: Vec<String>,
    destinations: Vec<ServiceDestinationFixture>,
    includes: Vec<String>,
    helpers: Vec<String>,
    modules: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceDestinationFixture {
    family: String,
    address: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceFailureFixture {
    kind: String,
    referenced_by: Option<String>,
    service: Option<String>,
    path: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticDocument {
    #[serde(flatten)]
    metadata: FixtureMetadata,
    rich_rules: Vec<RichRuleFixture>,
    operation_effects: Vec<OperationEffectFixture>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RichRuleFixture {
    id: String,
    raw: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationEffectFixture {
    id: String,
    expected_support: String,
    expected_targets: String,
    expected_dimensions: Vec<String>,
    expected_temporal: String,
    expected_partial: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityManifest {
    schema_version: u32,
    fixture_version: String,
    reviewed_on: String,
    features: Vec<CapabilityRow>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityRow {
    feature: String,
    kind: String,
    minimum: String,
    source: String,
}

fn assert_metadata(metadata: &FixtureMetadata) {
    assert_eq!(metadata.schema_version, 1);
    assert_eq!(metadata.fixture_version, "phase0-v1");
    assert_eq!(metadata.reviewed_on, "2026-08-21");
    assert!(!metadata.sources.is_empty());
    assert!(metadata.sources.iter().all(|source| {
        source.starts_with("https://firewalld.org/") && !source.contains(char::is_whitespace)
    }));
}

fn service_name(raw: &str) -> ServiceName {
    ServiceName::parse(raw).unwrap()
}

fn definition(fixture: &ServiceDefinitionFixture) -> ServiceDefinition {
    ServiceDefinition {
        ports: fixture
            .ports
            .iter()
            .map(|port| port.parse().unwrap())
            .collect(),
        protocols: fixture
            .protocols
            .iter()
            .map(|protocol| IpProtocol::parse(protocol).unwrap())
            .collect(),
        source_ports: fixture
            .source_ports
            .iter()
            .map(|port| port.parse().unwrap())
            .collect(),
        destinations: fixture
            .destinations
            .iter()
            .map(|destination| ServiceDestination {
                family: match destination.family.as_str() {
                    "ipv4" => AddressFamily::Ipv4,
                    "ipv6" => AddressFamily::Ipv6,
                    other => panic!("unknown fixture address family {other}"),
                },
                address: SourceAddress::parse(&destination.address).unwrap(),
            })
            .collect(),
        includes: fixture
            .includes
            .iter()
            .map(|name| service_name(name))
            .collect(),
        helpers: fixture
            .helpers
            .iter()
            .map(|name| service_name(name))
            .collect(),
        modules: fixture
            .modules
            .iter()
            .map(|name| ServiceModuleName::parse(name).unwrap())
            .collect(),
    }
}

fn assert_service_case(case: &ServiceCase) {
    let definitions = case
        .definitions
        .iter()
        .map(|fixture| (service_name(&fixture.name), definition(fixture)))
        .collect::<BTreeMap<_, _>>();
    let resolved = resolve_service_includes(&service_name(&case.root), &definitions);

    assert_eq!(
        resolved
            .services
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        case.expected_services
    );
    assert_eq!(
        resolved
            .effective
            .ports
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        case.expected_ports
    );
    assert_eq!(
        resolved
            .effective
            .protocols
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        case.expected_protocols
    );
    assert_eq!(
        resolved
            .effective
            .source_ports
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        case.expected_source_ports
    );
    assert_eq!(
        resolved
            .effective
            .helpers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        case.expected_helpers
    );
    assert_eq!(
        resolved
            .effective
            .modules
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        case.expected_modules
    );

    match (&case.expected_failure, resolved.failures.as_slice()) {
        (None, []) => {}
        (
            Some(expected),
            [
                ServiceResolutionFailure::MissingInclude {
                    referenced_by,
                    service,
                },
            ],
        ) if expected.kind == "missing_include" => {
            assert_eq!(
                referenced_by.as_str(),
                expected.referenced_by.as_deref().unwrap()
            );
            assert_eq!(service.as_str(), expected.service.as_deref().unwrap());
        }
        (Some(expected), [ServiceResolutionFailure::Cycle { path }])
            if expected.kind == "cycle" =>
        {
            assert_eq!(
                path.iter().map(ToString::to_string).collect::<Vec<_>>(),
                expected.path.clone().unwrap()
            );
        }
        other => panic!("unexpected service resolution result: {other:?}"),
    }
}

fn zone_details(name: &str, scope: &ZoneScopeFixture) -> ZoneDetails {
    let mut details = ZoneDetails::empty(ZoneName::parse(name).unwrap());
    details.ingress_priority = RulePriority::new(scope.ingress_priority).unwrap();
    details.egress_priority = RulePriority::new(scope.egress_priority).unwrap();
    details.services = scope
        .services
        .iter()
        .map(|name| service_name(name))
        .collect();
    details
}

fn observed_drift(runtime: &ZoneDetails, permanent: &ZoneDetails) -> Vec<String> {
    let mut drift = Vec::new();
    if runtime.ingress_priority != permanent.ingress_priority {
        drift.push("ingress_priority".to_owned());
    }
    if runtime.egress_priority != permanent.egress_priority {
        drift.push("egress_priority".to_owned());
    }
    if runtime.services != permanent.services {
        drift.push("services".to_owned());
    }
    drift
}

fn degraded_record(fixture: &DegradedFixture) -> DegradedSection {
    let section = match fixture.section.as_str() {
        "service_definitions" => SnapshotSection::ServiceDefinitions,
        "policies" => SnapshotSection::Policies,
        other => panic!("unknown fixture section {other}"),
    };
    let target = fixture.target.as_deref().map(|target| match target {
        "runtime" => ConfigurationTarget::Runtime,
        "permanent" => ConfigurationTarget::Permanent,
        other => panic!("unknown fixture target {other}"),
    });
    DegradedSection::new(section, target, fixture.reason.clone())
        .with_object(fixture.object.clone())
}

fn snapshot(zone_document: &ZoneDocument) -> FirewallSnapshot {
    let runtime = zone_document
        .zones
        .iter()
        .map(|zone| {
            (
                ZoneName::parse(&zone.name).unwrap(),
                zone_details(&zone.name, &zone.runtime),
            )
        })
        .collect();
    let permanent = zone_document
        .zones
        .iter()
        .map(|zone| {
            (
                ZoneName::parse(&zone.name).unwrap(),
                zone_details(&zone.name, &zone.permanent),
            )
        })
        .collect();
    FirewallSnapshot {
        status: FirewallStatus {
            daemon_running: true,
            version: Some(zone_document.firewalld_version.clone()),
            backend: NetfilterBackend::Nftables,
            log_denied: LogDenied::Off,
            panic_mode: false,
        },
        default_zone: ZoneName::parse("public").unwrap(),
        active: BTreeMap::new(),
        runtime,
        permanent,
        ipsets: Scoped {
            runtime: BTreeMap::new(),
            permanent: BTreeMap::new(),
        },
        service_definitions: BTreeMap::new(),
        available_services: vec![],
        policies: Scoped {
            runtime: BTreeMap::new(),
            permanent: BTreeMap::new(),
        },
        direct_rules: vec![],
        degraded: zone_document
            .degraded_evidence
            .iter()
            .map(degraded_record)
            .collect(),
    }
}

fn operation(id: &str) -> FirewallOperation {
    match id {
        "add-service-both" => FirewallOperation::AddService {
            zone: ZoneName::parse("public").unwrap(),
            service: service_name("ssh"),
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        "temporary-service" => FirewallOperation::AddTemporaryService {
            zone: ZoneName::parse("public").unwrap(),
            service: service_name("ssh"),
            seconds: 90,
        },
        "reload" => FirewallOperation::Reload,
        "set-log-denied" => FirewallOperation::SetLogDenied {
            value: LogDenied::All,
        },
        "create-ipset" => FirewallOperation::CreateIpSet {
            name: IpSetName::parse("trusted").unwrap(),
            kind: "hash:ip".to_owned(),
        },
        other => panic!("unknown operation fixture {other}"),
    }
}

fn support_label(support: OperationEffectSupport) -> &'static str {
    match support {
        OperationEffectSupport::SupportedExact => "supported_exact",
        OperationEffectSupport::SupportedAtEvaluationInstant => "supported_at_evaluation_instant",
        OperationEffectSupport::GlobalTransform => "global_transform",
        OperationEffectSupport::TrafficIrrelevant(
            TrafficIrrelevanceProof::LoggingSideEffectOnly,
        ) => "traffic_irrelevant_logging_side_effect_only",
        OperationEffectSupport::UnsupportedRelevant(UnsupportedOperationReason::IpSetSemantics) => {
            "unsupported_relevant_ipset_semantics"
        }
        OperationEffectSupport::UnsupportedRelevant(_) => "other_unsupported_relevant",
    }
}

fn target_label(target: OperationTargetSequence) -> &'static str {
    match target {
        OperationTargetSequence::Runtime => "runtime",
        OperationTargetSequence::Permanent => "permanent",
        OperationTargetSequence::RuntimeThenPermanent => "runtime_then_permanent",
        OperationTargetSequence::RuntimeAndPermanent => "runtime_and_permanent",
        OperationTargetSequence::RuntimeFromPermanent => "runtime_from_permanent",
        OperationTargetSequence::PermanentFromRuntime => "permanent_from_runtime",
    }
}

fn dimension_label(dimension: TrafficDimension) -> &'static str {
    match dimension {
        TrafficDimension::Service => "service",
        TrafficDimension::IpSet => "ipset",
        TrafficDimension::GlobalConfiguration => "global_configuration",
        TrafficDimension::Observability => "observability",
        other => panic!("unexpected golden traffic dimension {other:?}"),
    }
}

fn temporal_label(temporal: TemporalBehavior) -> String {
    match temporal {
        TemporalBehavior::Immediate => "immediate".to_owned(),
        TemporalBehavior::StoredUntilReload => "stored_until_reload".to_owned(),
        TemporalBehavior::ExpiresAfterSeconds(seconds) => {
            format!("expires_after_{seconds}_seconds")
        }
        TemporalBehavior::GlobalReplacement => "global_replacement".to_owned(),
        TemporalBehavior::NoTrafficDecisionEffect => "no_traffic_decision_effect".to_owned(),
    }
}

fn partial_label(policy: PartialApplicationPolicy) -> &'static str {
    match policy {
        PartialApplicationPolicy::SingleStep => "single_step",
        PartialApplicationPolicy::ReconcileExecutedSteps => "reconcile_executed_steps",
    }
}

#[test]
fn reviewed_documents_have_deterministic_schema_and_primary_sources() {
    let zone: ZoneDocument = load_fixture("zone-observation.json");
    let service: ServiceDocument = load_fixture("service-evidence.json");
    let semantic: SemanticDocument = load_fixture("semantic-classification.json");

    assert_metadata(&zone.metadata);
    assert_metadata(&service.metadata);
    assert_metadata(&semantic.metadata);
}

#[test]
fn capability_threshold_manifest_is_versioned_and_source_attributed() {
    let manifest: CapabilityManifest = load_fixture("capability_thresholds.json");
    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.fixture_version, "phase0-v1");
    assert_eq!(manifest.reviewed_on, "2026-08-21");
    assert_eq!(manifest.features.len(), FirewalldFeature::ALL.len());
    assert!(manifest.features.iter().all(|row| {
        !row.feature.is_empty()
            && matches!(row.kind.as_str(), "syntax" | "behavior")
            && !row.minimum.is_empty()
            && row.source.starts_with("https://firewalld.org/")
    }));
    assert!(manifest.features.iter().any(|row| {
        row.feature == "zone_priorities"
            && row.kind
                == match FirewalldFeature::ZonePriorities.kind() {
                    SemanticCapabilityKind::Syntax => "syntax",
                    SemanticCapabilityKind::Behavior => "behavior",
                }
            && row.minimum == FirewalldFeature::ZonePriorities.minimum_version()
    }));
}

#[test]
fn zone_priorities_drift_and_degraded_scope_match_the_golden_observation() {
    let document: ZoneDocument = load_fixture("zone-observation.json");
    let snapshot = snapshot(&document);

    for fixture in &document.zones {
        let name = ZoneName::parse(&fixture.name).unwrap();
        assert_eq!(
            observed_drift(&snapshot.runtime[&name], &snapshot.permanent[&name]),
            fixture.expected_drift
        );
    }
    assert!(!snapshot.section_is_complete(
        SnapshotSection::ServiceDefinitions,
        ConfigurationTarget::Runtime
    ));
    assert!(!snapshot.section_is_complete(
        SnapshotSection::ServiceDefinitions,
        ConfigurationTarget::Permanent
    ));
    assert!(!snapshot.section_is_complete(SnapshotSection::Policies, ConfigurationTarget::Runtime));
    assert!(
        snapshot.section_is_complete(SnapshotSection::Policies, ConfigurationTarget::Permanent)
    );
    assert_eq!(snapshot.degraded[0].object.as_deref(), Some("ftp"));
}

#[test]
fn complete_and_incomplete_service_evidence_resolves_exactly() {
    let document: ServiceDocument = load_fixture("service-evidence.json");
    assert_service_case(&document.complete_case);
    assert_service_case(&document.missing_include_case);
    assert_service_case(&document.cycle_case);
}

#[test]
fn rich_rules_and_operation_effects_match_reviewed_semantics() {
    let document: SemanticDocument = load_fixture("semantic-classification.json");

    for fixture in document.rich_rules {
        let analysis = RichRule::parse(&fixture.raw).unwrap().analyze();
        let actual = match analysis {
            RichRuleAnalysis::Supported(_) => "supported",
            RichRuleAnalysis::Unsupported(_) => "unsupported",
            RichRuleAnalysis::Malformed(_) => "malformed",
        };
        assert_eq!(actual, fixture.expected, "rich-rule fixture {}", fixture.id);
    }

    for fixture in document.operation_effects {
        let effect = operation(&fixture.id).effect();
        assert_eq!(support_label(effect.support), fixture.expected_support);
        assert_eq!(target_label(effect.targets), fixture.expected_targets);
        assert_eq!(
            effect
                .dimensions
                .into_iter()
                .map(dimension_label)
                .collect::<Vec<_>>(),
            fixture.expected_dimensions
        );
        assert_eq!(temporal_label(effect.temporal), fixture.expected_temporal);
        assert_eq!(
            partial_label(effect.partial_application),
            fixture.expected_partial
        );
    }
}
