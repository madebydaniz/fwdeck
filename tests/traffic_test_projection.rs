#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::Arc;

use fwdeck::domain::{
    CandidateProjector, ConfigurationTarget, EvaluationPlanId, EvaluationSnapshotIdentity,
    EvaluationTarget, FirewallOperation, FirewallSnapshot, FirewallStatus, LogDenied,
    MutationIntentId, NetfilterBackend, PolicyDetails, PolicyName, PolicyTarget, PortSpec,
    RichRule, Scoped, ServiceDefinition, ServiceName, UnsupportedOperationReason, ZoneDetails,
    ZoneName, ZoneTarget,
};

fn identity() -> EvaluationSnapshotIdentity {
    EvaluationSnapshotIdentity::new(41, 7).unwrap()
}

fn project(
    base: &Arc<fwdeck::domain::FirewallSnapshot>,
    target: EvaluationTarget,
    operations: &[FirewallOperation],
) -> fwdeck::domain::CandidateProjection {
    CandidateProjector::project(
        base,
        identity(),
        MutationIntentId::new(9).unwrap(),
        Some(EvaluationPlanId::new(12)),
        target,
        operations,
    )
    .unwrap()
}

fn public() -> ZoneName {
    ZoneName::parse("public").unwrap()
}

fn ssh() -> ServiceName {
    ServiceName::parse("ssh").unwrap()
}

fn snapshot() -> FirewallSnapshot {
    let zone = ZoneDetails::empty(public());
    let mut runtime_zone = zone.clone();
    runtime_zone.services.push(ssh());
    let mut permanent_zone = zone;
    permanent_zone.services.push(ssh());

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
        runtime: BTreeMap::from([(public(), runtime_zone)]),
        permanent: BTreeMap::from([(public(), permanent_zone)]),
        ipsets: Scoped::default(),
        service_definitions: BTreeMap::from([(
            ssh(),
            ServiceDefinition {
                ports: vec!["22/tcp".parse().unwrap()],
                ..ServiceDefinition::default()
            },
        )]),
        available_services: vec![ssh(), ServiceName::parse("mysql").unwrap()],
        policies: Scoped::default(),
        direct_rules: Vec::new(),
        degraded: Vec::new(),
    }
}

#[test]
fn ordered_operations_change_both_projection_and_identity() {
    let base = Arc::new(snapshot());
    let port: PortSpec = "9443/tcp".parse().unwrap();
    let add = FirewallOperation::AddPort {
        zone: public(),
        port,
        target: ConfigurationTarget::Runtime,
    };
    let remove = FirewallOperation::RemovePort {
        zone: public(),
        port,
        target: ConfigurationTarget::Runtime,
    };

    let removed = project(
        &base,
        EvaluationTarget::Runtime,
        &[add.clone(), remove.clone()],
    );
    let added = project(&base, EvaluationTarget::Runtime, &[remove, add]);

    assert!(!removed.snapshot().runtime[&public()].ports.contains(&port));
    assert!(added.snapshot().runtime[&public()].ports.contains(&port));
    assert_ne!(removed.identity(), added.identity());
    assert!(removed.is_exact());
    assert!(added.is_exact());
}

#[test]
fn runtime_and_permanent_candidates_are_strictly_separated() {
    let base = Arc::new(snapshot());
    let port: PortSpec = "9443/tcp".parse().unwrap();
    let operation = FirewallOperation::AddPort {
        zone: public(),
        port,
        target: ConfigurationTarget::Permanent,
    };

    let runtime = project(
        &base,
        EvaluationTarget::Runtime,
        std::slice::from_ref(&operation),
    );
    let permanent = project(&base, EvaluationTarget::Permanent, &[operation]);

    assert!(!runtime.snapshot().runtime[&public()].ports.contains(&port));
    assert!(
        permanent.snapshot().permanent[&public()]
            .ports
            .contains(&port)
    );
    assert_ne!(runtime.identity(), permanent.identity());
}

#[test]
fn temporary_services_exist_only_in_the_runtime_candidate() {
    let base = Arc::new(snapshot());
    let operation = FirewallOperation::AddTemporaryService {
        zone: public(),
        service: ServiceName::parse("mysql").unwrap(),
        seconds: 120,
    };

    let runtime = project(
        &base,
        EvaluationTarget::Runtime,
        std::slice::from_ref(&operation),
    );
    let permanent = project(&base, EvaluationTarget::Permanent, &[operation]);

    assert!(
        runtime.snapshot().runtime[&public()]
            .services
            .contains(&ServiceName::parse("mysql").unwrap())
    );
    assert!(
        !permanent.snapshot().permanent[&public()]
            .services
            .contains(&ServiceName::parse("mysql").unwrap())
    );
}

#[test]
fn reload_replaces_runtime_with_the_projected_permanent_configuration() {
    let base = Arc::new(snapshot());
    let port: PortSpec = "9443/tcp".parse().unwrap();
    let operations = [
        FirewallOperation::AddPort {
            zone: public(),
            port,
            target: ConfigurationTarget::Permanent,
        },
        FirewallOperation::AddTemporaryService {
            zone: public(),
            service: ServiceName::parse("mysql").unwrap(),
            seconds: 120,
        },
        FirewallOperation::Reload,
    ];

    let runtime = project(&base, EvaluationTarget::Runtime, &operations);

    assert!(runtime.snapshot().runtime[&public()].ports.contains(&port));
    assert!(
        !runtime.snapshot().runtime[&public()]
            .services
            .contains(&ServiceName::parse("mysql").unwrap())
    );
}

#[test]
fn runtime_to_permanent_replaces_the_stored_configuration() {
    let base = Arc::new(snapshot());
    let port: PortSpec = "9443/tcp".parse().unwrap();
    let operations = [
        FirewallOperation::AddPort {
            zone: public(),
            port,
            target: ConfigurationTarget::Runtime,
        },
        FirewallOperation::RuntimeToPermanent,
    ];

    let permanent = project(&base, EvaluationTarget::Permanent, &operations);

    assert!(
        permanent.snapshot().permanent[&public()]
            .ports
            .contains(&port)
    );
}

#[test]
fn panic_mode_is_projected_only_for_runtime_evaluation() {
    let base = Arc::new(snapshot());
    let operation = FirewallOperation::SetPanicMode { enabled: true };

    let runtime = project(
        &base,
        EvaluationTarget::Runtime,
        std::slice::from_ref(&operation),
    );
    let permanent = project(&base, EvaluationTarget::Permanent, &[operation]);

    assert!(runtime.snapshot().status.panic_mode);
    assert!(!permanent.snapshot().status.panic_mode);
}

#[test]
fn zone_policy_and_service_mutations_compose_before_reload() {
    let base = Arc::new(snapshot());
    let policy = PolicyName::parse("candidate-policy").unwrap();
    let service = ServiceName::parse("candidate-service").unwrap();
    let port: PortSpec = "8443/tcp".parse().unwrap();
    let operations = [
        FirewallOperation::CreateService {
            service: service.clone(),
        },
        FirewallOperation::AddServicePort {
            service: service.clone(),
            port,
        },
        FirewallOperation::AddService {
            zone: public(),
            service: service.clone(),
            target: ConfigurationTarget::Permanent,
        },
        FirewallOperation::CreatePolicy {
            policy: policy.clone(),
        },
        FirewallOperation::AddPolicyIngressZone {
            policy: policy.clone(),
            zone: "public".to_owned(),
        },
        FirewallOperation::AddPolicyEgressZone {
            policy: policy.clone(),
            zone: "HOST".to_owned(),
        },
        FirewallOperation::SetPolicyTarget {
            policy: policy.clone(),
            policy_target: PolicyTarget::Accept,
        },
        FirewallOperation::Reload,
    ];

    let runtime = project(&base, EvaluationTarget::Runtime, &operations);
    let policy_details: &PolicyDetails = &runtime.snapshot().policies.runtime[&policy];

    assert!(
        runtime.snapshot().runtime[&public()]
            .services
            .contains(&service)
    );
    assert_eq!(
        runtime.snapshot().service_definitions[&service].ports,
        vec![port]
    );
    assert_eq!(policy_details.ingress_zones, vec!["public"]);
    assert_eq!(policy_details.egress_zones, vec!["HOST"]);
    assert_eq!(policy_details.target, PolicyTarget::Accept);
}

#[test]
fn log_denied_reload_discards_runtime_only_changes() {
    let mut snapshot = snapshot();
    let runtime_only_port: PortSpec = "9443/tcp".parse().unwrap();
    snapshot
        .runtime
        .get_mut(&public())
        .unwrap()
        .ports
        .push(runtime_only_port);
    let base = Arc::new(snapshot);
    let unchanged = project(&base, EvaluationTarget::Runtime, &[]);
    let logging_only = project(
        &base,
        EvaluationTarget::Runtime,
        &[FirewallOperation::SetLogDenied {
            value: LogDenied::All,
        }],
    );

    assert!(logging_only.is_exact());
    assert_eq!(logging_only.snapshot().status.log_denied, LogDenied::Off);
    assert!(
        unchanged.snapshot().runtime[&public()]
            .ports
            .contains(&runtime_only_port)
    );
    assert!(
        !logging_only.snapshot().runtime[&public()]
            .ports
            .contains(&runtime_only_port)
    );
    assert_ne!(logging_only.identity(), unchanged.identity());
}

#[test]
fn unsupported_relevant_operations_create_typed_target_markers() {
    let base = Arc::new(snapshot());
    let unsupported = FirewallOperation::AddRichRule {
        zone: public(),
        rule: RichRule::parse(r#"rule family=\"ipv4\" log prefix=\"audit\" accept"#).unwrap(),
        target: ConfigurationTarget::Permanent,
    };

    let runtime = project(
        &base,
        EvaluationTarget::Runtime,
        std::slice::from_ref(&unsupported),
    );
    let permanent = project(&base, EvaluationTarget::Permanent, &[unsupported]);

    assert!(runtime.is_exact());
    assert!(!permanent.is_exact());
    assert_eq!(permanent.unknown_effects().len(), 1);
    assert_eq!(permanent.unknown_effects()[0].operation_index(), 0);
    assert_eq!(
        permanent.unknown_effects()[0].reason(),
        UnsupportedOperationReason::RichRuleSemantics
    );
}

#[test]
fn global_replacement_propagates_unknown_effects_to_the_destination_target() {
    let base = Arc::new(snapshot());
    let operations = [
        FirewallOperation::AddRichRule {
            zone: public(),
            rule: RichRule::parse(r#"rule family=\"ipv4\" log prefix=\"audit\" accept"#).unwrap(),
            target: ConfigurationTarget::Permanent,
        },
        FirewallOperation::Reload,
    ];

    let runtime = project(&base, EvaluationTarget::Runtime, &operations);

    assert!(!runtime.is_exact());
    assert_eq!(runtime.unknown_effects()[0].operation_index(), 0);
}

#[test]
fn projection_never_mutates_the_authoritative_base_snapshot() {
    let base = Arc::new(snapshot());
    let before = (*base).clone();
    let operation = FirewallOperation::RemoveService {
        zone: public(),
        service: ssh(),
        target: ConfigurationTarget::RuntimeAndPermanent,
    };

    let projected = project(&base, EvaluationTarget::Runtime, &[operation]);

    assert_eq!(*base, before);
    assert!(!Arc::ptr_eq(projected.snapshot_arc(), &base));
    assert!(
        projected.snapshot().runtime[&public()]
            .services
            .iter()
            .all(|service| service != &ssh())
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn exact_zone_primitives_project_as_one_reviewed_sequence() {
    let base = Arc::new(snapshot());
    let zone = public();
    let source_port = "53000/udp".parse().unwrap();
    let protocol = fwdeck::domain::IpProtocol::parse("gre").unwrap();
    let forward: fwdeck::domain::ForwardPort = "port=8443:proto=tcp:toport=443".parse().unwrap();
    let rule = RichRule::parse(
        r#"rule family="ipv4" source address="192.0.2.0/24" port port="9443" protocol="tcp" accept"#,
    )
    .unwrap();
    let interface = fwdeck::domain::InterfaceName::parse("eth9").unwrap();
    let source = fwdeck::domain::SourceAddress::parse("198.51.100.0/24").unwrap();
    let icmp = fwdeck::domain::IcmpType::parse("echo-request").unwrap();
    let mysql = ServiceName::parse("mysql").unwrap();
    let operations = vec![
        FirewallOperation::AddService {
            zone: zone.clone(),
            service: mysql.clone(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::RemoveService {
            zone: zone.clone(),
            service: mysql,
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::SetDefaultZone { zone: zone.clone() },
        FirewallOperation::SetMasquerade {
            zone: zone.clone(),
            enabled: true,
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::SetZoneTarget {
            zone: zone.clone(),
            zone_target: ZoneTarget::Drop,
        },
        FirewallOperation::AddSourcePort {
            zone: zone.clone(),
            port: source_port,
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::RemoveSourcePort {
            zone: zone.clone(),
            port: source_port,
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::AddProtocol {
            zone: zone.clone(),
            protocol: protocol.clone(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::RemoveProtocol {
            zone: zone.clone(),
            protocol,
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::SetForward {
            zone: zone.clone(),
            enabled: true,
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::SetIcmpBlockInversion {
            zone: zone.clone(),
            enabled: true,
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::AddForwardPort {
            zone: zone.clone(),
            forward: forward.clone(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::RemoveForwardPort {
            zone: zone.clone(),
            forward,
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::AddRichRule {
            zone: zone.clone(),
            rule: rule.clone(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::RemoveRichRule {
            zone: zone.clone(),
            rule,
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::AddInterface {
            zone: zone.clone(),
            interface: interface.clone(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::RemoveInterface {
            zone: zone.clone(),
            interface,
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::AddSource {
            zone: zone.clone(),
            source: source.clone(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::RemoveSource {
            zone: zone.clone(),
            source,
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::AddIcmpBlock {
            zone: zone.clone(),
            icmp: icmp.clone(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::RemoveIcmpBlock {
            zone,
            icmp,
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
    ];

    let runtime = project(&base, EvaluationTarget::Runtime, &operations);
    let permanent = project(&base, EvaluationTarget::Permanent, &operations);
    assert!(runtime.is_exact());
    assert!(permanent.is_exact());
    assert!(runtime.snapshot().runtime[&public()].masquerade);
    assert!(runtime.snapshot().runtime[&public()].forward);
    assert!(runtime.snapshot().runtime[&public()].icmp_block_inversion);
    assert_eq!(
        permanent.snapshot().permanent[&public()].target,
        ZoneTarget::Drop
    );
}

#[test]
fn service_policy_and_zone_lifecycle_failures_are_typed() {
    let base = Arc::new(snapshot());
    let missing_service = ServiceName::parse("absent").unwrap();
    let missing_policy = PolicyName::parse("absent-policy").unwrap();
    let missing_zone = ZoneName::parse("absent-zone").unwrap();
    let port: PortSpec = "9443/tcp".parse().unwrap();

    for operation in [
        FirewallOperation::DeleteService {
            service: missing_service.clone(),
        },
        FirewallOperation::AddServicePort {
            service: missing_service.clone(),
            port,
        },
        FirewallOperation::RemoveServicePort {
            service: missing_service,
            port,
        },
        FirewallOperation::DeletePolicy {
            policy: missing_policy,
        },
        FirewallOperation::DeleteZone { zone: missing_zone },
    ] {
        let error = CandidateProjector::project(
            &base,
            identity(),
            MutationIntentId::new(9).unwrap(),
            None,
            EvaluationTarget::Permanent,
            &[operation],
        )
        .unwrap_err();
        assert!(!error.to_string().is_empty());
    }
}

#[test]
fn service_policy_zone_and_active_lifecycles_project_exactly() {
    let mut base_snapshot = snapshot();
    let policy = PolicyName::parse("gateway-ingress").unwrap();
    let mut policy_details = PolicyDetails::empty(policy.clone());
    policy_details.ingress_zones = vec!["ANY".to_owned()];
    policy_details.egress_zones = vec!["HOST".to_owned()];
    base_snapshot
        .policies
        .runtime
        .insert(policy.clone(), policy_details.clone());
    base_snapshot
        .policies
        .permanent
        .insert(policy.clone(), policy_details);
    let base = Arc::new(base_snapshot);
    let service = ServiceName::parse("lifecycle-service").unwrap();
    let port: PortSpec = "10443/tcp".parse().unwrap();
    let zone = ZoneName::parse("lifecycle-zone").unwrap();
    let operations = [
        FirewallOperation::CreateService {
            service: service.clone(),
        },
        FirewallOperation::AddServicePort {
            service: service.clone(),
            port,
        },
        FirewallOperation::RemoveServicePort {
            service: service.clone(),
            port,
        },
        FirewallOperation::AddPolicyService {
            policy: policy.clone(),
            service: ssh(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::RemovePolicyService {
            policy: policy.clone(),
            service: ssh(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::SetPolicySetEnabled {
            policy_set: fwdeck::domain::PolicySetName::parse("gateway").unwrap(),
            enabled: false,
            target: ConfigurationTarget::RuntimeAndPermanent,
        },
        FirewallOperation::CreateZone { zone: zone.clone() },
        FirewallOperation::AddInterface {
            zone: zone.clone(),
            interface: fwdeck::domain::InterfaceName::parse("eth77").unwrap(),
            target: ConfigurationTarget::Permanent,
        },
        FirewallOperation::Reload,
        FirewallOperation::DeleteZone { zone },
        FirewallOperation::DeleteService { service },
    ];

    let runtime = project(&base, EvaluationTarget::Runtime, &operations);
    let permanent = project(&base, EvaluationTarget::Permanent, &operations);
    assert!(runtime.is_exact());
    assert!(permanent.is_exact());
    assert!(runtime.snapshot().policies.runtime[&policy].disabled);
    assert!(permanent.snapshot().policies.permanent[&policy].disabled);
    assert!(
        runtime
            .snapshot()
            .active
            .keys()
            .any(|zone| zone.as_str() == "lifecycle-zone")
    );
    assert!(
        !permanent
            .snapshot()
            .permanent
            .keys()
            .any(|zone| zone.as_str() == "lifecycle-zone")
    );
}

#[test]
fn duplicate_creates_and_target_specific_missing_objects_are_rejected() {
    let base = Arc::new(snapshot());
    let policy = PolicyName::parse("missing-policy").unwrap();
    let zone = ZoneName::parse("missing-zone").unwrap();
    for operation in [
        FirewallOperation::CreateService { service: ssh() },
        FirewallOperation::CreateZone { zone: public() },
        FirewallOperation::AddPolicyService {
            policy: policy.clone(),
            service: ssh(),
            target: ConfigurationTarget::Runtime,
        },
        FirewallOperation::AddPolicyService {
            policy,
            service: ssh(),
            target: ConfigurationTarget::Permanent,
        },
        FirewallOperation::AddPort {
            zone: zone.clone(),
            port: "22/tcp".parse().unwrap(),
            target: ConfigurationTarget::Runtime,
        },
        FirewallOperation::AddPort {
            zone,
            port: "22/tcp".parse().unwrap(),
            target: ConfigurationTarget::Permanent,
        },
    ] {
        let error = CandidateProjector::project(
            &base,
            identity(),
            MutationIntentId::new(19).unwrap(),
            None,
            EvaluationTarget::Runtime,
            &[operation],
        )
        .unwrap_err();
        assert!(!error.to_string().is_empty());
    }
}

#[test]
fn projection_metadata_degradation_and_policy_lifecycle_are_preserved() {
    let mut observed = snapshot();
    observed.degraded = vec![
        fwdeck::domain::DegradedSection::new(
            fwdeck::domain::SnapshotSection::Zones,
            None,
            "global evidence gap",
        ),
        fwdeck::domain::DegradedSection::new(
            fwdeck::domain::SnapshotSection::Policies,
            Some(ConfigurationTarget::RuntimeAndPermanent),
            "shared policy gap",
        ),
        fwdeck::domain::DegradedSection::new(
            fwdeck::domain::SnapshotSection::Services,
            Some(ConfigurationTarget::Permanent),
            "permanent service gap",
        ),
    ];
    let base = Arc::new(observed);
    let policy = PolicyName::parse("lifecycle-policy").unwrap();
    let created = project(
        &base,
        EvaluationTarget::Permanent,
        &[FirewallOperation::CreatePolicy {
            policy: policy.clone(),
        }],
    );
    assert!(created.snapshot().policies.permanent.contains_key(&policy));
    assert_eq!(created.snapshot().degraded.len(), 3);
    assert!(created.snapshot().degraded.iter().all(|record| {
        record.target.is_none() || record.target == Some(ConfigurationTarget::Permanent)
    }));

    let duplicate = CandidateProjector::project(
        created.snapshot_arc(),
        identity(),
        MutationIntentId::new(22).unwrap(),
        None,
        EvaluationTarget::Permanent,
        &[FirewallOperation::CreatePolicy {
            policy: policy.clone(),
        }],
    );
    assert!(matches!(
        duplicate,
        Err(fwdeck::domain::CandidateProjectionError::ObjectAlreadyExists { kind: "policy", .. })
    ));
    let deleted = CandidateProjector::project(
        created.snapshot_arc(),
        identity(),
        MutationIntentId::new(23).unwrap(),
        None,
        EvaluationTarget::Permanent,
        &[FirewallOperation::DeletePolicy { policy }],
    )
    .unwrap();
    assert!(deleted.snapshot().policies.permanent.is_empty());

    let unsupported = FirewallOperation::AddRichRule {
        zone: public(),
        rule: RichRule::parse(r#"rule log prefix="audit" accept"#).unwrap(),
        target: ConfigurationTarget::RuntimeAndPermanent,
    };
    let projection = project(&base, EvaluationTarget::Runtime, &[unsupported]);
    assert!(!projection.unknown_effects()[0].dimensions().is_empty());
    assert!(!format!("{:?}", projection.unknown_effects()[0].object()).is_empty());
}

#[test]
fn policy_scope_and_runtime_to_permanent_paths_are_exact() {
    let mut observed = snapshot();
    let policy = PolicyName::parse("gateway-ingress").unwrap();
    let mut details = PolicyDetails::empty(policy.clone());
    details.ingress_zones = vec!["ANY".to_owned()];
    details.egress_zones = vec!["HOST".to_owned()];
    observed
        .policies
        .runtime
        .insert(policy.clone(), details.clone());
    observed.policies.permanent.insert(policy.clone(), details);
    let base = Arc::new(observed);
    let service = ServiceName::parse("mysql").unwrap();
    let policy_set = fwdeck::domain::PolicySetName::parse("gateway").unwrap();

    let runtime = project(
        &base,
        EvaluationTarget::Runtime,
        &[
            FirewallOperation::AddPolicyService {
                policy: policy.clone(),
                service: service.clone(),
                target: ConfigurationTarget::Runtime,
            },
            FirewallOperation::SetPolicySetEnabled {
                policy_set: policy_set.clone(),
                enabled: false,
                target: ConfigurationTarget::Runtime,
            },
        ],
    );
    assert!(
        runtime.snapshot().policies.runtime[&policy]
            .services
            .contains(&service)
    );
    assert!(runtime.snapshot().policies.runtime[&policy].disabled);

    let permanent = project(
        &base,
        EvaluationTarget::Permanent,
        &[
            FirewallOperation::AddPolicyService {
                policy: policy.clone(),
                service,
                target: ConfigurationTarget::Permanent,
            },
            FirewallOperation::SetPolicySetEnabled {
                policy_set,
                enabled: false,
                target: ConfigurationTarget::Permanent,
            },
        ],
    );
    assert!(permanent.snapshot().policies.permanent[&policy].disabled);

    let copied = project(
        &base,
        EvaluationTarget::Permanent,
        &[FirewallOperation::RuntimeToPermanent],
    );
    assert!(!copied.snapshot().policies.permanent[&policy].active);
}

#[test]
fn unsupported_ipset_effects_are_scoped_before_global_copy() {
    let base = Arc::new(snapshot());
    let name = fwdeck::domain::IpSetName::parse("blocked").unwrap();
    let entry = fwdeck::domain::IpSetEntry::parse("203.0.113.9").unwrap();
    let runtime_only = FirewallOperation::AddIpSetEntry {
        name: name.clone(),
        entry: entry.clone(),
        target: ConfigurationTarget::Runtime,
    };
    let runtime = project(&base, EvaluationTarget::Runtime, &[runtime_only]);
    assert_eq!(runtime.unknown_effects().len(), 1);

    let both = FirewallOperation::AddIpSetEntry {
        name,
        entry,
        target: ConfigurationTarget::RuntimeAndPermanent,
    };
    let permanent = project(&base, EvaluationTarget::Permanent, &[both]);
    assert_eq!(permanent.unknown_effects().len(), 1);
}

#[test]
fn every_projection_error_has_stable_operator_text() {
    let errors = [
        fwdeck::domain::CandidateProjectionError::OperationEncoding { operation_index: 4 },
        fwdeck::domain::CandidateProjectionError::MissingZone {
            target: "runtime",
            zone: public(),
        },
        fwdeck::domain::CandidateProjectionError::MissingPolicy {
            target: "permanent",
            policy: PolicyName::parse("policy").unwrap(),
        },
        fwdeck::domain::CandidateProjectionError::MissingServiceDefinition { service: ssh() },
        fwdeck::domain::CandidateProjectionError::ObjectAlreadyExists {
            kind: "zone",
            name: "public".to_owned(),
        },
    ];
    assert!(errors.iter().all(|error| !error.to_string().is_empty()));
}

#[test]
fn exact_zone_operations_propagate_missing_zone_without_mutating_authority() {
    let base = Arc::new(snapshot());
    let before = (*base).clone();
    let missing = ZoneName::parse("missing-zone").unwrap();
    let operations = [
        FirewallOperation::AddService {
            zone: missing.clone(),
            service: ssh(),
            target: ConfigurationTarget::Runtime,
        },
        FirewallOperation::AddTemporaryService {
            zone: missing.clone(),
            service: ssh(),
            seconds: 60,
        },
        FirewallOperation::RemoveService {
            zone: missing.clone(),
            service: ssh(),
            target: ConfigurationTarget::Runtime,
        },
        FirewallOperation::RemovePort {
            zone: missing.clone(),
            port: "22/tcp".parse().unwrap(),
            target: ConfigurationTarget::Runtime,
        },
        FirewallOperation::SetMasquerade {
            zone: missing.clone(),
            enabled: true,
            target: ConfigurationTarget::Runtime,
        },
        FirewallOperation::SetForward {
            zone: missing,
            enabled: true,
            target: ConfigurationTarget::Runtime,
        },
    ];

    for operation in operations {
        let error = CandidateProjector::project(
            &base,
            identity(),
            MutationIntentId::new(31).unwrap(),
            None,
            EvaluationTarget::Runtime,
            &[operation],
        )
        .unwrap_err();
        assert!(matches!(
            error,
            fwdeck::domain::CandidateProjectionError::MissingZone {
                target: "runtime",
                ..
            }
        ));
        assert_eq!(*base, before);
    }
}
