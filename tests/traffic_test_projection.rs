#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::sync::Arc;

use fwdeck::domain::{
    CandidateProjector, ConfigurationTarget, EvaluationPlanId, EvaluationSnapshotIdentity,
    EvaluationTarget, FirewallOperation, FirewallSnapshot, FirewallStatus, LogDenied,
    MutationIntentId, NetfilterBackend, PolicyDetails, PolicyName, PolicyTarget, PortSpec,
    RichRule, Scoped, ServiceDefinition, ServiceName, UnsupportedOperationReason, ZoneDetails,
    ZoneName,
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
