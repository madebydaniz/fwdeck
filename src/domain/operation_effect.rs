//! Exhaustive traffic-testing metadata for every firewall mutation.

use super::{
    ConfigurationTarget, FirewallOperation, ForwardPort, IcmpType, InterfaceName, IpProtocol,
    IpSetEntry, IpSetName, PolicyName, PolicySetName, PortSpec, RichRule, RichRuleAnalysis,
    ServiceName, SourceAddress, ZoneName,
};

/// Whether a mutation can be represented honestly by the traffic-test projector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationEffectSupport {
    /// The selected snapshot target has one deterministic transition.
    SupportedExact,
    /// The transition is exact only at the stated evaluation instant.
    SupportedAtEvaluationInstant,
    /// The operation replaces one complete configuration from another.
    GlobalTransform,
    /// The mutation cannot change a traffic verdict for the typed reason.
    TrafficIrrelevant(TrafficIrrelevanceProof),
    /// The mutation may affect traffic but its transition is not modeled exactly.
    UnsupportedRelevant(UnsupportedOperationReason),
}

/// Typed proof that an operation does not affect packet decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficIrrelevanceProof {
    /// A logging-only effect with no configuration lifecycle side effect.
    LoggingSideEffectOnly,
}

/// Why a traffic-relevant mutation cannot be projected exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedOperationReason {
    /// The rich-rule parser rejected or deliberately does not model the rule.
    RichRuleSemantics,
    /// MAC-based zone selection is outside the approved address model.
    MacSourceBinding,
    /// IP-set membership and matching are not yet part of the exact projector.
    IpSetSemantics,
    /// Direct-rule and policy precedence cannot be projected as one exact transition.
    DirectRuleMigration,
}

/// Ordered configuration targets touched by an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationTargetSequence {
    /// Live runtime configuration only.
    Runtime,
    /// Stored permanent configuration only.
    Permanent,
    /// Runtime first, followed by permanent configuration.
    RuntimeThenPermanent,
    /// One global backend step affects runtime and permanent configuration together.
    RuntimeAndPermanent,
    /// Reload replaces runtime from permanent configuration.
    RuntimeFromPermanent,
    /// Runtime-to-permanent replaces permanent from runtime configuration.
    PermanentFromRuntime,
}

/// Traffic-relevant time behavior of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporalBehavior {
    /// The transition is immediate within its selected configuration target.
    Immediate,
    /// The permanent transition is stored now and activates at reload.
    StoredUntilReload,
    /// The runtime transition expires after this many seconds.
    ExpiresAfterSeconds(u32),
    /// One complete configuration replaces another at one lifecycle boundary.
    GlobalReplacement,
    /// The operation has no effect on traffic decisions.
    NoTrafficDecisionEffect,
}

/// How a backend partial application must be handled by projection code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartialApplicationPolicy {
    /// The operation has one mutation step; no partial-success projection exists.
    SingleStep,
    /// Executed steps must be reconciled against a fresh authoritative snapshot.
    ReconcileExecutedSteps,
}

/// One traffic dimension that an operation can alter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficDimension {
    /// Ingress or egress zone selection.
    ZoneSelection,
    /// Named service allowance or expansion.
    Service,
    /// Destination port matching.
    DestinationPort,
    /// Source port matching.
    SourcePort,
    /// Raw IP protocol matching.
    Protocol,
    /// Zone masquerading or NAT behavior.
    Masquerade,
    /// Intra-zone or port-forwarding behavior.
    Forwarding,
    /// ICMP blocking or inversion.
    Icmp,
    /// Rich-rule matching and decision behavior.
    RichRule,
    /// A zone's terminal target decision.
    ZoneDecision,
    /// A policy's selection or terminal decision.
    Policy,
    /// A custom service definition.
    ServiceDefinition,
    /// IP-set definition or membership.
    IpSet,
    /// Global panic-mode decision.
    PanicMode,
    /// Whole-configuration lifecycle semantics.
    GlobalConfiguration,
    /// Diagnostics with no packet-decision effect.
    Observability,
}

/// Direction of a policy-zone binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyZoneDirection {
    /// Policy ingress zone.
    Ingress,
    /// Policy egress zone.
    Egress,
}

/// Stable identity of the firewall object affected by one operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AffectedObject {
    /// A zone object or zone-wide property.
    Zone(ZoneName),
    /// A named service enabled within a zone.
    ZoneService {
        /// Owning zone.
        zone: ZoneName,
        /// Referenced service.
        service: ServiceName,
    },
    /// A destination port within a zone.
    ZonePort {
        /// Owning zone.
        zone: ZoneName,
        /// Port specification.
        port: PortSpec,
    },
    /// A source port within a zone.
    ZoneSourcePort {
        /// Owning zone.
        zone: ZoneName,
        /// Port specification.
        port: PortSpec,
    },
    /// A raw IP protocol within a zone.
    ZoneProtocol {
        /// Owning zone.
        zone: ZoneName,
        /// Protocol name.
        protocol: IpProtocol,
    },
    /// A port-forwarding rule within a zone.
    ZoneForwardPort {
        /// Owning zone.
        zone: ZoneName,
        /// Forwarding rule.
        forward: ForwardPort,
    },
    /// A rich rule within a zone.
    ZoneRichRule {
        /// Owning zone.
        zone: ZoneName,
        /// Original validated rule.
        rule: RichRule,
    },
    /// An interface-to-zone binding.
    ZoneInterface {
        /// Owning zone.
        zone: ZoneName,
        /// Interface identity.
        interface: InterfaceName,
    },
    /// A source-to-zone binding.
    ZoneSource {
        /// Owning zone.
        zone: ZoneName,
        /// Source identity.
        source: SourceAddress,
    },
    /// An ICMP block within a zone.
    ZoneIcmp {
        /// Owning zone.
        zone: ZoneName,
        /// ICMP type.
        icmp: IcmpType,
    },
    /// A custom service definition.
    ServiceDefinition(ServiceName),
    /// One port within a custom service definition.
    ServiceDefinitionPort {
        /// Service identity.
        service: ServiceName,
        /// Port specification.
        port: PortSpec,
    },
    /// A policy object or policy-wide property.
    Policy(PolicyName),
    /// A policy-zone binding.
    PolicyZone {
        /// Policy identity.
        policy: PolicyName,
        /// Binding direction.
        direction: PolicyZoneDirection,
        /// Zone or `ANY`/`HOST` pseudo-zone.
        zone: String,
    },
    /// A named service enabled within a policy.
    PolicyService {
        /// Policy identity.
        policy: PolicyName,
        /// Referenced service.
        service: ServiceName,
    },
    /// A predefined policy-set identity.
    PolicySet(PolicySetName),
    /// An IP-set definition.
    IpSet(IpSetName),
    /// One member of an IP set.
    IpSetEntry {
        /// IP-set identity.
        name: IpSetName,
        /// Member identity.
        entry: IpSetEntry,
    },
    /// Firewalld panic mode.
    PanicMode,
    /// Whole-firewall lifecycle or global setting.
    Global,
}

/// Complete projection metadata for one firewall operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationEffect {
    /// Projection support category.
    pub support: OperationEffectSupport,
    /// Ordered configuration targets.
    pub targets: OperationTargetSequence,
    /// Stable affected object identity.
    pub object: AffectedObject,
    /// Traffic dimensions potentially changed by the operation.
    pub dimensions: Vec<TrafficDimension>,
    /// Time-dependent behavior.
    pub temporal: TemporalBehavior,
    /// Required handling if backend execution is not fully applied.
    pub partial_application: PartialApplicationPolicy,
}

impl OperationEffect {
    #[allow(clippy::too_many_lines)] // one exhaustive arm per operation family
    pub(crate) fn classify(operation: &FirewallOperation) -> Self {
        match operation {
            FirewallOperation::AddService {
                zone,
                service,
                target,
            }
            | FirewallOperation::RemoveService {
                zone,
                service,
                target,
            } => exact(
                *target,
                AffectedObject::ZoneService {
                    zone: zone.clone(),
                    service: service.clone(),
                },
                vec![TrafficDimension::Service],
            ),
            FirewallOperation::AddTemporaryService {
                zone,
                service,
                seconds,
            } => Self {
                support: OperationEffectSupport::SupportedAtEvaluationInstant,
                targets: OperationTargetSequence::Runtime,
                object: AffectedObject::ZoneService {
                    zone: zone.clone(),
                    service: service.clone(),
                },
                dimensions: vec![TrafficDimension::Service],
                temporal: TemporalBehavior::ExpiresAfterSeconds(*seconds),
                partial_application: PartialApplicationPolicy::SingleStep,
            },
            FirewallOperation::AddPort { zone, port, target }
            | FirewallOperation::RemovePort { zone, port, target } => exact(
                *target,
                AffectedObject::ZonePort {
                    zone: zone.clone(),
                    port: *port,
                },
                vec![TrafficDimension::DestinationPort],
            ),
            FirewallOperation::SetDefaultZone { zone } => Self {
                support: OperationEffectSupport::SupportedExact,
                targets: OperationTargetSequence::RuntimeAndPermanent,
                object: AffectedObject::Zone(zone.clone()),
                dimensions: vec![TrafficDimension::ZoneSelection],
                temporal: TemporalBehavior::Immediate,
                partial_application: PartialApplicationPolicy::SingleStep,
            },
            FirewallOperation::SetMasquerade { zone, target, .. } => exact(
                *target,
                AffectedObject::Zone(zone.clone()),
                vec![TrafficDimension::Masquerade],
            ),
            FirewallOperation::SetZoneTarget { zone, .. } => exact(
                ConfigurationTarget::Permanent,
                AffectedObject::Zone(zone.clone()),
                vec![TrafficDimension::ZoneDecision],
            ),
            FirewallOperation::AddSourcePort { zone, port, target }
            | FirewallOperation::RemoveSourcePort { zone, port, target } => exact(
                *target,
                AffectedObject::ZoneSourcePort {
                    zone: zone.clone(),
                    port: *port,
                },
                vec![TrafficDimension::SourcePort],
            ),
            FirewallOperation::AddProtocol {
                zone,
                protocol,
                target,
            }
            | FirewallOperation::RemoveProtocol {
                zone,
                protocol,
                target,
            } => exact(
                *target,
                AffectedObject::ZoneProtocol {
                    zone: zone.clone(),
                    protocol: protocol.clone(),
                },
                vec![TrafficDimension::Protocol],
            ),
            FirewallOperation::SetForward { zone, target, .. } => exact(
                *target,
                AffectedObject::Zone(zone.clone()),
                vec![TrafficDimension::Forwarding],
            ),
            FirewallOperation::SetIcmpBlockInversion { zone, target, .. } => exact(
                *target,
                AffectedObject::Zone(zone.clone()),
                vec![TrafficDimension::Icmp],
            ),
            FirewallOperation::AddForwardPort {
                zone,
                forward,
                target,
            }
            | FirewallOperation::RemoveForwardPort {
                zone,
                forward,
                target,
            } => exact(
                *target,
                AffectedObject::ZoneForwardPort {
                    zone: zone.clone(),
                    forward: forward.clone(),
                },
                vec![
                    TrafficDimension::Forwarding,
                    TrafficDimension::DestinationPort,
                ],
            ),
            FirewallOperation::AddRichRule { zone, rule, target }
            | FirewallOperation::RemoveRichRule { zone, rule, target } => classified(
                rich_rule_support(rule),
                *target,
                AffectedObject::ZoneRichRule {
                    zone: zone.clone(),
                    rule: rule.clone(),
                },
                vec![TrafficDimension::RichRule],
            ),
            FirewallOperation::AddInterface {
                zone,
                interface,
                target,
            }
            | FirewallOperation::RemoveInterface {
                zone,
                interface,
                target,
            } => exact(
                *target,
                AffectedObject::ZoneInterface {
                    zone: zone.clone(),
                    interface: interface.clone(),
                },
                vec![TrafficDimension::ZoneSelection],
            ),
            FirewallOperation::AddSource {
                zone,
                source,
                target,
            }
            | FirewallOperation::RemoveSource {
                zone,
                source,
                target,
            } => classified(
                source_binding_support(source),
                *target,
                AffectedObject::ZoneSource {
                    zone: zone.clone(),
                    source: source.clone(),
                },
                vec![TrafficDimension::ZoneSelection],
            ),
            FirewallOperation::AddIcmpBlock { zone, icmp, target }
            | FirewallOperation::RemoveIcmpBlock { zone, icmp, target } => exact(
                *target,
                AffectedObject::ZoneIcmp {
                    zone: zone.clone(),
                    icmp: icmp.clone(),
                },
                vec![TrafficDimension::Icmp],
            ),
            FirewallOperation::CreateService { service }
            | FirewallOperation::DeleteService { service } => exact(
                ConfigurationTarget::Permanent,
                AffectedObject::ServiceDefinition(service.clone()),
                vec![TrafficDimension::ServiceDefinition],
            ),
            FirewallOperation::AddServicePort { service, port }
            | FirewallOperation::RemoveServicePort { service, port } => exact(
                ConfigurationTarget::Permanent,
                AffectedObject::ServiceDefinitionPort {
                    service: service.clone(),
                    port: *port,
                },
                vec![
                    TrafficDimension::ServiceDefinition,
                    TrafficDimension::DestinationPort,
                ],
            ),
            FirewallOperation::CreatePolicy { policy }
            | FirewallOperation::DeletePolicy { policy }
            | FirewallOperation::SetPolicyTarget { policy, .. } => exact(
                ConfigurationTarget::Permanent,
                AffectedObject::Policy(policy.clone()),
                vec![TrafficDimension::Policy],
            ),
            FirewallOperation::MigrateDirectRule { migration } => classified_with_partial(
                OperationEffectSupport::UnsupportedRelevant(
                    UnsupportedOperationReason::DirectRuleMigration,
                ),
                ConfigurationTarget::Permanent,
                AffectedObject::Policy(migration.policy().clone()),
                vec![TrafficDimension::Policy, TrafficDimension::RichRule],
                PartialApplicationPolicy::ReconcileExecutedSteps,
            ),
            FirewallOperation::AddPolicyIngressZone { policy, zone } => exact(
                ConfigurationTarget::Permanent,
                AffectedObject::PolicyZone {
                    policy: policy.clone(),
                    direction: PolicyZoneDirection::Ingress,
                    zone: zone.clone(),
                },
                vec![TrafficDimension::Policy, TrafficDimension::ZoneSelection],
            ),
            FirewallOperation::AddPolicyEgressZone { policy, zone } => exact(
                ConfigurationTarget::Permanent,
                AffectedObject::PolicyZone {
                    policy: policy.clone(),
                    direction: PolicyZoneDirection::Egress,
                    zone: zone.clone(),
                },
                vec![TrafficDimension::Policy, TrafficDimension::ZoneSelection],
            ),
            FirewallOperation::AddPolicyService {
                policy,
                service,
                target,
            }
            | FirewallOperation::RemovePolicyService {
                policy,
                service,
                target,
            } => exact(
                *target,
                AffectedObject::PolicyService {
                    policy: policy.clone(),
                    service: service.clone(),
                },
                vec![TrafficDimension::Policy, TrafficDimension::Service],
            ),
            FirewallOperation::SetPolicySetEnabled {
                policy_set, target, ..
            } => classified_with_partial(
                OperationEffectSupport::SupportedExact,
                *target,
                AffectedObject::PolicySet(policy_set.clone()),
                vec![TrafficDimension::Policy],
                PartialApplicationPolicy::ReconcileExecutedSteps,
            ),
            FirewallOperation::CreateIpSet { name, .. }
            | FirewallOperation::DeleteIpSet { name } => classified(
                OperationEffectSupport::UnsupportedRelevant(
                    UnsupportedOperationReason::IpSetSemantics,
                ),
                ConfigurationTarget::Permanent,
                AffectedObject::IpSet(name.clone()),
                vec![TrafficDimension::IpSet],
            ),
            FirewallOperation::AddIpSetEntry {
                name,
                entry,
                target,
            }
            | FirewallOperation::RemoveIpSetEntry {
                name,
                entry,
                target,
            } => classified(
                OperationEffectSupport::UnsupportedRelevant(
                    UnsupportedOperationReason::IpSetSemantics,
                ),
                *target,
                AffectedObject::IpSetEntry {
                    name: name.clone(),
                    entry: entry.clone(),
                },
                vec![TrafficDimension::IpSet],
            ),
            FirewallOperation::CreateZone { zone } | FirewallOperation::DeleteZone { zone } => {
                exact(
                    ConfigurationTarget::Permanent,
                    AffectedObject::Zone(zone.clone()),
                    vec![
                        TrafficDimension::ZoneSelection,
                        TrafficDimension::ZoneDecision,
                    ],
                )
            }
            FirewallOperation::SetPanicMode { .. } => exact(
                ConfigurationTarget::Runtime,
                AffectedObject::PanicMode,
                vec![TrafficDimension::PanicMode],
            ),
            FirewallOperation::RuntimeToPermanent => Self {
                support: OperationEffectSupport::GlobalTransform,
                targets: OperationTargetSequence::PermanentFromRuntime,
                object: AffectedObject::Global,
                dimensions: vec![TrafficDimension::GlobalConfiguration],
                temporal: TemporalBehavior::GlobalReplacement,
                partial_application: PartialApplicationPolicy::SingleStep,
            },
            FirewallOperation::SetLogDenied { .. } => Self {
                support: OperationEffectSupport::GlobalTransform,
                targets: OperationTargetSequence::RuntimeFromPermanent,
                object: AffectedObject::Global,
                dimensions: vec![
                    TrafficDimension::Observability,
                    TrafficDimension::GlobalConfiguration,
                ],
                temporal: TemporalBehavior::GlobalReplacement,
                partial_application: PartialApplicationPolicy::SingleStep,
            },
            FirewallOperation::Reload => Self {
                support: OperationEffectSupport::GlobalTransform,
                targets: OperationTargetSequence::RuntimeFromPermanent,
                object: AffectedObject::Global,
                dimensions: vec![TrafficDimension::GlobalConfiguration],
                temporal: TemporalBehavior::GlobalReplacement,
                partial_application: PartialApplicationPolicy::SingleStep,
            },
        }
    }
}

fn exact(
    target: ConfigurationTarget,
    object: AffectedObject,
    dimensions: Vec<TrafficDimension>,
) -> OperationEffect {
    classified(
        OperationEffectSupport::SupportedExact,
        target,
        object,
        dimensions,
    )
}

fn classified(
    support: OperationEffectSupport,
    target: ConfigurationTarget,
    object: AffectedObject,
    dimensions: Vec<TrafficDimension>,
) -> OperationEffect {
    classified_with_partial(support, target, object, dimensions, partial_policy(target))
}

fn classified_with_partial(
    support: OperationEffectSupport,
    target: ConfigurationTarget,
    object: AffectedObject,
    dimensions: Vec<TrafficDimension>,
    partial_application: PartialApplicationPolicy,
) -> OperationEffect {
    OperationEffect {
        support,
        targets: target_sequence(target),
        object,
        dimensions,
        temporal: temporal_behavior(target),
        partial_application,
    }
}

const fn target_sequence(target: ConfigurationTarget) -> OperationTargetSequence {
    match target {
        ConfigurationTarget::Runtime => OperationTargetSequence::Runtime,
        ConfigurationTarget::Permanent => OperationTargetSequence::Permanent,
        ConfigurationTarget::RuntimeAndPermanent => OperationTargetSequence::RuntimeThenPermanent,
    }
}

const fn temporal_behavior(target: ConfigurationTarget) -> TemporalBehavior {
    match target {
        ConfigurationTarget::Permanent => TemporalBehavior::StoredUntilReload,
        ConfigurationTarget::Runtime | ConfigurationTarget::RuntimeAndPermanent => {
            TemporalBehavior::Immediate
        }
    }
}

const fn partial_policy(target: ConfigurationTarget) -> PartialApplicationPolicy {
    match target {
        ConfigurationTarget::Runtime | ConfigurationTarget::Permanent => {
            PartialApplicationPolicy::SingleStep
        }
        ConfigurationTarget::RuntimeAndPermanent => {
            PartialApplicationPolicy::ReconcileExecutedSteps
        }
    }
}

fn rich_rule_support(rule: &RichRule) -> OperationEffectSupport {
    match rule.analyze() {
        RichRuleAnalysis::Supported(_) => OperationEffectSupport::SupportedExact,
        RichRuleAnalysis::Unsupported(_) | RichRuleAnalysis::Malformed(_) => {
            OperationEffectSupport::UnsupportedRelevant(
                UnsupportedOperationReason::RichRuleSemantics,
            )
        }
    }
}

const fn source_binding_support(source: &SourceAddress) -> OperationEffectSupport {
    match source {
        SourceAddress::Ip { .. } => OperationEffectSupport::SupportedExact,
        SourceAddress::Mac(_) => OperationEffectSupport::UnsupportedRelevant(
            UnsupportedOperationReason::MacSourceBinding,
        ),
        SourceAddress::IpSet(_) => {
            OperationEffectSupport::UnsupportedRelevant(UnsupportedOperationReason::IpSetSemantics)
        }
    }
}

#[cfg(test)]
#[allow(clippy::too_many_lines, clippy::unwrap_used)]
mod tests {
    use crate::application::ports::{
        FirewallError, OperationOutcome, OperationProjectionStatus, StepReport,
    };
    use crate::domain::{
        ConfigurationTarget, FirewallOperation, IcmpType, InterfaceName, IpProtocol, IpSetEntry,
        IpSetName, LogDenied, PolicyName, PolicySetName, PolicyTarget, PortSpec, RichRule,
        ServiceName, SourceAddress, ZoneName, ZoneTarget, translate_direct_rule,
    };

    use super::{
        AffectedObject, OperationEffectSupport, OperationTargetSequence, PartialApplicationPolicy,
        TemporalBehavior, TrafficDimension, UnsupportedOperationReason,
    };

    fn zone() -> ZoneName {
        ZoneName::parse("public").unwrap()
    }

    fn service() -> ServiceName {
        ServiceName::parse("ssh").unwrap()
    }

    fn policy() -> PolicyName {
        PolicyName::parse("allow-ssh").unwrap()
    }

    fn all_operations() -> Vec<(FirewallOperation, OperationEffectSupport)> {
        let zone = zone();
        let service = service();
        let port: PortSpec = "22/tcp".parse().unwrap();
        let target = ConfigurationTarget::RuntimeAndPermanent;
        let supported_rule = RichRule::parse(
            r#"rule family="ipv4" source address="192.0.2.0/24" service name="ssh" accept"#,
        )
        .unwrap();
        let unsupported_rule = RichRule::parse(
            r#"rule family="ipv4" source ipset="trusted" service name="ssh" accept"#,
        )
        .unwrap();
        let migration = translate_direct_rule("ipv4 filter INPUT 9 -p tcp --dport 12345 -j ACCEPT")
            .unwrap()
            .into_migration(policy());

        vec![
            (
                FirewallOperation::AddService {
                    zone: zone.clone(),
                    service: service.clone(),
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::AddTemporaryService {
                    zone: zone.clone(),
                    service: service.clone(),
                    seconds: 60,
                },
                OperationEffectSupport::SupportedAtEvaluationInstant,
            ),
            (
                FirewallOperation::RemoveService {
                    zone: zone.clone(),
                    service: service.clone(),
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::AddPort {
                    zone: zone.clone(),
                    port,
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::RemovePort {
                    zone: zone.clone(),
                    port,
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::SetDefaultZone { zone: zone.clone() },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::SetMasquerade {
                    zone: zone.clone(),
                    enabled: true,
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::SetZoneTarget {
                    zone: zone.clone(),
                    zone_target: ZoneTarget::Drop,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::AddSourcePort {
                    zone: zone.clone(),
                    port,
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::RemoveSourcePort {
                    zone: zone.clone(),
                    port,
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::AddProtocol {
                    zone: zone.clone(),
                    protocol: IpProtocol::parse("gre").unwrap(),
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::RemoveProtocol {
                    zone: zone.clone(),
                    protocol: IpProtocol::parse("gre").unwrap(),
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::SetForward {
                    zone: zone.clone(),
                    enabled: true,
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::SetIcmpBlockInversion {
                    zone: zone.clone(),
                    enabled: true,
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::AddForwardPort {
                    zone: zone.clone(),
                    forward: "port=8080:proto=tcp:toport=80".parse().unwrap(),
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::RemoveForwardPort {
                    zone: zone.clone(),
                    forward: "port=8080:proto=tcp:toport=80".parse().unwrap(),
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::AddRichRule {
                    zone: zone.clone(),
                    rule: supported_rule,
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::RemoveRichRule {
                    zone: zone.clone(),
                    rule: unsupported_rule,
                    target,
                },
                OperationEffectSupport::UnsupportedRelevant(
                    UnsupportedOperationReason::RichRuleSemantics,
                ),
            ),
            (
                FirewallOperation::AddInterface {
                    zone: zone.clone(),
                    interface: InterfaceName::parse("eth0").unwrap(),
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::RemoveInterface {
                    zone: zone.clone(),
                    interface: InterfaceName::parse("eth0").unwrap(),
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::AddSource {
                    zone: zone.clone(),
                    source: SourceAddress::parse("192.0.2.0/24").unwrap(),
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::RemoveSource {
                    zone: zone.clone(),
                    source: SourceAddress::parse("aa:bb:cc:dd:ee:ff").unwrap(),
                    target,
                },
                OperationEffectSupport::UnsupportedRelevant(
                    UnsupportedOperationReason::MacSourceBinding,
                ),
            ),
            (
                FirewallOperation::AddIcmpBlock {
                    zone: zone.clone(),
                    icmp: IcmpType::parse("echo-request").unwrap(),
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::RemoveIcmpBlock {
                    zone: zone.clone(),
                    icmp: IcmpType::parse("echo-request").unwrap(),
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::CreateService {
                    service: service.clone(),
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::DeleteService {
                    service: service.clone(),
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::AddServicePort {
                    service: service.clone(),
                    port,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::RemoveServicePort {
                    service: service.clone(),
                    port,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::CreatePolicy { policy: policy() },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::MigrateDirectRule { migration },
                OperationEffectSupport::UnsupportedRelevant(
                    UnsupportedOperationReason::DirectRuleMigration,
                ),
            ),
            (
                FirewallOperation::DeletePolicy { policy: policy() },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::SetPolicyTarget {
                    policy: policy(),
                    policy_target: PolicyTarget::Drop,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::AddPolicyIngressZone {
                    policy: policy(),
                    zone: "ANY".to_owned(),
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::AddPolicyEgressZone {
                    policy: policy(),
                    zone: "HOST".to_owned(),
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::AddPolicyService {
                    policy: policy(),
                    service: service.clone(),
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::RemovePolicyService {
                    policy: policy(),
                    service: service.clone(),
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::SetPolicySetEnabled {
                    policy_set: PolicySetName::parse("gateway").unwrap(),
                    enabled: true,
                    target,
                },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::CreateIpSet {
                    name: IpSetName::parse("trusted").unwrap(),
                    kind: "hash:ip".to_owned(),
                },
                OperationEffectSupport::UnsupportedRelevant(
                    UnsupportedOperationReason::IpSetSemantics,
                ),
            ),
            (
                FirewallOperation::DeleteIpSet {
                    name: IpSetName::parse("trusted").unwrap(),
                },
                OperationEffectSupport::UnsupportedRelevant(
                    UnsupportedOperationReason::IpSetSemantics,
                ),
            ),
            (
                FirewallOperation::AddIpSetEntry {
                    name: IpSetName::parse("trusted").unwrap(),
                    entry: IpSetEntry::parse("192.0.2.10").unwrap(),
                    target,
                },
                OperationEffectSupport::UnsupportedRelevant(
                    UnsupportedOperationReason::IpSetSemantics,
                ),
            ),
            (
                FirewallOperation::RemoveIpSetEntry {
                    name: IpSetName::parse("trusted").unwrap(),
                    entry: IpSetEntry::parse("192.0.2.10").unwrap(),
                    target,
                },
                OperationEffectSupport::UnsupportedRelevant(
                    UnsupportedOperationReason::IpSetSemantics,
                ),
            ),
            (
                FirewallOperation::CreateZone { zone: zone.clone() },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::DeleteZone { zone: zone.clone() },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::SetPanicMode { enabled: true },
                OperationEffectSupport::SupportedExact,
            ),
            (
                FirewallOperation::RuntimeToPermanent,
                OperationEffectSupport::GlobalTransform,
            ),
            (
                FirewallOperation::SetLogDenied {
                    value: LogDenied::All,
                },
                OperationEffectSupport::GlobalTransform,
            ),
            (
                FirewallOperation::Reload,
                OperationEffectSupport::GlobalTransform,
            ),
        ]
    }

    #[test]
    fn every_firewall_operation_has_an_explicit_effect_classification() {
        let operations = all_operations();
        assert_eq!(
            operations.len(),
            47,
            "fixture must cover every current variant"
        );

        for (operation, expected_support) in operations {
            let effect = operation.effect();
            assert_eq!(
                effect.support, expected_support,
                "unexpected effect classification for {operation:?}"
            );
            assert!(!effect.dimensions.is_empty());
        }
    }

    #[test]
    fn target_sequence_preserves_runtime_permanent_execution_order() {
        for (target, expected) in [
            (
                ConfigurationTarget::Runtime,
                OperationTargetSequence::Runtime,
            ),
            (
                ConfigurationTarget::Permanent,
                OperationTargetSequence::Permanent,
            ),
            (
                ConfigurationTarget::RuntimeAndPermanent,
                OperationTargetSequence::RuntimeThenPermanent,
            ),
        ] {
            let effect = FirewallOperation::AddService {
                zone: zone(),
                service: service(),
                target,
            }
            .effect();
            assert_eq!(effect.targets, expected);
        }
    }

    #[test]
    fn effect_keeps_identity_dimensions_temporal_and_partial_semantics() {
        let temporary = FirewallOperation::AddTemporaryService {
            zone: zone(),
            service: service(),
            seconds: 90,
        }
        .effect();
        assert_eq!(
            temporary.object,
            AffectedObject::ZoneService {
                zone: zone(),
                service: service(),
            }
        );
        assert_eq!(temporary.dimensions, vec![TrafficDimension::Service]);
        assert_eq!(
            temporary.temporal,
            TemporalBehavior::ExpiresAfterSeconds(90)
        );
        assert_eq!(
            temporary.partial_application,
            PartialApplicationPolicy::SingleStep
        );

        let both = FirewallOperation::AddPort {
            zone: zone(),
            port: "443/tcp".parse().unwrap(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        }
        .effect();
        assert_eq!(
            both.partial_application,
            PartialApplicationPolicy::ReconcileExecutedSteps
        );

        let reload = FirewallOperation::Reload.effect();
        assert_eq!(
            reload.targets,
            OperationTargetSequence::RuntimeFromPermanent
        );
        assert_eq!(reload.temporal, TemporalBehavior::GlobalReplacement);

        let default_zone = FirewallOperation::SetDefaultZone { zone: zone() }.effect();
        assert_eq!(
            default_zone.targets,
            OperationTargetSequence::RuntimeAndPermanent
        );
        assert_eq!(
            default_zone.partial_application,
            PartialApplicationPolicy::SingleStep
        );
    }

    #[test]
    fn partial_or_indeterminate_outcomes_never_claim_full_projection() {
        let operation = FirewallOperation::AddService {
            zone: zone(),
            service: service(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        let succeeded = StepReport {
            target: "runtime",
            invocation: vec!["addService".to_owned()],
            result: Ok(()),
        };
        let failed = StepReport {
            target: "permanent",
            invocation: vec!["addService".to_owned()],
            result: Err(FirewallError::Process("fixture failure".to_owned())),
        };

        let partial = OperationOutcome::PartiallyApplied {
            operation: operation.clone(),
            steps: vec![succeeded.clone(), failed.clone()],
            rollback_hint: None,
        };
        assert_eq!(
            partial.projection_status(),
            OperationProjectionStatus::RequiresAuthoritativeReconciliation
        );

        let indeterminate = OperationOutcome::Indeterminate {
            operation,
            steps: vec![succeeded, failed],
        };
        assert_eq!(
            indeterminate.projection_status(),
            OperationProjectionStatus::RequiresAuthoritativeReconciliation
        );

        let applied = OperationOutcome::Applied {
            operation: FirewallOperation::Reload,
            steps: vec![],
        };
        assert_eq!(
            applied.projection_status(),
            OperationProjectionStatus::FullyApplied
        );

        let failed = OperationOutcome::Failed {
            operation: FirewallOperation::Reload,
            steps: vec![],
        };
        assert_eq!(
            failed.projection_status(),
            OperationProjectionStatus::NotApplied
        );
    }
}
