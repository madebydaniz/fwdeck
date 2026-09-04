//! Pure domain types for firewalld state. No I/O, no async, no UI dependencies.

pub mod address;
pub mod capability;
pub mod dependency;
pub mod direct_migration;
pub mod explain;
pub mod ids;
#[cfg(test)]
pub mod mock;
pub mod observation;
pub mod operation;
pub mod operation_effect;
pub mod policy;
pub mod policy_set;
pub mod port;
pub mod proposal;
pub mod restore;
pub mod rich_rule;
pub mod service;
pub mod snapshot;
pub mod traffic_test;
pub mod zone;

pub use address::{AddressFamily, IpSetEntry, SourceAddress};
pub use capability::{
    FeatureSupport, FirewalldFeature, SemanticCapabilityKind, SemanticCapabilityMatrix,
};
pub use dependency::{PolicyDependency, PolicyDependencyGraph, PolicyDependencyResource};
pub use direct_migration::{
    DirectChain, DirectMigrationError, DirectPolicyMigration, DirectRuleTranslation,
    translate_direct_rule,
};
pub use ids::{
    IcmpType, InterfaceName, IpProtocol, IpSetName, PolicyName, PolicySetName, ServiceName,
    ValidationError, ZoneName,
};
pub use observation::{
    ChainCounter, LogAction, LogEntry, RefreshObservation, RefreshSection,
    RefreshSectionObservation,
};
pub use operation::{FirewallOperation, OperationError};
pub use operation_effect::{
    AffectedObject, OperationEffect, OperationEffectSupport, OperationTargetSequence,
    PartialApplicationPolicy, PolicyZoneDirection, TemporalBehavior, TrafficDimension,
    TrafficIrrelevanceProof, UnsupportedOperationReason,
};
pub use policy::{PolicyDetails, PolicyTarget};
pub use policy_set::{PolicySetDetails, PolicySetScope, PolicySetState};
pub use port::{ForwardPort, PortNumber, PortRange, PortSelector, PortSpec, Protocol};
pub use proposal::{DeniedFlow, ProposalError};
pub use rich_rule::{
    RichRule, RichRuleAction, RichRuleAddressMatch, RichRuleAnalysis, RichRuleExpression,
    RichRuleMalformed, RichRuleUnsupported,
};
pub use service::{
    MAX_SERVICE_INCLUDE_DEPTH, ServiceDefinition, ServiceDestination, ServiceModuleName,
    ServiceResolution, ServiceResolutionFailure, resolve_service_includes,
};
pub use snapshot::{
    ConfigurationTarget, DegradedSection, FirewallSnapshot, FirewallStatus, IpSetInfo, LogDenied,
    NetfilterBackend, Scoped, SnapshotSection,
};
pub use traffic_test::{
    CandidateIdentity, EvaluationContext, EvaluationPhase, EvaluationPlanId,
    EvaluationSnapshotIdentity, EvaluationTarget, FirewallDecision, MAX_SCENARIOS_PER_SUITE,
    MAX_TRACE_STEPS, MAX_TRAFFIC_NAME_BYTES, MAX_TRAFFIC_NOTE_BYTES, MAX_TRAFFIC_REPORT_BYTES,
    MutationIntentId, OrderedOperationDigest, RulePriority, RulePriorityError, TraceObjectRef,
    TrafficConnectionState, TrafficDestination, TrafficDirection, TrafficExpectation,
    TrafficReportError, TrafficScenario, TrafficScenarioId, TrafficSeverity, TrafficSuite,
    TrafficSuiteId, TrafficSuiteRevision, TrafficTestReport, TrafficTestResult, TrafficTestRunId,
    TrafficTestStatus, TrafficTestSummary, TrafficTraceOutcome, TrafficTraceStage,
    TrafficTraceStep, TrafficTransport, TrafficValidationError, UnknownReason,
};
pub use zone::{ActiveZone, ZoneDetails, ZoneTarget};
