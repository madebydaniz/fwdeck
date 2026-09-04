//! Truth and trace contracts shared by native traffic-test phases.

use super::{PolicyName, ServiceName, SnapshotSection, ZoneName};

mod evaluator;
mod index;
mod report;
mod scenario;
pub use evaluator::{TrafficEvaluationError, evaluate_scenario};
pub use index::{IndexedZoneBinding, IndexedZoneBindingKind, TrafficEvaluationIndex};
pub use report::{
    CandidateIdentity, EvaluationContext, EvaluationPhase, EvaluationPlanId,
    EvaluationSnapshotIdentity, EvaluationTarget, MAX_TRAFFIC_REPORT_BYTES, MutationIntentId,
    OrderedOperationDigest, TrafficReportError, TrafficTestReport, TrafficTestResult,
    TrafficTestRunId, TrafficTestSummary,
};
pub use scenario::{
    MAX_SCENARIOS_PER_SUITE, MAX_TRAFFIC_NAME_BYTES, MAX_TRAFFIC_NOTE_BYTES,
    TrafficConnectionState, TrafficDestination, TrafficDirection, TrafficScenario,
    TrafficScenarioId, TrafficSeverity, TrafficSuite, TrafficSuiteId, TrafficSuiteRevision,
    TrafficTransport, TrafficValidationError,
};

/// Maximum ordered trace steps retained for one scenario result.
pub const MAX_TRACE_STEPS: usize = 128;

/// Proven firewall decision for the modeled configuration path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallDecision {
    /// The complete supported path proves that traffic is allowed.
    Allow,
    /// A terminal supported rule or target proves that traffic is blocked.
    Block,
    /// The available evidence cannot prove either terminal decision.
    Unknown,
}

/// Operator-declared result expected from a traffic scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficExpectation {
    /// The scenario is expected to be allowed.
    Allow,
    /// The scenario is expected to be blocked.
    Block,
}

/// Comparison status between a proven decision and an operator expectation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficTestStatus {
    /// The proven decision matches the expectation.
    Pass,
    /// The proven decision contradicts the expectation.
    Fail,
    /// The decision is unknown and cannot be compared honestly.
    Indeterminate,
    /// No matching evaluation has completed.
    NotRun,
    /// Historical evidence no longer matches the active context.
    Stale,
}

impl TrafficTestStatus {
    /// Derives a status without converting unknown evidence into pass or fail.
    #[must_use]
    pub const fn from_decision(
        decision: FirewallDecision,
        expectation: TrafficExpectation,
    ) -> Self {
        match (decision, expectation) {
            (FirewallDecision::Unknown, _) => Self::Indeterminate,
            (FirewallDecision::Allow, TrafficExpectation::Allow)
            | (FirewallDecision::Block, TrafficExpectation::Block) => Self::Pass,
            (FirewallDecision::Allow, TrafficExpectation::Block)
            | (FirewallDecision::Block, TrafficExpectation::Allow) => Self::Fail,
        }
    }
}

/// Typed reason that prevents a definitive allow or block decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    /// A required snapshot section or object was not observed completely.
    IncompleteSnapshot,
    /// A relevant rich rule falls outside the supported AST subset.
    UnsupportedRichRule,
    /// A relevant policy construct is not modeled.
    UnsupportedPolicyFeature,
    /// The ingress zone cannot be selected uniquely.
    AmbiguousIngressZone,
    /// The egress zone cannot be selected uniquely.
    AmbiguousEgressZone,
    /// A direction-dependent route could not be observed.
    MissingRouteData,
    /// A staged operation has no exact relevant projection.
    UnsupportedStagedOperation,
    /// A potentially intersecting direct rule cannot be classified safely.
    RelevantDirectRuleUnsupported,
    /// The authoritative snapshot identity no longer matches.
    StaleSnapshot,
    /// The staged plan identity no longer matches.
    StalePlan,
    /// Required semantic capability evidence is unavailable.
    CapabilityUnavailable,
    /// The observed firewalld version predates required behavior.
    VersionUnsupported,
    /// Conflicting equal-priority rules have no proven deterministic order.
    ConflictingEqualPriorityRules,
    /// A referenced service definition is incomplete.
    IncompleteServiceDefinition,
    /// A relevant service field is not modeled.
    UnsupportedServiceFeature,
    /// The requested connection state has no supported model.
    UnsupportedConnectionState,
    /// The requested traffic direction has no supported model.
    UnsupportedDirection,
    /// A relevant mutation effect cannot be represented exactly.
    UnsupportedOperationEffect,
    /// Potentially intersecting rules exist outside the firewalld model.
    ExternalRulesOutsideModel,
    /// The required post-apply rollback guarantee cannot be provided.
    RollbackGuaranteeUnavailable,
}

/// Validated firewalld rule priority. Lower numbers run first.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(transparent)]
pub struct RulePriority(i16);

impl RulePriority {
    /// Validates firewalld's signed 16-bit priority range.
    pub fn new(value: i32) -> Result<Self, RulePriorityError> {
        i16::try_from(value)
            .map(Self)
            .map_err(|_| RulePriorityError::OutOfRange(value))
    }

    /// Returns the validated numeric priority.
    #[must_use]
    pub const fn get(self) -> i16 {
        self.0
    }
}

impl TryFrom<i32> for RulePriority {
    type Error = RulePriorityError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl std::str::FromStr for RulePriority {
    type Err = RulePriorityError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let value = raw
            .parse::<i32>()
            .map_err(|_| RulePriorityError::Invalid(raw.to_owned()))?;
        Self::new(value)
    }
}

/// Invalid priority input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RulePriorityError {
    /// A numeric value is outside firewalld's signed 16-bit range.
    #[error("priority {0} is outside -32768..=32767")]
    OutOfRange(i32),
    /// Text is not a decimal integer.
    #[error("invalid priority `{0}`")]
    Invalid(String),
}

/// Stable stage in the ordered reasoning trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficTraceStage {
    /// Scenario fields were normalized and validated.
    ScenarioNormalization,
    /// Snapshot, plan, suite, or run identities were checked.
    IdentityCheck,
    /// Required semantic capability was checked.
    CapabilityCheck,
    /// Snapshot section or object completeness was checked.
    CompletenessCheck,
    /// Ingress classification was resolved.
    IngressResolution,
    /// Egress classification was resolved.
    EgressResolution,
    /// The direction-specific traffic path was resolved.
    PathResolution,
    /// A referenced service was expanded.
    ServiceExpansion,
    /// An applicable policy was evaluated.
    PolicyEvaluation,
    /// An applicable rich rule was evaluated.
    RichRuleEvaluation,
    /// An ordinary zone primitive was evaluated.
    ZoneEvaluation,
    /// A terminal or continuing target was applied.
    TargetEvaluation,
    /// The firewall decision was reached.
    Decision,
    /// The decision was compared with the expectation.
    ExpectationComparison,
    /// Final status was assigned.
    Status,
}

/// Typed reference to evidence contributing to one trace step.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceObjectRef {
    /// One authoritative snapshot section.
    SnapshotSection(SnapshotSection),
    /// A zone object.
    Zone(ZoneName),
    /// A policy object.
    Policy(PolicyName),
    /// A service object.
    Service(ServiceName),
    /// A rich rule by owning zone and stable snapshot index.
    RichRule {
        /// Owning zone.
        zone: ZoneName,
        /// Position in the immutable observed rule list.
        index: u32,
    },
    /// A direct rule by stable snapshot index.
    DirectRule {
        /// Position in the immutable observed rule list.
        index: u32,
    },
}

/// Typed result of one reasoning stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficTraceOutcome {
    /// The referenced input matched.
    Matched,
    /// The referenced input did not match.
    NotMatched,
    /// The referenced object was selected for the path.
    Selected,
    /// The referenced object was expanded into concrete semantics.
    Expanded,
    /// Evaluation continues after a non-terminal construct.
    Continued,
    /// A proven firewall decision was reached.
    Decision(FirewallDecision),
    /// A final comparison status was assigned.
    Status(TrafficTestStatus),
    /// Evaluation stopped with a typed unknown reason.
    Unknown(UnknownReason),
}

/// One bounded, typed, ordered reasoning step.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrafficTraceStep {
    stage: TrafficTraceStage,
    #[serde(skip_serializing_if = "Option::is_none")]
    object: Option<TraceObjectRef>,
    outcome: TrafficTraceOutcome,
}

impl TrafficTraceStep {
    /// Creates a step without an object reference.
    #[must_use]
    pub const fn new(stage: TrafficTraceStage, outcome: TrafficTraceOutcome) -> Self {
        Self {
            stage,
            object: None,
            outcome,
        }
    }

    /// Attaches the exact evidence object used by this step.
    #[must_use]
    pub fn with_object(mut self, object: TraceObjectRef) -> Self {
        self.object = Some(object);
        self
    }

    /// Returns the trace stage.
    #[must_use]
    pub const fn stage(&self) -> TrafficTraceStage {
        self.stage
    }

    /// Returns the referenced evidence object, when applicable.
    #[must_use]
    pub const fn object(&self) -> Option<&TraceObjectRef> {
        self.object.as_ref()
    }

    /// Returns the typed stage outcome.
    #[must_use]
    pub const fn outcome(&self) -> TrafficTraceOutcome {
        self.outcome
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::domain::{ServiceName, SnapshotSection, ZoneName};

    #[test]
    fn decision_and_expectation_derive_only_proven_statuses() {
        let cases = [
            (
                FirewallDecision::Allow,
                TrafficExpectation::Allow,
                TrafficTestStatus::Pass,
            ),
            (
                FirewallDecision::Allow,
                TrafficExpectation::Block,
                TrafficTestStatus::Fail,
            ),
            (
                FirewallDecision::Block,
                TrafficExpectation::Allow,
                TrafficTestStatus::Fail,
            ),
            (
                FirewallDecision::Block,
                TrafficExpectation::Block,
                TrafficTestStatus::Pass,
            ),
            (
                FirewallDecision::Unknown,
                TrafficExpectation::Allow,
                TrafficTestStatus::Indeterminate,
            ),
            (
                FirewallDecision::Unknown,
                TrafficExpectation::Block,
                TrafficTestStatus::Indeterminate,
            ),
        ];

        for (decision, expectation, expected) in cases {
            assert_eq!(
                TrafficTestStatus::from_decision(decision, expectation),
                expected
            );
        }
    }

    #[test]
    fn truth_contracts_have_stable_snake_case_serialization() {
        assert_eq!(
            serde_json::to_string(&FirewallDecision::Allow).unwrap(),
            "\"allow\""
        );
        assert_eq!(
            serde_json::to_string(&TrafficExpectation::Block).unwrap(),
            "\"block\""
        );
        assert_eq!(
            serde_json::to_string(&TrafficTestStatus::NotRun).unwrap(),
            "\"not_run\""
        );
        assert_eq!(
            serde_json::to_string(&TrafficTestStatus::Stale).unwrap(),
            "\"stale\""
        );
    }

    #[test]
    fn every_unknown_reason_has_a_stable_round_trip() {
        let cases = [
            (UnknownReason::IncompleteSnapshot, "incomplete_snapshot"),
            (UnknownReason::UnsupportedRichRule, "unsupported_rich_rule"),
            (
                UnknownReason::UnsupportedPolicyFeature,
                "unsupported_policy_feature",
            ),
            (
                UnknownReason::AmbiguousIngressZone,
                "ambiguous_ingress_zone",
            ),
            (UnknownReason::AmbiguousEgressZone, "ambiguous_egress_zone"),
            (UnknownReason::MissingRouteData, "missing_route_data"),
            (
                UnknownReason::UnsupportedStagedOperation,
                "unsupported_staged_operation",
            ),
            (
                UnknownReason::RelevantDirectRuleUnsupported,
                "relevant_direct_rule_unsupported",
            ),
            (UnknownReason::StaleSnapshot, "stale_snapshot"),
            (UnknownReason::StalePlan, "stale_plan"),
            (
                UnknownReason::CapabilityUnavailable,
                "capability_unavailable",
            ),
            (UnknownReason::VersionUnsupported, "version_unsupported"),
            (
                UnknownReason::ConflictingEqualPriorityRules,
                "conflicting_equal_priority_rules",
            ),
            (
                UnknownReason::IncompleteServiceDefinition,
                "incomplete_service_definition",
            ),
            (
                UnknownReason::UnsupportedServiceFeature,
                "unsupported_service_feature",
            ),
            (
                UnknownReason::UnsupportedConnectionState,
                "unsupported_connection_state",
            ),
            (UnknownReason::UnsupportedDirection, "unsupported_direction"),
            (
                UnknownReason::UnsupportedOperationEffect,
                "unsupported_operation_effect",
            ),
            (
                UnknownReason::ExternalRulesOutsideModel,
                "external_rules_outside_model",
            ),
            (
                UnknownReason::RollbackGuaranteeUnavailable,
                "rollback_guarantee_unavailable",
            ),
        ];

        for (reason, spelling) in cases {
            let encoded = serde_json::to_string(&reason).unwrap();
            assert_eq!(encoded, format!("\"{spelling}\""));
            assert_eq!(
                serde_json::from_str::<UnknownReason>(&encoded).unwrap(),
                reason
            );
        }
    }

    #[test]
    fn priority_validates_firewalld_bounds_and_sorts_lowest_first() {
        assert_eq!(RulePriority::new(-32_768).unwrap().get(), -32_768);
        assert_eq!(RulePriority::new(32_767).unwrap().get(), 32_767);
        assert_eq!(
            RulePriority::new(-32_769),
            Err(RulePriorityError::OutOfRange(-32_769))
        );
        assert_eq!(
            RulePriority::new(32_768),
            Err(RulePriorityError::OutOfRange(32_768))
        );

        let mut priorities = [
            RulePriority::new(100).unwrap(),
            RulePriority::new(-100).unwrap(),
            RulePriority::new(0).unwrap(),
        ];
        priorities.sort();
        assert_eq!(priorities.map(RulePriority::get), [-100, 0, 100]);
    }

    #[test]
    fn trace_steps_require_typed_stages_outcomes_and_object_references() {
        let zone = ZoneName::parse("public").unwrap();
        let service = ServiceName::parse("ssh").unwrap();
        let steps = [
            TrafficTraceStep::new(
                TrafficTraceStage::IngressResolution,
                TrafficTraceOutcome::Selected,
            )
            .with_object(TraceObjectRef::Zone(zone)),
            TrafficTraceStep::new(
                TrafficTraceStage::ServiceExpansion,
                TrafficTraceOutcome::Expanded,
            )
            .with_object(TraceObjectRef::Service(service)),
            TrafficTraceStep::new(
                TrafficTraceStage::CompletenessCheck,
                TrafficTraceOutcome::Unknown(UnknownReason::IncompleteSnapshot),
            )
            .with_object(TraceObjectRef::SnapshotSection(SnapshotSection::Policies)),
        ];

        assert_eq!(steps.len(), 3);
        assert_eq!(MAX_TRACE_STEPS, 128);
        assert!(steps.iter().all(|step| step.object().is_some()));
        assert_eq!(
            serde_json::to_string(&steps[2]).unwrap(),
            r#"{"stage":"completeness_check","object":{"snapshot_section":"policies"},"outcome":{"unknown":"incomplete_snapshot"}}"#,
        );
    }
}
