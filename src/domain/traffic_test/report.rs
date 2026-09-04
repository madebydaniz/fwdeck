use std::collections::BTreeSet;
use std::num::NonZeroU64;

use super::{
    FirewallDecision, MAX_SCENARIOS_PER_SUITE, MAX_TRACE_STEPS, TrafficExpectation,
    TrafficScenarioId, TrafficSuiteId, TrafficSuiteRevision, TrafficTestStatus, TrafficTraceStep,
    UnknownReason,
};

/// Maximum serialized size of one aggregate report.
pub const MAX_TRAFFIC_REPORT_BYTES: usize = 32 * 1024 * 1024;

macro_rules! non_zero_id {
    ($(#[$meta:meta])* $name:ident, $error:ident) => {
        $(#[$meta])*
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            serde::Serialize,
            serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(NonZeroU64);

        impl $name {
            /// Creates a non-zero process-local identity.
            pub fn new(value: u64) -> Result<Self, TrafficReportError> {
                NonZeroU64::new(value)
                    .map(Self)
                    .ok_or(TrafficReportError::$error)
            }

            /// Returns the numeric identity.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0.get()
            }
        }
    };
}

non_zero_id!(
    /// Process-local identity for one traffic-test run.
    TrafficTestRunId,
    ZeroRunId
);
non_zero_id!(
    /// Process-local identity for one reviewed mutation intent.
    MutationIntentId,
    ZeroMutationIntentId
);

/// Domain-safe copy of one authoritative application snapshot identity.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct EvaluationSnapshotIdentity {
    refresh_id: u64,
    generation: NonZeroU64,
}

impl EvaluationSnapshotIdentity {
    /// Creates an identity from a refresh lifecycle and publication generation.
    pub fn new(refresh_id: u64, generation: u64) -> Result<Self, TrafficReportError> {
        let generation =
            NonZeroU64::new(generation).ok_or(TrafficReportError::ZeroSnapshotGeneration)?;
        Ok(Self {
            refresh_id,
            generation,
        })
    }

    /// Returns the originating refresh identity.
    #[must_use]
    pub const fn refresh_id(self) -> u64 {
        self.refresh_id
    }

    /// Returns the process-local publication generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation.get()
    }
}

/// Domain-safe copy of an optional staged plan identity.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct EvaluationPlanId(u64);

impl EvaluationPlanId {
    /// Copies an application-owned plan identity into an evaluation context.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric correlation identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Exact configuration scope evaluated by one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationTarget {
    /// Live runtime configuration.
    Runtime,
    /// Stored permanent configuration.
    Permanent,
}

/// Lifecycle phase represented by an evaluation context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationPhase {
    /// Current authoritative configuration.
    Current,
    /// Pure projected configuration before apply.
    StagedCandidate,
    /// Fresh authoritative configuration after apply.
    PostApply,
}

/// Stable non-cryptographic digest of one ordered mutation sequence.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct OrderedOperationDigest(u64);

impl OrderedOperationDigest {
    /// Hashes length-delimited canonical operation bytes with fixed FNV-1a parameters.
    #[must_use]
    pub fn from_ordered_bytes<'a>(operations: impl IntoIterator<Item = &'a [u8]>) -> Self {
        const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const PRIME: u64 = 0x0000_0100_0000_01b3;

        let mut digest = OFFSET;
        for operation in operations {
            let length = u64::try_from(operation.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes();
            for byte in length.iter().chain(operation) {
                digest ^= u64::from(*byte);
                digest = digest.wrapping_mul(PRIME);
            }
        }
        Self(digest)
    }

    /// Returns the fixed-width lowercase diagnostic representation.
    #[must_use]
    pub fn as_hex(self) -> String {
        format!("{:016x}", self.0)
    }

    /// Returns the raw deterministic correlation value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Identity of one target-specific immutable candidate projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CandidateIdentity {
    base_snapshot: EvaluationSnapshotIdentity,
    mutation_intent_id: MutationIntentId,
    plan_id: Option<EvaluationPlanId>,
    target: EvaluationTarget,
    ordered_operation_digest: OrderedOperationDigest,
}

impl CandidateIdentity {
    /// Binds a candidate to its exact base, reviewed intent, target, and operation order.
    #[must_use]
    pub const fn new(
        base_snapshot: EvaluationSnapshotIdentity,
        mutation_intent_id: MutationIntentId,
        plan_id: Option<EvaluationPlanId>,
        target: EvaluationTarget,
        ordered_operation_digest: OrderedOperationDigest,
    ) -> Self {
        Self {
            base_snapshot,
            mutation_intent_id,
            plan_id,
            target,
            ordered_operation_digest,
        }
    }

    /// Returns the authoritative snapshot used as projection input.
    #[must_use]
    pub const fn base_snapshot(self) -> EvaluationSnapshotIdentity {
        self.base_snapshot
    }

    /// Returns the reviewed mutation identity.
    #[must_use]
    pub const fn mutation_intent_id(self) -> MutationIntentId {
        self.mutation_intent_id
    }

    /// Returns the optional staged-plan identity.
    #[must_use]
    pub const fn plan_id(self) -> Option<EvaluationPlanId> {
        self.plan_id
    }

    /// Returns the exact projected target.
    #[must_use]
    pub const fn target(self) -> EvaluationTarget {
        self.target
    }

    /// Returns the ordered-operation correlation digest.
    #[must_use]
    pub const fn ordered_operation_digest(self) -> OrderedOperationDigest {
        self.ordered_operation_digest
    }
}

/// Immutable identity boundary carried through one evaluation run.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EvaluationContext {
    /// Unique run identity.
    pub run_id: TrafficTestRunId,
    /// Suite whose ordered scenarios are being evaluated.
    pub suite_id: TrafficSuiteId,
    /// Exact persisted suite revision.
    pub suite_revision: TrafficSuiteRevision,
    /// Current, candidate, or post-apply lifecycle.
    pub phase: EvaluationPhase,
    /// Runtime or permanent configuration; never both.
    pub target: EvaluationTarget,
    /// Authoritative publication that anchors the evidence.
    pub authoritative_snapshot: EvaluationSnapshotIdentity,
    /// Candidate base publication, when applicable.
    pub base_snapshot: Option<EvaluationSnapshotIdentity>,
    /// Reviewed mutation identity for candidate and post-apply runs.
    pub mutation_intent_id: Option<MutationIntentId>,
    /// Optional staged-plan identity.
    pub plan_id: Option<EvaluationPlanId>,
    /// Exact candidate identity for candidate runs.
    pub candidate_identity: Option<CandidateIdentity>,
}

impl EvaluationContext {
    /// Rejects phase-incoherent or partially bound identities.
    pub fn validate(&self) -> Result<(), TrafficReportError> {
        match self.phase {
            EvaluationPhase::Current => {
                if self.mutation_intent_id.is_some()
                    || self.plan_id.is_some()
                    || self.base_snapshot.is_some()
                    || self.candidate_identity.is_some()
                {
                    return Err(TrafficReportError::UnexpectedMutationIdentity {
                        phase: self.phase,
                    });
                }
            }
            EvaluationPhase::StagedCandidate => {
                let mutation_intent_id = self
                    .mutation_intent_id
                    .ok_or(TrafficReportError::MissingMutationIdentity { phase: self.phase })?;
                let base_snapshot = self
                    .base_snapshot
                    .ok_or(TrafficReportError::MissingCandidateIdentity)?;
                let candidate = self
                    .candidate_identity
                    .ok_or(TrafficReportError::MissingCandidateIdentity)?;
                if self.authoritative_snapshot != base_snapshot
                    || candidate.base_snapshot != base_snapshot
                    || candidate.mutation_intent_id != mutation_intent_id
                    || candidate.plan_id != self.plan_id
                    || candidate.target != self.target
                {
                    return Err(TrafficReportError::CandidateIdentityMismatch);
                }
            }
            EvaluationPhase::PostApply => {
                if self.mutation_intent_id.is_none() {
                    return Err(TrafficReportError::MissingMutationIdentity { phase: self.phase });
                }
                if self.candidate_identity.is_some() {
                    return Err(TrafficReportError::UnexpectedCandidateIdentity);
                }
            }
        }
        Ok(())
    }

    /// Requires every active identity and target to match before publication.
    #[must_use]
    pub fn matches_active(&self, active: &Self) -> bool {
        self == active
    }
}

/// One scenario decision bound to an expectation and bounded trace.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TrafficTestResult {
    scenario_id: TrafficScenarioId,
    expectation: TrafficExpectation,
    decision: FirewallDecision,
    status: TrafficTestStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    unknown_reason: Option<UnknownReason>,
    trace: Vec<TrafficTraceStep>,
}

impl TrafficTestResult {
    /// Constructs one internally consistent result.
    pub fn new(
        scenario_id: TrafficScenarioId,
        expectation: TrafficExpectation,
        decision: FirewallDecision,
        unknown_reason: Option<UnknownReason>,
        trace: Vec<TrafficTraceStep>,
    ) -> Result<Self, TrafficReportError> {
        match (decision, unknown_reason) {
            (FirewallDecision::Unknown, None) => {
                return Err(TrafficReportError::MissingUnknownReason);
            }
            (FirewallDecision::Allow | FirewallDecision::Block, Some(_)) => {
                return Err(TrafficReportError::UnexpectedUnknownReason);
            }
            _ => {}
        }
        if trace.len() > MAX_TRACE_STEPS {
            return Err(TrafficReportError::TraceTooLong {
                count: trace.len(),
                max: MAX_TRACE_STEPS,
            });
        }
        Ok(Self {
            scenario_id,
            expectation,
            decision,
            status: TrafficTestStatus::from_decision(decision, expectation),
            unknown_reason,
            trace,
        })
    }

    /// Returns the scenario identity.
    #[must_use]
    pub const fn scenario_id(&self) -> &TrafficScenarioId {
        &self.scenario_id
    }

    /// Returns the declared expectation.
    #[must_use]
    pub const fn expectation(&self) -> TrafficExpectation {
        self.expectation
    }

    /// Returns the proven or unknown decision.
    #[must_use]
    pub const fn decision(&self) -> FirewallDecision {
        self.decision
    }

    /// Returns the comparison status.
    #[must_use]
    pub const fn status(&self) -> TrafficTestStatus {
        self.status
    }

    /// Returns why no decision could be proven.
    #[must_use]
    pub const fn unknown_reason(&self) -> Option<UnknownReason> {
        self.unknown_reason
    }

    /// Returns the deterministic evidence path.
    #[must_use]
    pub fn trace(&self) -> &[TrafficTraceStep] {
        &self.trace
    }
}

/// Aggregate status counts for one complete report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct TrafficTestSummary {
    /// Total retained results.
    pub total: u32,
    /// Proven decisions matching expectations.
    pub passed: u32,
    /// Proven decisions contradicting expectations.
    pub failed: u32,
    /// Unknown decisions.
    pub indeterminate: u32,
    /// Reserved not-run results.
    pub not_run: u32,
    /// Reserved stale historical results.
    pub stale: u32,
}

impl TrafficTestSummary {
    fn from_results(results: &[TrafficTestResult]) -> Self {
        let mut summary = Self {
            total: u32::try_from(results.len()).unwrap_or(u32::MAX),
            ..Self::default()
        };
        for result in results {
            match result.status {
                TrafficTestStatus::Pass => summary.passed += 1,
                TrafficTestStatus::Fail => summary.failed += 1,
                TrafficTestStatus::Indeterminate => summary.indeterminate += 1,
                TrafficTestStatus::NotRun => summary.not_run += 1,
                TrafficTestStatus::Stale => summary.stale += 1,
            }
        }
        summary
    }
}

/// Complete bounded publication unit for one evaluation context.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TrafficTestReport {
    context: EvaluationContext,
    results: Vec<TrafficTestResult>,
    summary: TrafficTestSummary,
}

impl TrafficTestReport {
    /// Validates identities, uniqueness, counts, traces, and serialized budget.
    pub fn new(
        context: EvaluationContext,
        results: Vec<TrafficTestResult>,
    ) -> Result<Self, TrafficReportError> {
        context.validate()?;
        if results.len() > MAX_SCENARIOS_PER_SUITE {
            return Err(TrafficReportError::TooManyResults {
                count: results.len(),
                max: MAX_SCENARIOS_PER_SUITE,
            });
        }
        let mut ids = BTreeSet::new();
        for result in &results {
            if result.trace.len() > MAX_TRACE_STEPS {
                return Err(TrafficReportError::TraceTooLong {
                    count: result.trace.len(),
                    max: MAX_TRACE_STEPS,
                });
            }
            if !ids.insert(result.scenario_id.clone()) {
                return Err(TrafficReportError::DuplicateResult(
                    result.scenario_id.clone(),
                ));
            }
        }

        let report = Self {
            summary: TrafficTestSummary::from_results(&results),
            context,
            results,
        };
        let serialized_len = serde_json::to_vec(&report)
            .map_err(|_| TrafficReportError::SerializationFailed)?
            .len();
        if serialized_len > MAX_TRAFFIC_REPORT_BYTES {
            return Err(TrafficReportError::ReportTooLarge {
                bytes: serialized_len,
                max: MAX_TRAFFIC_REPORT_BYTES,
            });
        }
        Ok(report)
    }

    /// Returns the immutable evaluation identity boundary.
    #[must_use]
    pub const fn context(&self) -> &EvaluationContext {
        &self.context
    }

    /// Returns ordered scenario results.
    #[must_use]
    pub fn results(&self) -> &[TrafficTestResult] {
        &self.results
    }

    /// Returns aggregate status counts.
    #[must_use]
    pub const fn summary(&self) -> TrafficTestSummary {
        self.summary
    }

    /// Returns the exact current JSON publication size, or `usize::MAX` on encoding failure.
    #[must_use]
    pub fn serialized_len(&self) -> usize {
        serde_json::to_vec(self).map_or(usize::MAX, |bytes| bytes.len())
    }

    /// Whether every identity still matches the active evaluation state.
    #[must_use]
    pub fn matches_active(&self, active: &EvaluationContext) -> bool {
        self.context.matches_active(active)
    }
}

/// Invalid evaluation identity, result, or report boundary.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrafficReportError {
    /// Run identity zero is reserved for absence.
    #[error("traffic-test run ID must be non-zero")]
    ZeroRunId,
    /// Mutation identity zero is reserved for absence.
    #[error("mutation intent ID must be non-zero")]
    ZeroMutationIntentId,
    /// Authoritative publication generation zero is invalid.
    #[error("snapshot publication generation must be non-zero")]
    ZeroSnapshotGeneration,
    /// Candidate or post-apply phases require one reviewed mutation identity.
    #[error("{phase:?} evaluation requires a mutation identity")]
    MissingMutationIdentity {
        /// Invalid phase.
        phase: EvaluationPhase,
    },
    /// Current evaluation cannot carry mutation-specific identity.
    #[error("{phase:?} evaluation cannot carry mutation identity")]
    UnexpectedMutationIdentity {
        /// Invalid phase.
        phase: EvaluationPhase,
    },
    /// Candidate phase is missing its base or candidate binding.
    #[error("candidate evaluation requires base and candidate identities")]
    MissingCandidateIdentity,
    /// Candidate fields do not all refer to the same base, intent, plan, and target.
    #[error("candidate identity does not match its evaluation context")]
    CandidateIdentityMismatch,
    /// Post-apply evidence cannot retain a projected candidate identity.
    #[error("post-apply evaluation cannot carry a candidate identity")]
    UnexpectedCandidateIdentity,
    /// Unknown decision lacks a typed cause.
    #[error("unknown decision requires an unknown reason")]
    MissingUnknownReason,
    /// Proven decision incorrectly carries an unknown cause.
    #[error("proven decision cannot carry an unknown reason")]
    UnexpectedUnknownReason,
    /// One trace exceeds the per-scenario evidence cap.
    #[error("trace contains {count} steps; maximum is {max}")]
    TraceTooLong {
        /// Actual step count.
        count: usize,
        /// Maximum step count.
        max: usize,
    },
    /// One report exceeds the suite execution cap.
    #[error("report contains {count} results; maximum is {max}")]
    TooManyResults {
        /// Actual result count.
        count: usize,
        /// Maximum result count.
        max: usize,
    },
    /// One scenario appears more than once in a report.
    #[error("duplicate result for scenario `{0}`")]
    DuplicateResult(TrafficScenarioId),
    /// The aggregate publication exceeds the hard memory/transport budget.
    #[error("serialized report is {bytes} bytes; maximum is {max}")]
    ReportTooLarge {
        /// Actual encoded bytes.
        bytes: usize,
        /// Maximum bytes.
        max: usize,
    },
    /// Serialization failed despite validated domain-only fields.
    #[error("traffic-test report serialization failed")]
    SerializationFailed,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::domain::{
        FirewallDecision, TrafficExpectation, TrafficScenarioId, TrafficTestStatus,
        TrafficTraceOutcome, TrafficTraceStage, TrafficTraceStep, UnknownReason,
    };

    fn snapshot(refresh: u64, generation: u64) -> EvaluationSnapshotIdentity {
        EvaluationSnapshotIdentity::new(refresh, generation).unwrap()
    }

    fn current_context(target: EvaluationTarget) -> EvaluationContext {
        EvaluationContext {
            run_id: TrafficTestRunId::new(1).unwrap(),
            suite_id: crate::domain::TrafficSuiteId::parse("default").unwrap(),
            suite_revision: crate::domain::TrafficSuiteRevision::new(3).unwrap(),
            phase: EvaluationPhase::Current,
            target,
            authoritative_snapshot: snapshot(10, 4),
            base_snapshot: None,
            mutation_intent_id: None,
            plan_id: None,
            candidate_identity: None,
        }
    }

    fn result(id: &str, decision: FirewallDecision) -> TrafficTestResult {
        TrafficTestResult::new(
            TrafficScenarioId::parse(id).unwrap(),
            TrafficExpectation::Allow,
            decision,
            (decision == FirewallDecision::Unknown).then_some(UnknownReason::IncompleteSnapshot),
            vec![TrafficTraceStep::new(
                TrafficTraceStage::Decision,
                TrafficTraceOutcome::Decision(decision),
            )],
        )
        .unwrap()
    }

    #[test]
    fn identities_are_non_zero_and_round_trip_stably() {
        assert!(TrafficTestRunId::new(0).is_err());
        assert!(MutationIntentId::new(0).is_err());
        assert!(EvaluationSnapshotIdentity::new(1, 0).is_err());

        let context = current_context(EvaluationTarget::Runtime);
        let encoded = serde_json::to_string(&context).unwrap();
        assert_eq!(
            serde_json::from_str::<EvaluationContext>(&encoded).unwrap(),
            context
        );
    }

    #[test]
    fn ordered_operation_digest_is_deterministic_and_order_sensitive() {
        let first = OrderedOperationDigest::from_ordered_bytes([
            b"add ssh".as_slice(),
            b"drop 9".as_slice(),
        ]);
        let same = OrderedOperationDigest::from_ordered_bytes([
            b"add ssh".as_slice(),
            b"drop 9".as_slice(),
        ]);
        let reversed = OrderedOperationDigest::from_ordered_bytes([
            b"drop 9".as_slice(),
            b"add ssh".as_slice(),
        ]);
        assert_eq!(first, same);
        assert_ne!(first, reversed);
        assert_eq!(first.as_hex().len(), 16);
    }

    #[test]
    fn candidate_context_must_bind_every_identity_and_target() {
        let base = snapshot(10, 4);
        let mutation = MutationIntentId::new(7).unwrap();
        let plan = Some(EvaluationPlanId::new(9));
        let digest = OrderedOperationDigest::from_ordered_bytes([b"operation".as_slice()]);
        let candidate =
            CandidateIdentity::new(base, mutation, plan, EvaluationTarget::Permanent, digest);
        let context = EvaluationContext {
            run_id: TrafficTestRunId::new(2).unwrap(),
            suite_id: crate::domain::TrafficSuiteId::parse("default").unwrap(),
            suite_revision: crate::domain::TrafficSuiteRevision::new(3).unwrap(),
            phase: EvaluationPhase::StagedCandidate,
            target: EvaluationTarget::Permanent,
            authoritative_snapshot: base,
            base_snapshot: Some(base),
            mutation_intent_id: Some(mutation),
            plan_id: plan,
            candidate_identity: Some(candidate),
        };
        assert_eq!(context.validate(), Ok(()));

        let mut wrong_target = context.clone();
        wrong_target.target = EvaluationTarget::Runtime;
        assert_eq!(
            wrong_target.validate(),
            Err(TrafficReportError::CandidateIdentityMismatch)
        );
    }

    #[test]
    fn current_and_post_apply_contexts_reject_incoherent_mutation_state() {
        let mut current = current_context(EvaluationTarget::Runtime);
        current.mutation_intent_id = Some(MutationIntentId::new(2).unwrap());
        assert_eq!(
            current.validate(),
            Err(TrafficReportError::UnexpectedMutationIdentity {
                phase: EvaluationPhase::Current
            })
        );

        let mut post_apply = current_context(EvaluationTarget::Runtime);
        post_apply.phase = EvaluationPhase::PostApply;
        assert_eq!(
            post_apply.validate(),
            Err(TrafficReportError::MissingMutationIdentity {
                phase: EvaluationPhase::PostApply
            })
        );
    }

    #[test]
    fn exact_context_equality_rejects_stale_suite_snapshot_and_target() {
        let context = current_context(EvaluationTarget::Runtime);
        assert!(context.matches_active(&context));

        let mut stale_suite = context.clone();
        stale_suite.suite_revision = crate::domain::TrafficSuiteRevision::new(4).unwrap();
        assert!(!context.matches_active(&stale_suite));

        let mut stale_snapshot = context.clone();
        stale_snapshot.authoritative_snapshot = snapshot(11, 5);
        assert!(!context.matches_active(&stale_snapshot));

        let mut other_target = context.clone();
        other_target.target = EvaluationTarget::Permanent;
        assert!(!context.matches_active(&other_target));
    }

    #[test]
    fn result_constructor_keeps_decision_status_reason_and_trace_consistent() {
        let allowed = result("allowed", FirewallDecision::Allow);
        assert_eq!(allowed.status(), TrafficTestStatus::Pass);
        assert_eq!(allowed.unknown_reason(), None);

        assert_eq!(
            TrafficTestResult::new(
                TrafficScenarioId::parse("bad").unwrap(),
                TrafficExpectation::Block,
                FirewallDecision::Unknown,
                None,
                Vec::new(),
            ),
            Err(TrafficReportError::MissingUnknownReason)
        );
        assert_eq!(
            TrafficTestResult::new(
                TrafficScenarioId::parse("bad").unwrap(),
                TrafficExpectation::Block,
                FirewallDecision::Block,
                Some(UnknownReason::IncompleteSnapshot),
                Vec::new(),
            ),
            Err(TrafficReportError::UnexpectedUnknownReason)
        );
    }

    #[test]
    fn report_enforces_trace_result_and_duplicate_bounds() {
        let context = current_context(EvaluationTarget::Runtime);
        let mut oversized_trace = vec![
            TrafficTraceStep::new(
                TrafficTraceStage::Decision,
                TrafficTraceOutcome::Decision(FirewallDecision::Allow),
            );
            crate::domain::MAX_TRACE_STEPS + 1
        ];
        assert!(matches!(
            TrafficTestResult::new(
                TrafficScenarioId::parse("trace").unwrap(),
                TrafficExpectation::Allow,
                FirewallDecision::Allow,
                None,
                std::mem::take(&mut oversized_trace),
            ),
            Err(TrafficReportError::TraceTooLong { .. })
        ));

        let duplicate = result("same", FirewallDecision::Allow);
        assert!(matches!(
            TrafficTestReport::new(context.clone(), vec![duplicate.clone(), duplicate]),
            Err(TrafficReportError::DuplicateResult(_))
        ));

        let many = (0..=crate::domain::MAX_SCENARIOS_PER_SUITE)
            .map(|index| result(&format!("scenario-{index}"), FirewallDecision::Allow))
            .collect();
        assert!(matches!(
            TrafficTestReport::new(context, many),
            Err(TrafficReportError::TooManyResults { .. })
        ));
    }

    #[test]
    fn report_summary_and_serialized_budget_are_deterministic() {
        let report = TrafficTestReport::new(
            current_context(EvaluationTarget::Runtime),
            vec![
                result("pass", FirewallDecision::Allow),
                result("fail", FirewallDecision::Block),
                result("unknown", FirewallDecision::Unknown),
            ],
        )
        .unwrap();
        assert_eq!(report.summary().passed, 1);
        assert_eq!(report.summary().failed, 1);
        assert_eq!(report.summary().indeterminate, 1);
        assert_eq!(report.summary().total, 3);
        assert!(report.serialized_len() <= MAX_TRAFFIC_REPORT_BYTES);
        assert_eq!(
            report.serialized_len(),
            serde_json::to_vec(&report).unwrap().len()
        );
    }
}
