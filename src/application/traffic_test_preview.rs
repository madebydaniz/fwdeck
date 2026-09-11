//! Immutable informational preview evidence; never an apply authorization.
use super::{ObservedSnapshot, PlanId};
use crate::domain::{
    EvaluationContext, EvaluationTarget, FirewallOperation, MutationIntentId,
    TrafficComparisonCounts, TrafficSuite, TrafficTestReport,
};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct TrafficPreviewRequest {
    pub operations: Vec<FirewallOperation>,
    pub observation: ObservedSnapshot,
    pub plan_id: Option<PlanId>,
}

impl TrafficPreviewRequest {
    /// Retains captured evidence across newer publications of identical data,
    /// without changing its original request or report identities.
    #[must_use]
    pub fn is_compatible_with(&self, current: &ObservedSnapshot) -> bool {
        if current.identity() == self.observation.identity() {
            return Arc::ptr_eq(current.snapshot_arc(), self.observation.snapshot_arc());
        }
        current.identity().generation() > self.observation.identity().generation()
            && current.snapshot() == self.observation.snapshot()
    }
}

/// A bounded cause suitable for display without exposing raw worker errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrafficPreviewFailure {
    #[error("reviewed observation is stale or unavailable; refresh the review")]
    StaleObservation,
    #[error("no firewall operations to preview")]
    EmptyOperations,
    #[error("no enabled saved scenarios to compare")]
    NoEnabledScenarios,
    #[error("runtime preview is unavailable offline")]
    OfflineTarget,
    #[error("preview projection failed")]
    Projection,
    #[error("preview evaluation failed")]
    Evaluation,
    #[error("preview evidence is incomplete or mismatched")]
    InvalidEvidence,
    #[error("combined preview evidence exceeds 32 MiB")]
    ReportBudget,
    #[error("preview worker is unavailable")]
    Worker,
}

#[derive(Debug, Clone)]
pub struct TrafficPreviewPair {
    pub target: EvaluationTarget,
    pub before_context: EvaluationContext,
    pub after_context: EvaluationContext,
    pub before: Option<Arc<TrafficTestReport>>,
    pub after: Option<Arc<TrafficTestReport>>,
    pub counts: Option<TrafficComparisonCounts>,
}

/// Captured suite enables input lookup by scenario ID for both report traces.
#[derive(Debug, Clone)]
pub struct TrafficPreviewEvidence {
    pub intent_id: MutationIntentId,
    pub request: Arc<TrafficPreviewRequest>,
    pub suite: Arc<TrafficSuite>,
    pub pairs: Vec<TrafficPreviewPair>,
}

#[derive(Debug, Clone, Default)]
pub enum TrafficPreviewState {
    #[default]
    Idle,
    Preparing(Arc<TrafficPreviewEvidence>),
    Running(Arc<TrafficPreviewEvidence>),
    Completed(Arc<TrafficPreviewEvidence>),
    Stale(Arc<TrafficPreviewEvidence>),
    Failed {
        evidence: Arc<TrafficPreviewEvidence>,
        reason: TrafficPreviewFailure,
    },
}
impl TrafficPreviewState {
    #[must_use]
    pub fn evidence(&self) -> Option<&Arc<TrafficPreviewEvidence>> {
        match self {
            Self::Idle => None,
            Self::Preparing(e)
            | Self::Running(e)
            | Self::Completed(e)
            | Self::Stale(e)
            | Self::Failed { evidence: e, .. } => Some(e),
        }
    }
}
