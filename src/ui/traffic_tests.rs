//! Immutable presentation of application-owned configuration evaluation.

use crate::application::{EvaluationState, SuiteState, TrafficTestWorkspace};
use crate::domain::{EvaluationTarget, TrafficTestReport};
use std::sync::Arc;
pub(super) mod details;
pub(super) mod render;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficPresentation {
    pub preview: Box<super::traffic_preview::Publication>,
    pub audit: crate::application::traffic_test_audit::TrafficAuditStatus,
    pub save: crate::application::TrafficSaveState,
    pub suite: SuiteState,
    pub evaluation: EvaluationState,
    pub stale_report: Option<Arc<TrafficTestReport>>,
    pub target: EvaluationTarget,
    pub authoritative: bool,
    /// Identity of the currently accepted observation, independent of any run.
    pub current_snapshot: Option<crate::application::SnapshotIdentity>,
    pub error: Option<String>,
    pub load_requested: bool,
}

impl TrafficPresentation {
    #[must_use]
    pub fn details(
        &self,
        id: &crate::domain::TrafficScenarioId,
    ) -> Option<super::details::DetailsContent> {
        details::build(self, id)
    }
    #[must_use]
    pub fn rows(&self) -> Vec<super::views::ViewRow> {
        let SuiteState::Available(suite) = &self.suite else {
            return Vec::new();
        };
        suite
            .scenarios
            .iter()
            .map(|scenario| {
                let (actual, status) = self.outcome(scenario);
                super::views::ViewRow::new(
                    super::views::RowId::TrafficScenario(scenario.id.clone()),
                    vec![
                        scenario.name.clone(),
                        format!("{:?}", scenario.direction),
                        format!("{:?}", scenario.expectation),
                        actual,
                        status,
                        format!("{:?}", scenario.severity),
                        format!("{:?}", self.target),
                    ],
                )
            })
            .collect()
    }

    fn outcome(&self, scenario: &crate::domain::TrafficScenario) -> (String, String) {
        if !scenario.enabled {
            return ("-".into(), "NotRun (disabled)".into());
        }
        let status = match &self.evaluation {
            EvaluationState::NotRun => if self.stale_report.is_some() {
                "Stale"
            } else {
                "NotRun"
            }
            .into(),
            EvaluationState::Queued(_) => "Queued".into(),
            EvaluationState::Running(_) => "Running".into(),
            EvaluationState::Cancelled { .. } => "Cancelled".into(),
            EvaluationState::Failed { reason, .. } => format!("Failed ({reason:?})"),
            EvaluationState::Stale(_) => "Stale".into(),
            EvaluationState::Completed(report) => {
                if !self.report_is_current(report) {
                    return ("-".into(), "Stale".into());
                }
                if let Some(result) = report
                    .results()
                    .iter()
                    .find(|result| result.scenario_id() == &scenario.id)
                {
                    return (
                        format!("{:?}", result.decision()),
                        format!("{:?}", result.status()),
                    );
                }
                "NotRun".into()
            }
        };
        ("-".into(), status)
    }

    fn report_is_current(&self, report: &TrafficTestReport) -> bool {
        let SuiteState::Available(suite) = &self.suite else {
            return false;
        };
        let Some(snapshot) = self.current_snapshot else {
            return false;
        };
        let context = report.context();
        self.authoritative
            && context.suite_id == suite.id
            && context.suite_revision == suite.revision
            && context.target == self.target
            && context.phase == crate::domain::EvaluationPhase::Current
            && context.authoritative_snapshot.refresh_id() == snapshot.refresh_id().get()
            && context.authoritative_snapshot.generation() == snapshot.generation().get()
    }

    #[must_use]
    pub fn message(&self) -> String {
        match &self.suite {
            SuiteState::NotLoaded => "Not loaded. Enter Traffic Tests to load the default suite.".into(),
            SuiteState::Loading(_) => "Loading default suite…".into(),
            SuiteState::Missing => "No default suite exists. No file was created. Open templates (a). Review, then explicitly Save to create the local default suite.".into(),
            SuiteState::UnsupportedSchema(version) => format!("Unsupported future schema {version}. Suite preserved; use a compatible FWDeck version."),
            SuiteState::Failed(reason) => format!("Default suite unavailable: {reason:?}. Check the suite, then reload (r)."),
            SuiteState::Available(_) => String::new(),
        }
    }

    #[must_use]
    pub fn new(offline: bool) -> Self {
        Self::from_workspace(&TrafficTestWorkspace::new(offline))
    }

    #[must_use]
    pub fn from_workspace(workspace: &TrafficTestWorkspace) -> Self {
        Self {
            preview: Box::default(),
            audit: crate::application::traffic_test_audit::TrafficAuditStatus::default(),
            save: crate::application::TrafficSaveState::Idle,
            suite: workspace.suite_state().clone(),
            evaluation: workspace.evaluation_state().clone(),
            stale_report: workspace.stale_report().cloned(),
            target: workspace.target(),
            authoritative: workspace.observation().is_some(),
            current_snapshot: workspace
                .observation()
                .map(crate::application::ObservedSnapshot::identity),
            error: None,
            load_requested: !matches!(workspace.suite_state(), SuiteState::NotLoaded),
        }
    }
}
