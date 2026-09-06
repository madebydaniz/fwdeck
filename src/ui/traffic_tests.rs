//! Immutable presentation of application-owned configuration evaluation.

use crate::application::{EvaluationState, SuiteState, TrafficTestWorkspace};
use crate::domain::{EvaluationTarget, TrafficTestReport};
use std::sync::Arc;
pub(super) mod render;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficPresentation {
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
    #[allow(clippy::too_many_lines)] // One bounded field list plus current and historical identities.
    pub fn details(
        &self,
        id: &crate::domain::TrafficScenarioId,
    ) -> Option<super::details::DetailsContent> {
        let SuiteState::Available(suite) = &self.suite else {
            return None;
        };
        let scenario = suite.scenarios.iter().find(|scenario| &scenario.id == id)?;
        let (actual, status) = self.outcome(scenario);
        let mut lines = vec![
            (
                "Evaluation".into(),
                "Configuration evaluation; Live connectivity: NOT VERIFIED".into(),
            ),
            ("Name".into(), scenario.name.clone()),
            ("Scenario ID".into(), scenario.id.to_string()),
            ("Direction".into(), format!("{:?}", scenario.direction)),
            ("Source".into(), scenario.source.to_string()),
            (
                "Ingress interface / zone".into(),
                format!(
                    "{:?} / {:?}",
                    scenario.ingress_interface, scenario.ingress_zone
                ),
            ),
            ("Destination".into(), format!("{:?}", scenario.destination)),
            (
                "Egress interface / zone".into(),
                format!(
                    "{:?} / {:?}",
                    scenario.egress_interface, scenario.egress_zone
                ),
            ),
            ("Transport".into(), format!("{:?}", scenario.transport)),
            (
                "Source / destination ports".into(),
                format!(
                    "{:?} / {:?}",
                    scenario.source_port, scenario.destination_port
                ),
            ),
            (
                "Connection state".into(),
                format!("{:?}", scenario.connection_state),
            ),
            ("Expected".into(), format!("{:?}", scenario.expectation)),
            ("Actual".into(), actual),
            ("Status".into(), status),
            ("Target".into(), format!("{:?}", self.target)),
            ("Severity".into(), format!("{:?}", scenario.severity)),
            (
                "Required safety gate".into(),
                format!("{}; not enforced in Phase 2", scenario.required_safety_gate),
            ),
            (
                "Suite".into(),
                format!("{} revision {}", suite.id, suite.revision.get()),
            ),
        ];
        if let Some(identity) = self.current_snapshot {
            lines.push((
                "Current authoritative snapshot".into(),
                format!(
                    "refresh {} / generation {}",
                    identity.refresh_id().get(),
                    identity.generation().get()
                ),
            ));
        }
        let context = match &self.evaluation {
            EvaluationState::Completed(report) => Some(("Current context", report.context())),
            EvaluationState::Stale(report) => Some((
                "Historical context (not current evidence)",
                report.context(),
            )),
            EvaluationState::Queued(context)
            | EvaluationState::Running(context)
            | EvaluationState::Failed { context, .. }
            | EvaluationState::Cancelled { context, .. } => Some(("Run context", context)),
            EvaluationState::NotRun => self.stale_report.as_ref().map(|report| {
                (
                    "Historical context (not current evidence)",
                    report.context(),
                )
            }),
        };
        if let Some((label, context)) = context {
            lines.push((
                label.into(),
                format!(
                    "run {} / suite {} / revision {} / target {:?} / snapshot {:?}",
                    context.run_id.get(),
                    context.suite_id,
                    context.suite_revision.get(),
                    context.target,
                    context.authoritative_snapshot
                ),
            ));
        }
        if !matches!(
            self.evaluation,
            EvaluationState::Stale(_) | EvaluationState::NotRun
        ) && let Some(report) = &self.stale_report
        {
            let historical = report.context();
            lines.push((
                "Historical context (not current evidence)".into(),
                format!(
                    "run {} / suite {} / revision {} / target {:?} / snapshot {:?}",
                    historical.run_id.get(),
                    historical.suite_id,
                    historical.suite_revision.get(),
                    historical.target,
                    historical.authoritative_snapshot
                ),
            ));
        }
        if let Some(note) = &scenario.note {
            lines.push(("Note".into(), note.clone()));
        }
        Some(super::details::DetailsContent {
            title: "Traffic scenario".into(),
            lines,
        })
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

    #[must_use]
    pub fn message(&self) -> String {
        match &self.suite {
            SuiteState::NotLoaded => "Not loaded. Enter Traffic Tests to load the default suite.".into(),
            SuiteState::Loading(_) => "Loading default suite…".into(),
            SuiteState::Missing => "No default suite exists. No file was created. Place traffic-tests/default.toml in the application config directory, then reload (r).".into(),
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
