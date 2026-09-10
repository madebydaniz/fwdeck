//! Owned informational comparison presentation, separate from ordinary results.
use super::{
    action::UiAction, details::DetailsContent, overlays::Confirmation, palette::Availability,
    state::UiState,
};
use crate::application::{TrafficPreviewRequest, TrafficPreviewState};
use crate::domain::{TrafficScenario, TrafficTestReport, TrafficTestResult};
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct Publication {
    pub audit: crate::application::traffic_test_audit::TrafficAuditStatus,
    pub owner: Option<Arc<TrafficPreviewRequest>>,
    pub state: TrafficPreviewState,
    pub error: Option<String>,
    pub loading: bool,
}
impl PartialEq for Publication {
    fn eq(&self, other: &Self) -> bool {
        let owner = match (&self.owner, &other.owner) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        let evidence = match (self.state.evidence(), other.state.evidence()) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            (None, None) => true,
            _ => false,
        };
        owner
            && evidence
            && self.audit == other.audit
            && self.error == other.error
            && self.loading == other.loading
            && std::mem::discriminant(&self.state) == std::mem::discriminant(&other.state)
            && match (&self.state, &other.state) {
                (
                    TrafficPreviewState::Failed { reason: a, .. },
                    TrafficPreviewState::Failed { reason: b, .. },
                ) => a == b,
                _ => true,
            }
    }
}
impl Eq for Publication {}

#[derive(Debug, Clone, PartialEq)]
pub struct Preview {
    pub request: Arc<TrafficPreviewRequest>,
    pub parent: Option<Confirmation>,
    pub staged: Option<Vec<crate::domain::FirewallOperation>>,
    pub publication: Publication,
    pub selected: usize,
    pub selection_changed: bool,
    pub invalidated: bool,
}

#[must_use]
pub fn is_mutation(action: &UiAction) -> bool {
    matches!(
        action,
        UiAction::ApplyOperation(_) | UiAction::ApplyPlanConfirmed(_)
    )
}

#[must_use]
pub fn staged_availability(state: &UiState) -> Availability {
    if state.staged.is_empty() {
        return Availability::Disabled("no staged operations");
    }
    if state.traffic_observation.as_ref().is_none_or(|o| {
        state
            .snapshot
            .as_ref()
            .is_none_or(|s| !Arc::ptr_eq(o.snapshot_arc(), s))
    }) {
        return Availability::Disabled("authoritative base unavailable or stale; refresh first");
    }
    if state.offline
        && state.staged.iter().any(|op| {
            !matches!(
                op.effect().targets,
                crate::domain::OperationTargetSequence::Permanent
                    | crate::domain::OperationTargetSequence::PermanentFromRuntime
            )
        })
    {
        return Availability::Disabled("runtime preview unavailable offline");
    }
    Availability::Enabled
}

fn result<'a>(
    report: Option<&'a TrafficTestReport>,
    scenario: &TrafficScenario,
) -> Option<&'a TrafficTestResult> {
    report?
        .results()
        .iter()
        .find(|r| r.scenario_id() == &scenario.id)
}
fn outcome(result: Option<&TrafficTestResult>) -> String {
    result.map_or_else(
        || "Unavailable".into(),
        |r| format!("{:?} / {:?}", r.status(), r.decision()),
    )
}
impl Preview {
    #[must_use]
    pub fn status(&self) -> String {
        if self.invalidated {
            return "Stale — captured evidence only; reopen the review".into();
        }
        if let Some(error) = &self.publication.error {
            return format!("Preview unavailable: {error}");
        }
        if self.publication.loading {
            return "Loading saved default suite…".into();
        }
        match &self.publication.state {
            TrafficPreviewState::Idle => "Preparing preview…".into(),
            TrafficPreviewState::Preparing(_) | TrafficPreviewState::Running(_) => {
                "Evaluating — comparison incomplete".into()
            }
            TrafficPreviewState::Completed(_) => "Completed — configuration comparison only".into(),
            TrafficPreviewState::Stale(_) => {
                "Stale — captured evidence only; reopen the review".into()
            }
            TrafficPreviewState::Failed { reason, .. } => {
                format!("Comparison unavailable: {reason}")
            }
        }
    }
    #[must_use]
    pub fn current(&self) -> bool {
        !self.invalidated
            && self.publication.error.is_none()
            && matches!(self.publication.state, TrafficPreviewState::Completed(_))
    }
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.publication
            .state
            .evidence()
            .map_or(0, |e| e.pairs.len() * e.suite.scenarios.len())
    }
    #[must_use]
    pub fn content(&self) -> DetailsContent {
        let mut lines = vec![
            ("Status".into(), self.status()),
            ("Safety".into(), "Live connectivity: NOT VERIFIED. Informational; apply requires the existing confirmation. Read-only preview executes no firewall commands.".into()),
            ("Keys".into(), "↑/↓ select · Enter details · PgUp/PgDn scroll · Esc return to review".into()),
        ];
        if let Some(error) = self.publication.audit.failure {
            lines.push(("Audit warning".into(), error.to_string()));
        } else if self.publication.audit.backpressure {
            lines.push((
                "Audit warning".into(),
                "Traffic audit backlog full; evaluation paused until persistence progresses".into(),
            ));
        }
        if let Some(e) = self.publication.state.evidence() {
            lines.push((
                "Excluded".into(),
                format!(
                    "{} disabled scenarios (suite total)",
                    e.suite.scenarios.iter().filter(|s| !s.enabled).count()
                ),
            ));
            for (pair_index, pair) in e.pairs.iter().enumerate() {
                let counts = if self.current() {
                    pair.counts.map_or_else(|| "Comparison unavailable".into(), |c| format!("{} regressions · {} improvements · {} unchanged status · 0 unavailable", c.regressions, c.improvements, c.unchanged))
                } else {
                    format!(
                        "{} comparisons unavailable — incomplete or stale evidence",
                        e.suite.scenarios.iter().filter(|s| s.enabled).count()
                    )
                };
                lines.push((format!("{:?}", pair.target), counts));
                for (index, scenario) in e.suite.scenarios.iter().enumerate() {
                    let before = result(pair.before.as_deref(), scenario);
                    let after = result(pair.after.as_deref(), scenario);
                    let change = if !scenario.enabled {
                        "Excluded (disabled)".into()
                    } else if self.current() {
                        before
                            .zip(after)
                            .and_then(|(a, b)| {
                                crate::domain::traffic_change(a.status(), b.status()).ok()
                            })
                            .map_or_else(|| "Unavailable".into(), |c| format!("{c:?} status"))
                    } else {
                        "Unavailable (captured evidence)".into()
                    };
                    let marker = if pair_index * e.suite.scenarios.len() + index == self.selected {
                        "> "
                    } else {
                        ""
                    };
                    lines.push((
                        format!("{marker}{} [{:?}]", scenario.name, scenario.severity),
                        format!(
                            "Before: {} | After: {} | Change: {change}",
                            outcome(before),
                            outcome(after)
                        ),
                    ));
                }
            }
            lines.push(("Uncertainty".into(), "Indeterminate is unknown, not Pass. Improvement may remain unknown; unchanged status does not prove no impact.".into()));
        }
        DetailsContent {
            title: "Traffic impact preview".into(),
            lines,
        }
    }
    #[must_use]
    pub fn details(&self) -> Option<DetailsContent> {
        let evidence = self.publication.state.evidence()?;
        let count = evidence.suite.scenarios.len();
        if count == 0 {
            return None;
        }
        let pair = evidence.pairs.get(self.selected / count)?;
        let scenario = evidence.suite.scenarios.get(self.selected % count)?;
        let mut lines = vec![
            ("Preview status".into(), self.status()),
            ("Capture".into(), "Immutable captured evidence. Reopen after changes. Live connectivity: NOT VERIFIED.".into()),
            ("Target".into(), format!("{:?}", pair.target)),
        ];
        lines.extend(super::traffic_tests::details::inputs(scenario));
        for (label, report) in [("Before", &pair.before), ("After", &pair.after)] {
            lines.push((label.into(), "Captured configuration evidence".into()));
            if let Some(r) = result(report.as_deref(), scenario) {
                super::traffic_tests::details::result_lines(&mut lines, r);
            } else {
                lines.push((
                    "Result unavailable".into(),
                    if scenario.enabled {
                        "No completed result"
                    } else {
                        "Scenario disabled; excluded"
                    }
                    .into(),
                ));
            }
        }
        Some(DetailsContent {
            title: format!("Traffic preview: {}", scenario.name),
            lines,
        })
    }
}
