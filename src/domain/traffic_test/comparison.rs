//! Pure comparison of complete, target-matched preview evidence.
use super::{
    EvaluationContext, EvaluationPhase, TrafficSuite, TrafficTestReport, TrafficTestStatus,
};

/// Change in terminal expectation status; uncertainty remains visible in reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficChange {
    /// Status moved away from satisfying the expectation.
    Regression,
    /// Status improved, potentially only to uncertainty.
    Improvement,
    /// Same status; does not prove absence of impact.
    Unchanged,
}

/// Counts for one fully validated pair.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrafficComparisonCounts {
    /// Worsened statuses.
    pub regressions: usize,
    /// Improved statuses.
    pub improvements: usize,
    /// Identical terminal statuses.
    pub unchanged: usize,
    /// Disabled scenarios excluded from comparison.
    pub disabled: usize,
}

/// Invalid or incomplete evidence must never produce comparison counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("traffic comparison evidence is incomplete or mismatched")]
pub struct TrafficComparisonError;

/// Requires exact context, enabled scenario coverage, and saved expectations.
pub fn validate_preview_report(
    report: &TrafficTestReport,
    context: &EvaluationContext,
    suite: &TrafficSuite,
) -> Result<(), TrafficComparisonError> {
    if report.context() != context
        || context.validate().is_err()
        || suite.validate().is_err()
        || suite.id != context.suite_id
        || suite.revision != context.suite_revision
        || report.results().len() != suite.scenarios.iter().filter(|s| s.enabled).count()
    {
        return Err(TrafficComparisonError);
    }
    for scenario in suite.scenarios.iter().filter(|s| s.enabled) {
        if !report
            .results()
            .iter()
            .any(|r| r.scenario_id() == &scenario.id && r.expectation() == scenario.expectation)
        {
            return Err(TrafficComparisonError);
        }
    }
    Ok(())
}

/// Compares terminal outcomes without treating unknown evidence as a pass.
pub fn traffic_change(
    before: TrafficTestStatus,
    after: TrafficTestStatus,
) -> Result<TrafficChange, TrafficComparisonError> {
    use TrafficTestStatus::{Fail, Indeterminate, Pass};
    match (before, after) {
        (Pass, Fail | Indeterminate) | (Indeterminate, Fail) => Ok(TrafficChange::Regression),
        (Fail, Pass | Indeterminate) | (Indeterminate, Pass) => Ok(TrafficChange::Improvement),
        (Pass, Pass) | (Fail, Fail) | (Indeterminate, Indeterminate) => {
            Ok(TrafficChange::Unchanged)
        }
        _ => Err(TrafficComparisonError),
    }
}

/// Validates both sides against the outer batch contexts before comparing.
pub fn compare_traffic_reports(
    suite: &TrafficSuite,
    before_context: &EvaluationContext,
    after_context: &EvaluationContext,
    before: &TrafficTestReport,
    after: &TrafficTestReport,
) -> Result<TrafficComparisonCounts, TrafficComparisonError> {
    validate_preview_report(before, before_context, suite)?;
    validate_preview_report(after, after_context, suite)?;
    if before_context.phase != EvaluationPhase::Current
        || after_context.phase != EvaluationPhase::StagedCandidate
        || before_context.target != after_context.target
        || before_context.authoritative_snapshot != after_context.authoritative_snapshot
        || before_context.run_id == after_context.run_id
    {
        return Err(TrafficComparisonError);
    }
    let mut counts = TrafficComparisonCounts {
        disabled: suite.scenarios.iter().filter(|s| !s.enabled).count(),
        ..TrafficComparisonCounts::default()
    };
    for a in before.results() {
        let b = after
            .results()
            .iter()
            .find(|r| r.scenario_id() == a.scenario_id())
            .ok_or(TrafficComparisonError)?;
        match traffic_change(a.status(), b.status())? {
            TrafficChange::Regression => counts.regressions += 1,
            TrafficChange::Improvement => counts.improvements += 1,
            TrafficChange::Unchanged => counts.unchanged += 1,
        }
    }
    Ok(counts)
}
