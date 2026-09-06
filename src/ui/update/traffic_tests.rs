//! Traffic-only reducer routing, with no filesystem or firewall operations.

use crate::domain::EvaluationTarget;
use crate::ui::{
    action::{Effect, UiAction},
    state::UiState,
};

pub(super) fn update(state: &mut UiState, action: UiAction) -> Vec<Effect> {
    match action {
        UiAction::TrafficReload => {
            state.traffic.load_requested = true;
            vec![Effect::TrafficLoad]
        }
        UiAction::TrafficEvaluate => vec![Effect::TrafficEvaluate],
        UiAction::TrafficToggleTarget => vec![Effect::TrafficTarget(
            if state.offline || state.traffic.target == EvaluationTarget::Runtime {
                EvaluationTarget::Permanent
            } else {
                EvaluationTarget::Runtime
            },
        )],
        UiAction::TrafficPresented(presentation) => {
            state.traffic = presentation;
            super::clamp_selection(state);
            Vec::new()
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{
        application::{ObservedSnapshot, RefreshId, SnapshotGeneration, SnapshotIdentity},
        config::Config,
    };
    use std::sync::Arc;

    #[test]
    fn only_accepted_refresh_forwards_the_exact_envelope() {
        use crate::application::{RefreshScheduleObservation, RefreshTrigger};
        let mut state = UiState::new(&Config::default(), "test".into(), false, None);
        let snapshot = Arc::new(crate::domain::mock::sample().unwrap());
        let active = RefreshId::new(2);
        state.active_refresh = Some(active);
        for (schedule_id, envelope_id) in [
            (RefreshId::new(1), active),
            (active, RefreshId::new(1)),
            (active, active),
        ] {
            let envelope = ObservedSnapshot::new(
                SnapshotIdentity::new(
                    envelope_id,
                    SnapshotGeneration::new(std::num::NonZeroU64::MIN),
                ),
                Arc::clone(&snapshot),
            );
            let effects = super::super::update(
                &mut state,
                UiAction::RefreshCompleted {
                    schedule: RefreshScheduleObservation {
                        id: schedule_id,
                        trigger: RefreshTrigger::Manual,
                        merged_manual_requests: 0,
                        coalesced_periodic_ticks: 0,
                    },
                    result: Ok(envelope.clone()),
                    observation: crate::domain::RefreshObservation::total_only(
                        std::time::Duration::ZERO,
                    ),
                },
            );
            if schedule_id == active && envelope_id == active {
                assert_eq!(state.traffic_observation, Some(envelope.clone()));
                assert!(Arc::ptr_eq(
                    state.traffic_observation.as_ref().unwrap().snapshot_arc(),
                    &snapshot
                ));
                assert_eq!(effects, vec![Effect::TrafficObserve(Some(envelope))]);
            } else {
                assert!(state.traffic_observation.is_none());
                assert!(effects.is_empty());
            }
        }
    }

    #[test]
    fn engine_closure_revokes_retained_traffic_evidence() {
        let mut state = UiState::new(&Config::default(), "test".into(), false, None);
        let observed = ObservedSnapshot::new(
            SnapshotIdentity::new(
                RefreshId::new(1),
                SnapshotGeneration::new(std::num::NonZeroU64::MIN),
            ),
            Arc::new(crate::domain::mock::sample().unwrap()),
        );
        state.traffic_observation = Some(observed);
        state.traffic.authoritative = true;
        let effects = super::super::update(
            &mut state,
            UiAction::EngineStopped(crate::application::ports::FirewallError::Process(
                "closed".into(),
            )),
        );
        assert!(
            state.traffic_observation.is_none(),
            "closed engine must revoke evidence"
        );
        assert_eq!(effects, vec![Effect::TrafficObserve(None)]);
    }

    #[test]
    fn local_keys_route_only_inside_traffic_workspace() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut state = UiState::new(&Config::default(), "test".into(), false, None);
        state.view = crate::ui::views::ViewId::TrafficTests;
        for (key, expected) in [
            ('e', UiAction::TrafficEvaluate),
            ('r', UiAction::TrafficReload),
            ('t', UiAction::TrafficToggleTarget),
        ] {
            assert_eq!(
                crate::ui::keymap::translate(&state, KeyEvent::from(KeyCode::Char(key))),
                Some(expected)
            );
        }
    }

    #[test]
    fn confirmed_mutation_revokes_traffic_evidence_before_dispatch() {
        let mut state = UiState::new(&Config::default(), "test".into(), false, None);
        let snapshot = Arc::new(crate::domain::mock::sample().unwrap());
        state.snapshot = Some(Arc::clone(&snapshot));
        state.traffic_observation = Some(ObservedSnapshot::new(
            SnapshotIdentity::new(
                RefreshId::new(1),
                SnapshotGeneration::new(std::num::NonZeroU64::MIN),
            ),
            Arc::clone(&snapshot),
        ));
        let request = crate::application::MutationRequest::new(
            crate::domain::FirewallOperation::Reload,
            snapshot,
        );
        let effects = super::super::update(&mut state, UiAction::ApplyOperation(request));
        assert!(
            effects
                .iter()
                .any(|effect| matches!(effect, Effect::Apply(_)))
        );
        assert!(
            state.traffic_observation.is_none(),
            "mutation must revoke evidence immediately"
        );
        assert!(matches!(
            effects.first(),
            Some(Effect::TrafficObserve(None))
        ));
    }

    #[test]
    fn nested_confirmation_revokes_evidence_once() {
        let mut state = UiState::new(&Config::default(), "test".into(), false, None);
        let snapshot = Arc::new(crate::domain::mock::sample().unwrap());
        state.snapshot = Some(Arc::clone(&snapshot));
        state.traffic.load_requested = true;
        state.overlays.push(crate::ui::overlays::Overlay::Confirm(
            crate::ui::overlays::Confirmation {
                title: "Reload".into(),
                body: vec![],
                on_confirm: UiAction::ApplyOperation(crate::application::MutationRequest::new(
                    crate::domain::FirewallOperation::Reload,
                    snapshot,
                )),
            },
        ));
        let effects = super::super::update(&mut state, UiAction::ConfirmAccept);
        assert_eq!(
            effects
                .iter()
                .filter(|effect| matches!(effect, Effect::TrafficObserve(None)))
                .count(),
            1
        );
    }
}
