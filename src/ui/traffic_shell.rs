//! Lazy owned traffic service; no automatic loading or detached work.

use super::traffic_tests::TrafficPresentation;
use super::{
    action::{Effect, UiAction},
    state::UiState,
};
use crate::application::{
    TrafficServiceEvent, TrafficServiceShutdownError, TrafficSuiteStorage, TrafficTestService,
};
use std::sync::Arc;

pub(super) struct TrafficShell<S: TrafficSuiteStorage> {
    service: Option<TrafficTestService<S>>,
    storage: Option<Arc<S>>,
    armed: bool,
}

impl<S: TrafficSuiteStorage> TrafficShell<S> {
    pub(super) fn new(storage: Option<Arc<S>>) -> Self {
        Self {
            service: None,
            storage,
            armed: false,
        }
    }
    pub(super) fn route(&mut self, effect: &Effect, state: &UiState) -> Option<UiAction> {
        if !matches!(
            effect,
            Effect::TrafficLoad
                | Effect::TrafficEvaluate
                | Effect::TrafficTarget(_)
                | Effect::TrafficObserve(_)
        ) {
            return None;
        }
        if self.service.is_none() {
            if !matches!(effect, Effect::TrafficLoad) {
                return None;
            }
            let Some(storage) = &self.storage else {
                let mut presentation = state.traffic.clone();
                presentation.load_requested = true;
                presentation.error = Some("Application config directory unavailable; no default suite path can be resolved.".into());
                return Some(UiAction::TrafficPresented(presentation));
            };
            let mut service = TrafficTestService::new(state.offline, Arc::clone(storage));
            if let Some(observed) = &state.traffic_observation {
                let _ = service.observe(observed.clone());
            }
            self.service = Some(service);
        }
        let service = self.service.as_mut()?;
        let result = match effect {
            Effect::TrafficLoad => service.try_load().and_then(|accepted| {
                self.armed = true;
                accepted.cancellation_error.map_or(Ok(()), Err)
            }),
            Effect::TrafficEvaluate => service.try_evaluate(),
            Effect::TrafficTarget(target) => service.set_target(*target).map(|_| ()),
            Effect::TrafficObserve(Some(observed)) => service.observe(observed.clone()).map(|_| ()),
            Effect::TrafficObserve(None) => service.clear_observation(),
            _ => return None,
        };
        let mut presentation = TrafficPresentation::from_workspace(service.workspace());
        presentation.error = result.err().map(|error| error.to_string());
        Some(UiAction::TrafficPresented(presentation))
    }

    pub(super) const fn armed(&self) -> bool {
        self.armed
    }

    pub(super) async fn next_action(&mut self) -> Option<UiAction> {
        let service = self.service.as_mut()?;
        let Some(event) = service.next_event().await else {
            self.armed = false;
            return None;
        };
        let mut presentation = TrafficPresentation::from_workspace(service.workspace());
        presentation.error = match event {
            TrafficServiceEvent::Loaded(Err(error)) => Some(error.to_string()),
            TrafficServiceEvent::EvaluationSubmitted(Err(error)) => Some(error.to_string()),
            TrafficServiceEvent::CoordinatorClosed => Some("Traffic test service is closed".into()),
            _ => None,
        };
        Some(UiAction::TrafficPresented(presentation))
    }

    pub(super) async fn shutdown(&mut self) -> Result<(), TrafficServiceShutdownError> {
        let Some(service) = &mut self.service else {
            return Ok(());
        };
        loop {
            match service.shutdown().await {
                Err(TrafficServiceShutdownError::DeadlineExceeded) => {}
                result => return result,
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests;
