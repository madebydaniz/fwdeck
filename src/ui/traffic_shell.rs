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
    preview: super::traffic_preview::Publication,
    pending_preview: bool,
    preview_admitted: bool,
    audit_sink: Option<Arc<dyn crate::application::traffic_test_audit::TrafficAuditSink>>,
}

impl<S: TrafficSuiteStorage> TrafficShell<S> {
    pub(super) fn new(storage: Option<Arc<S>>) -> Self {
        Self {
            service: None,
            storage,
            armed: false,
            preview: super::traffic_preview::Publication::default(),
            pending_preview: false,
            preview_admitted: false,
            audit_sink: None,
        }
    }
    pub(super) fn with_audit(
        storage: Option<Arc<S>>,
        sink: Arc<dyn crate::application::traffic_test_audit::TrafficAuditSink>,
    ) -> Self {
        let mut shell = Self::new(storage);
        shell.audit_sink = Some(sink);
        shell
    }
    pub(super) fn route(&mut self, effect: &Effect, state: &UiState) -> Option<UiAction> {
        if !matches!(
            effect,
            Effect::TrafficLoad
                | Effect::TrafficSave(_)
                | Effect::TrafficEvaluate
                | Effect::TrafficTarget(_)
                | Effect::TrafficObserve(_)
                | Effect::TrafficPreview(_)
                | Effect::TrafficPreviewCancel
        ) {
            return None;
        }
        if let Effect::TrafficPreview(request) = effect {
            self.preview = super::traffic_preview::Publication {
                owner: Some(Arc::clone(request)),
                ..Default::default()
            };
            self.pending_preview = false;
            self.preview_admitted = false;
        }
        if matches!(effect, Effect::TrafficPreviewCancel) {
            self.pending_preview = false;
            self.preview = super::traffic_preview::Publication::default();
            self.preview_admitted = false;
        }
        if self.service.is_none() {
            if let Effect::TrafficSave(candidate) = effect {
                return Some(UiAction::TrafficSaveRejected(
                    Arc::clone(candidate),
                    "Traffic test service unavailable; reload the default suite before saving"
                        .into(),
                ));
            }
            if !matches!(effect, Effect::TrafficLoad | Effect::TrafficPreview(_)) {
                return None;
            }
            if let Some(action) = self.initialize(state) {
                return Some(action);
            }
        }
        let service = self.service.as_mut()?;
        let result = match effect {
            Effect::TrafficPreview(request) => match service.workspace().suite_state() {
                crate::application::SuiteState::NotLoaded => match service.try_load() {
                    Ok(_) => {
                        self.armed = true;
                        self.pending_preview = true;
                        self.preview.loading = true;
                        Ok(())
                    }
                    Err(error) => Err(error),
                },
                crate::application::SuiteState::Loading(_) => {
                    self.pending_preview = true;
                    self.preview.loading = true;
                    Ok(())
                }
                _ => {
                    let result = service.try_preview((**request).clone());
                    self.preview_admitted = result.is_ok();
                    if self.preview_admitted {
                        self.armed = true;
                    }
                    result
                }
            },
            Effect::TrafficPreviewCancel => service.cancel_preview(),
            Effect::TrafficSave(candidate) => {
                if let Err(error) = service.try_save(Arc::clone(candidate)) {
                    return Some(UiAction::TrafficSaveRejected(
                        Arc::clone(candidate),
                        error.to_string(),
                    ));
                }
                self.armed = true;
                Ok(())
            }
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
        self.publish_result(effect, result)
    }

    fn publish_result(
        &mut self,
        effect: &Effect,
        result: Result<(), crate::application::TrafficServiceError>,
    ) -> Option<UiAction> {
        let service = self.service.as_ref()?;
        let mut presentation = TrafficPresentation::from_workspace(service.workspace());
        presentation.save = service.save_state().clone();
        presentation.audit = service.audit_status();
        presentation.error = result.err().map(|error| error.to_string());
        if matches!(effect, Effect::TrafficPreview(_)) {
            self.preview.error.clone_from(&presentation.error);
            if matches!(
                service.workspace().suite_state(),
                crate::application::SuiteState::Missing
                    | crate::application::SuiteState::UnsupportedSchema(_)
                    | crate::application::SuiteState::Failed(_)
            ) {
                self.preview.error = Some(presentation.message());
            }
        }
        if matches!(
            effect,
            Effect::TrafficObserve(_)
                | Effect::TrafficLoad
                | Effect::TrafficSave(_)
                | Effect::TrafficEvaluate
                | Effect::TrafficTarget(_)
        ) && self.pending_preview
        {
            self.pending_preview = false;
            self.preview.loading = false;
            self.preview.error =
                Some("Preview cancelled: captured context changed; reopen the review".into());
        }
        if self.preview_admitted {
            self.preview.state = service.preview_state().clone();
        }
        self.preview.audit = service.audit_status();
        presentation.preview = Box::new(self.preview.clone());
        Some(UiAction::TrafficPresented(presentation))
    }

    fn initialize(&mut self, state: &UiState) -> Option<UiAction> {
        let Some(storage) = &self.storage else {
            let mut presentation = state.traffic.clone();
            presentation.load_requested = true;
            presentation.error = Some(
                "Application config directory unavailable; no default suite path can be resolved."
                    .into(),
            );
            self.preview.error.clone_from(&presentation.error);
            self.preview.audit = state.traffic.audit;
            presentation.preview = Box::new(self.preview.clone());
            return Some(UiAction::TrafficPresented(presentation));
        };
        let mut service = match &self.audit_sink {
            Some(sink) => TrafficTestService::with_audit_sink(
                state.offline,
                Arc::clone(storage),
                Arc::clone(sink),
            ),
            None => TrafficTestService::new(state.offline, Arc::clone(storage)),
        };
        if let Some(observed) = &state.traffic_observation {
            let _ = service.observe(observed.clone());
        }
        self.service = Some(service);
        None
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
        if self.pending_preview && matches!(event, TrafficServiceEvent::Loaded(_)) {
            self.pending_preview = false;
            self.preview.loading = false;
            if matches!(event, TrafficServiceEvent::Loaded(Ok(()))) {
                if let Some(request) = &self.preview.owner {
                    let result = service.try_preview((**request).clone());
                    self.preview_admitted = result.is_ok();
                    self.preview.error = result.err().map(|error| error.to_string());
                }
            } else {
                self.preview.error = Some("Saved default suite could not be loaded".into());
            }
            if !matches!(
                service.workspace().suite_state(),
                crate::application::SuiteState::Available(_)
            ) {
                self.preview.error =
                    Some(TrafficPresentation::from_workspace(service.workspace()).message());
            }
        }
        if self.preview_admitted {
            self.preview.state = service.preview_state().clone();
        }
        let mut presentation = TrafficPresentation::from_workspace(service.workspace());
        self.preview.audit = service.audit_status();
        presentation.preview = Box::new(self.preview.clone());
        presentation.save = service.save_state().clone();
        presentation.audit = service.audit_status();
        presentation.error = match event {
            TrafficServiceEvent::Loaded(Err(error))
            | TrafficServiceEvent::Saved {
                result: Err(error), ..
            } => Some(error.to_string()),
            TrafficServiceEvent::EvaluationSubmitted(Err(error))
            | TrafficServiceEvent::Saved {
                cancellation_error: Some(error),
                ..
            } => Some(error.to_string()),
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
