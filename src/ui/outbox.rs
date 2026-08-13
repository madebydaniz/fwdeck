use std::collections::VecDeque;
use std::num::NonZeroU64;

use tokio::sync::mpsc;

use crate::application::{EngineRequest, ManualRefreshRequest, RollbackRequest};
use crate::ui::action::UiAction;

use super::action::Effect;

pub(super) const ROLLBACK_OUTBOX_CAPACITY: usize = 32;

pub(super) struct EngineOutbox {
    normal: Option<EngineRequest>,
    manual_count: u64,
    rollbacks: VecDeque<RollbackRequest>,
    normal_closed: bool,
    manual_closed: bool,
    rollback_closed: bool,
    rollback_in_flight: std::collections::HashSet<crate::application::RollbackGuardId>,
}

impl Default for EngineOutbox {
    fn default() -> Self {
        Self {
            normal: None,
            manual_count: 0,
            rollbacks: VecDeque::with_capacity(ROLLBACK_OUTBOX_CAPACITY),
            normal_closed: false,
            manual_closed: false,
            rollback_closed: false,
            rollback_in_flight: std::collections::HashSet::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DispatchKind {
    Rollback,
    Manual,
    Normal,
}

#[derive(Debug)]
pub(super) enum DispatchOutcome {
    Sent {
        kind: DispatchKind,
        rollback_id: Option<crate::application::RollbackGuardId>,
        normal_pending: bool,
        rollback_pending: usize,
    },
    Closed {
        kind: DispatchKind,
        error: crate::application::FirewallError,
    },
}

impl DispatchOutcome {
    pub(super) const fn kind(&self) -> DispatchKind {
        match self {
            Self::Sent { kind, .. } | Self::Closed { kind, .. } => *kind,
        }
    }

    pub(super) const fn rollback_id(&self) -> Option<crate::application::RollbackGuardId> {
        match self {
            Self::Sent { rollback_id, .. } => *rollback_id,
            Self::Closed { .. } => None,
        }
    }

    pub(super) fn into_ui_action(self) -> UiAction {
        match self {
            Self::Sent {
                normal_pending,
                rollback_pending,
                ..
            } => UiAction::EngineOutboxChanged {
                normal_pending,
                rollback_pending,
            },
            Self::Closed { error, .. } => UiAction::EngineStopped(error),
        }
    }
}

#[derive(Debug, PartialEq)]
#[allow(clippy::large_enum_variant)] // The interface must return a non-engine Effect unchanged.
pub(super) enum EngineEffectDisposition {
    Queued,
    NotEngineBound(Effect),
}

#[derive(Debug, PartialEq)]
pub(super) enum OutboxEnqueueError {
    Normal(NormalEnqueueError),
    Manual(ManualEnqueueError),
    Rollback(RollbackEnqueueError),
}

#[derive(Debug, PartialEq)]
pub(super) enum NormalEnqueueError {
    Full(EngineRequest),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ManualEnqueueError {
    CountOverflow,
}

#[derive(Debug, PartialEq)]
pub(super) enum RollbackEnqueueError {
    Full(RollbackRequest),
}

impl EngineOutbox {
    pub(super) fn new() -> Self {
        Self::default()
    }

    #[allow(clippy::result_large_err)] // The rejected request must remain owned by the caller.
    pub(super) fn enqueue_normal(
        &mut self,
        request: EngineRequest,
    ) -> Result<(), NormalEnqueueError> {
        if self.normal.is_some() {
            return Err(NormalEnqueueError::Full(request));
        }
        self.normal = Some(request);
        Ok(())
    }

    pub(super) fn add_manual(&mut self, count: NonZeroU64) -> Result<(), ManualEnqueueError> {
        let next = self
            .manual_count
            .checked_add(count.get())
            .ok_or(ManualEnqueueError::CountOverflow)?;
        self.manual_count = next;
        Ok(())
    }

    #[allow(clippy::result_large_err)] // The rejected rollback must remain owned by the caller.
    pub(super) fn enqueue_rollback(
        &mut self,
        request: RollbackRequest,
    ) -> Result<(), RollbackEnqueueError> {
        if self.rollbacks.len() == ROLLBACK_OUTBOX_CAPACITY {
            return Err(RollbackEnqueueError::Full(request));
        }
        self.rollbacks.push_back(request);
        Ok(())
    }

    pub(super) fn take_normal(&mut self) -> Option<EngineRequest> {
        self.normal.take()
    }

    pub(super) fn take_manual(&mut self) -> Option<ManualRefreshRequest> {
        let count = NonZeroU64::new(self.manual_count)?;
        self.manual_count = 0;
        Some(ManualRefreshRequest::new(count))
    }

    pub(super) fn take_rollback(&mut self) -> Option<RollbackRequest> {
        self.rollbacks.pop_front()
    }

    pub(super) const fn normal_pending(&self) -> bool {
        self.normal.is_some()
    }

    pub(super) fn rollback_pending(&self) -> usize {
        self.rollbacks.len()
    }

    pub(super) fn has_dispatchable(&self) -> bool {
        (!self.rollback_closed && !self.rollbacks.is_empty())
            || (!self.manual_closed && self.manual_count != 0)
            || (!self.normal_closed && self.normal.is_some())
    }

    pub(super) fn has_dispatchable_rollback(&self) -> bool {
        !self.rollback_closed && !self.rollbacks.is_empty()
    }

    pub(super) fn abandon_non_rollbacks(&mut self) -> Option<EngineRequest> {
        self.manual_count = 0;
        self.normal.take()
    }

    pub(super) fn rollback_in_flight_ids(
        &self,
    ) -> std::collections::HashSet<crate::application::RollbackGuardId> {
        self.rollback_in_flight.clone()
    }

    pub(super) fn complete_rollback(&mut self, id: crate::application::RollbackGuardId) {
        self.rollback_in_flight.remove(&id);
    }

    pub(super) async fn dispatch_one(
        &mut self,
        rollbacks: &mpsc::Sender<RollbackRequest>,
        manual_refreshes: &mpsc::Sender<ManualRefreshRequest>,
        requests: &mpsc::Sender<EngineRequest>,
    ) -> DispatchOutcome {
        let can_rollback = !self.rollback_closed && !self.rollbacks.is_empty();
        let can_manual = !self.manual_closed && self.manual_count != 0;
        let can_normal = !self.normal_closed && self.normal.is_some();

        tokio::select! {
            biased;
            permit = rollbacks.reserve(), if can_rollback => {
                if let Ok(permit) = permit {
                    let Some(request) = self.take_rollback() else {
                        return std::future::pending().await;
                    };
                    let id = request.id;
                    permit.send(request);
                    self.rollback_in_flight.insert(id);
                    self.sent(DispatchKind::Rollback, Some(id))
                } else {
                    self.rollback_closed = true;
                    let identity = self.rollbacks.front().map_or_else(
                        || "unknown rollback".to_owned(),
                        |request| format!(
                            "rollback {} ({})",
                            request.id.get(),
                            request.operation.describe()
                        ),
                    );
                    Self::closed(
                        DispatchKind::Rollback,
                        format!("engine is gone — {identity} not sent"),
                    )
                }
            }
            permit = manual_refreshes.reserve(), if can_manual => {
                if let Ok(permit) = permit {
                    let Some(request) = self.take_manual() else {
                        return std::future::pending().await;
                    };
                    permit.send(request);
                    self.sent(DispatchKind::Manual, None)
                } else {
                    self.manual_closed = true;
                    Self::closed(
                        DispatchKind::Manual,
                        format!(
                            "engine is gone — manual refresh batch of {} request(s) not sent",
                            self.manual_count
                        ),
                    )
                }
            }
            permit = requests.reserve(), if can_normal => {
                if let Ok(permit) = permit {
                    let Some(request) = self.take_normal() else {
                        return std::future::pending().await;
                    };
                    permit.send(request);
                    self.sent(DispatchKind::Normal, None)
                } else {
                    self.normal_closed = true;
                    let identity = self.normal.as_ref().map_or_else(
                        || "engine request".to_owned(),
                        describe_normal_request,
                    );
                    Self::closed(
                        DispatchKind::Normal,
                        format!("engine is gone — {identity} not sent"),
                    )
                }
            }
            else => std::future::pending().await,
        }
    }

    fn sent(
        &self,
        kind: DispatchKind,
        rollback_id: Option<crate::application::RollbackGuardId>,
    ) -> DispatchOutcome {
        DispatchOutcome::Sent {
            kind,
            rollback_id,
            normal_pending: self.normal_pending(),
            rollback_pending: self.rollback_pending(),
        }
    }

    fn closed(kind: DispatchKind, message: String) -> DispatchOutcome {
        DispatchOutcome::Closed {
            kind,
            error: crate::application::FirewallError::Process(message),
        }
    }
}

#[allow(clippy::result_large_err)] // Rejected confirmed work stays owned by the caller.
pub(super) fn enqueue_engine_effect(
    outbox: &mut EngineOutbox,
    effect: Effect,
) -> Result<EngineEffectDisposition, OutboxEnqueueError> {
    match effect {
        Effect::Apply(request) => outbox
            .enqueue_normal(EngineRequest::Apply(request))
            .map(|()| EngineEffectDisposition::Queued)
            .map_err(OutboxEnqueueError::Normal),
        Effect::ApplyPlan(plan) => outbox
            .enqueue_normal(EngineRequest::ApplyPlan(plan))
            .map(|()| EngineEffectDisposition::Queued)
            .map_err(OutboxEnqueueError::Normal),
        Effect::Refresh => outbox
            .add_manual(NonZeroU64::MIN)
            .map(|()| EngineEffectDisposition::Queued)
            .map_err(OutboxEnqueueError::Manual),
        Effect::ApplyRollback {
            id,
            operation,
            watchdog_unit,
        } => outbox
            .enqueue_rollback(RollbackRequest {
                id,
                operation,
                watchdog_unit,
            })
            .map(|()| EngineEffectDisposition::Queued)
            .map_err(OutboxEnqueueError::Rollback),
        effect => Ok(EngineEffectDisposition::NotEngineBound(effect)),
    }
}

fn describe_normal_request(request: &EngineRequest) -> String {
    match request {
        EngineRequest::Apply(request) => format!("operation {}", request.operation.describe()),
        EngineRequest::ApplyPlan(plan) => {
            format!("plan with {} operation(s)", plan.operations.len())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

    use crate::application::{
        EngineRequest, ManualRefreshRequest, MutationRequest, RollbackGuardId, RollbackRequest,
    };
    use crate::domain::{ConfigurationTarget, FirewallOperation, ServiceName, ZoneName, mock};

    use super::*;

    fn normal_request(service: &str) -> EngineRequest {
        EngineRequest::Apply(MutationRequest::new(
            FirewallOperation::AddService {
                zone: ZoneName::parse("public").unwrap(),
                service: ServiceName::parse(service).unwrap(),
                target: ConfigurationTarget::Runtime,
            },
            Arc::new(mock::sample().unwrap()),
        ))
    }

    fn rollback_request(id: u64) -> RollbackRequest {
        RollbackRequest {
            id: RollbackGuardId::new(id),
            operation: FirewallOperation::RemoveService {
                zone: ZoneName::parse("public").unwrap(),
                service: ServiceName::parse("ssh").unwrap(),
                target: ConfigurationTarget::Runtime,
            },
            watchdog_unit: None,
        }
    }

    #[test]
    fn normal_slot_never_drops_or_reorders_confirmed_work() {
        let mut outbox = EngineOutbox::new();
        let first = normal_request("http");
        let second = normal_request("https");
        assert!(outbox.enqueue_normal(first.clone()).is_ok());
        assert_eq!(
            outbox.enqueue_normal(second.clone()),
            Err(NormalEnqueueError::Full(second))
        );
        assert_eq!(outbox.take_normal(), Some(first));
        assert_eq!(outbox.take_normal(), None);
    }

    #[test]
    fn manual_demand_aggregates_exactly_and_rejects_overflow() {
        let mut outbox = EngineOutbox::new();
        outbox
            .add_manual(NonZeroU64::new(u64::MAX).unwrap())
            .unwrap();
        assert_eq!(
            outbox.add_manual(NonZeroU64::MIN),
            Err(ManualEnqueueError::CountOverflow)
        );
        assert_eq!(
            outbox.take_manual().map(ManualRefreshRequest::count),
            NonZeroU64::new(u64::MAX)
        );
    }

    #[test]
    fn rollback_fifo_is_bounded_at_thirty_two() {
        let mut outbox = EngineOutbox::new();
        for id in 1..=32 {
            outbox.enqueue_rollback(rollback_request(id)).unwrap();
        }
        let overflow = rollback_request(33);
        assert_eq!(
            outbox.enqueue_rollback(overflow.clone()),
            Err(RollbackEnqueueError::Full(overflow))
        );
        for id in 1..=32 {
            assert_eq!(outbox.take_rollback(), Some(rollback_request(id)));
        }
        assert_eq!(outbox.take_rollback(), None);
    }
}
