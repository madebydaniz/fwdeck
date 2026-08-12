use std::collections::VecDeque;
use std::num::NonZeroU64;

use crate::application::{EngineRequest, ManualRefreshRequest, RollbackRequest};

pub(super) const ROLLBACK_OUTBOX_CAPACITY: usize = 32;

pub(super) struct EngineOutbox {
    normal: Option<EngineRequest>,
    manual_count: u64,
    rollbacks: VecDeque<RollbackRequest>,
}

impl Default for EngineOutbox {
    fn default() -> Self {
        Self {
            normal: None,
            manual_count: 0,
            rollbacks: VecDeque::with_capacity(ROLLBACK_OUTBOX_CAPACITY),
        }
    }
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
        assert_eq!(outbox.take_rollback(), Some(rollback_request(1)));
    }
}
