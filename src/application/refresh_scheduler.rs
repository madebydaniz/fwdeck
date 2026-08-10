use super::api::{RefreshId, RefreshScheduleObservation, RefreshTrigger};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RefreshStart {
    pub id: RefreshId,
    pub trigger: RefreshTrigger,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RefreshCompletion {
    pub schedule: RefreshScheduleObservation,
    pub trailing_manual: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RefreshCancellation {
    pub schedule: RefreshScheduleObservation,
    pub trailing_manual: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefreshDemand {
    StartNow,
    Trailing,
    Coalesced,
}

pub(crate) struct RefreshScheduler {
    next_id: u64,
    active: Option<ActiveRefresh>,
    trailing_manual: bool,
}

#[derive(Debug, Clone, Copy)]
struct ActiveRefresh {
    id: RefreshId,
    trigger: RefreshTrigger,
    merged_manual_requests: u64,
    coalesced_periodic_ticks: u64,
}

impl ActiveRefresh {
    const fn observation(self) -> RefreshScheduleObservation {
        RefreshScheduleObservation {
            id: self.id,
            trigger: self.trigger,
            merged_manual_requests: self.merged_manual_requests,
            coalesced_periodic_ticks: self.coalesced_periodic_ticks,
        }
    }
}

impl RefreshScheduler {
    pub(crate) const fn new() -> Self {
        Self {
            next_id: 1,
            active: None,
            trailing_manual: false,
        }
    }

    pub(crate) fn start(&mut self, trigger: RefreshTrigger) -> Option<RefreshStart> {
        if self.active.is_some() {
            return None;
        }
        let id = RefreshId::new(self.next_id);
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.active = Some(ActiveRefresh {
            id,
            trigger,
            merged_manual_requests: 0,
            coalesced_periodic_ticks: 0,
        });
        Some(RefreshStart { id, trigger })
    }

    pub(crate) fn active_id(&self) -> Option<RefreshId> {
        self.active.map(|active| active.id)
    }

    pub(crate) fn record_manual(&mut self) -> RefreshDemand {
        let Some(active) = self.active.as_mut() else {
            return RefreshDemand::StartNow;
        };
        active.merged_manual_requests = active.merged_manual_requests.saturating_add(1);
        if self.trailing_manual {
            RefreshDemand::Coalesced
        } else {
            self.trailing_manual = true;
            RefreshDemand::Trailing
        }
    }

    pub(crate) fn absorb_manual(&mut self) {
        if let Some(active) = self.active.as_mut() {
            active.merged_manual_requests = active.merged_manual_requests.saturating_add(1);
        }
    }

    pub(crate) fn record_periodic(&mut self) -> RefreshDemand {
        let Some(active) = self.active.as_mut() else {
            return RefreshDemand::StartNow;
        };
        active.coalesced_periodic_ticks = active.coalesced_periodic_ticks.saturating_add(1);
        RefreshDemand::Coalesced
    }

    pub(crate) fn cancel_for_mutation(&mut self) -> Option<RefreshScheduleObservation> {
        if !self
            .active
            .as_ref()
            .is_some_and(|active| active.trigger.is_preemptible())
        {
            return None;
        }
        let active = self.active.take()?;
        self.trailing_manual = false;
        Some(active.observation())
    }

    pub(crate) fn cancel_for_rollback(&mut self) -> Option<RefreshCancellation> {
        let active = self.active.take()?;
        let trailing_manual = std::mem::take(&mut self.trailing_manual);
        Some(RefreshCancellation {
            schedule: active.observation(),
            trailing_manual,
        })
    }

    pub(crate) fn finish(&mut self, id: RefreshId) -> Option<RefreshCompletion> {
        if self.active_id() != Some(id) {
            return None;
        }
        let active = self.active.take()?;
        let trailing_manual = std::mem::take(&mut self.trailing_manual);
        Some(RefreshCompletion {
            schedule: active.observation(),
            trailing_manual,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn manual_burst_creates_one_trailing_refresh() {
        let mut scheduler = RefreshScheduler::new();
        let active = scheduler.start(RefreshTrigger::Initial).unwrap();

        assert_eq!(scheduler.record_manual(), RefreshDemand::Trailing);
        for _ in 0..99 {
            assert_eq!(scheduler.record_manual(), RefreshDemand::Coalesced);
        }

        let finished = scheduler.finish(active.id).unwrap();
        assert!(finished.trailing_manual);
        assert_eq!(finished.schedule.merged_manual_requests, 100);
    }

    #[test]
    fn periodic_demand_never_creates_trailing_work() {
        let mut scheduler = RefreshScheduler::new();
        let active = scheduler.start(RefreshTrigger::Periodic).unwrap();
        for _ in 0..10 {
            assert_eq!(scheduler.record_periodic(), RefreshDemand::Coalesced);
        }
        let finished = scheduler.finish(active.id).unwrap();
        assert!(!finished.trailing_manual);
        assert_eq!(finished.schedule.coalesced_periodic_ticks, 10);
    }

    #[test]
    fn mutation_cancels_ordinary_but_not_post_mutation_refresh() {
        let mut scheduler = RefreshScheduler::new();
        scheduler.start(RefreshTrigger::Manual).unwrap();
        assert!(scheduler.cancel_for_mutation().is_some());

        let post = scheduler.start(RefreshTrigger::PostMutation).unwrap();
        assert!(scheduler.cancel_for_mutation().is_none());
        assert_eq!(scheduler.active_id(), Some(post.id));
    }

    #[test]
    fn safety_rollback_cancels_post_mutation_refresh() {
        let mut scheduler = RefreshScheduler::new();
        let post = scheduler.start(RefreshTrigger::PostMutation).unwrap();
        scheduler.record_manual();

        let cancelled = scheduler.cancel_for_rollback().unwrap();

        assert_eq!(cancelled.schedule.id, post.id);
        assert_eq!(cancelled.schedule.trigger, RefreshTrigger::PostMutation);
        assert_eq!(cancelled.schedule.merged_manual_requests, 1);
        assert!(cancelled.trailing_manual);
        assert_eq!(scheduler.active_id(), None);
    }

    #[test]
    fn absorbed_manual_demand_does_not_create_a_trailing_refresh() {
        let mut scheduler = RefreshScheduler::new();
        let post = scheduler.start(RefreshTrigger::PostMutation).unwrap();
        scheduler.absorb_manual();
        let finished = scheduler.finish(post.id).unwrap();
        assert!(!finished.trailing_manual);
        assert_eq!(finished.schedule.merged_manual_requests, 1);
    }

    #[test]
    fn idle_manual_demand_starts_now() {
        let mut scheduler = RefreshScheduler::new();

        assert_eq!(scheduler.record_manual(), RefreshDemand::StartNow);
    }

    #[test]
    fn idle_periodic_demand_starts_now() {
        let mut scheduler = RefreshScheduler::new();

        assert_eq!(scheduler.record_periodic(), RefreshDemand::StartNow);
    }

    #[test]
    fn mismatched_finish_identity_keeps_the_active_refresh() {
        let mut scheduler = RefreshScheduler::new();
        let active = scheduler.start(RefreshTrigger::Initial).unwrap();

        assert_eq!(scheduler.finish(RefreshId::new(active.id.get() + 1)), None);
        assert_eq!(scheduler.active_id(), Some(active.id));
    }

    #[test]
    fn refresh_ids_advance_monotonically() {
        let mut scheduler = RefreshScheduler::new();
        let first = scheduler.start(RefreshTrigger::Initial).unwrap();
        scheduler.finish(first.id).unwrap();
        let second = scheduler.start(RefreshTrigger::Manual).unwrap();

        assert_eq!(first.id.get(), 1);
        assert_eq!(second.id.get(), 2);
    }

    #[test]
    fn starting_while_active_is_rejected() {
        let mut scheduler = RefreshScheduler::new();
        scheduler.start(RefreshTrigger::Initial).unwrap();

        assert_eq!(scheduler.start(RefreshTrigger::Manual), None);
    }
}
