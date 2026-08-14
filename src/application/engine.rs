//! The engine task: single owner of the backend. Requests are processed
//! serially (mutations serialize structurally), refreshes are
//! coalesced, and events reach the UI in order — no stale-result races.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{Instant, Sleep};

use std::sync::atomic::{AtomicU64, Ordering};

use crate::domain::FirewallSnapshot;

use super::api::{
    EngineEvent, EngineRequest, ManualRefreshRequest, MutationPlan, MutationRequest,
    OperationResult, REQUEST_CAPACITY, RefreshCancellationReason, RefreshId, RefreshPrioritySource,
    RefreshScheduleObservation, RefreshTrigger, RollbackRegistration, RollbackRequest,
};
use super::ports::{
    FirewallBackend, FirewallError, OperationOutcome, OverviewRead, RollbackGuard, RollbackGuardId,
    SnapshotRead, StepReport,
};
use super::refresh_scheduler::{
    ManualDemandOverflow, RefreshCancellation, RefreshCompletion, RefreshDemand, RefreshScheduler,
    RefreshStart,
};

/// Process-wide operation counter. The id it mints is logged via tracing and
/// written to the audit line for the same operation, so `fwdeck.log` and
/// `audit.jsonl` can be joined on one field even across identical retries.
static OP_SEQ: AtomicU64 = AtomicU64::new(1);
static ROLLBACK_SEQ: AtomicU64 = AtomicU64::new(1);

/// The next correlation id for an operation.
pub fn next_op_id() -> u64 {
    OP_SEQ.fetch_add(1, Ordering::Relaxed)
}

enum OrdinaryRefreshOutcome {
    Completed(SnapshotRead),
    Preempted {
        work: EngineWork,
        schedule: RefreshScheduleObservation,
        reason: RefreshCancellationReason,
        elapsed: Duration,
    },
    Shutdown,
}

enum OrdinaryLifecycleOutcome {
    Completed { trailing_manual: bool },
    Preempted(EngineWork),
    Shutdown,
}

enum MandatoryRefreshOutcome {
    Completed {
        read: Box<SnapshotRead>,
        completion: RefreshCompletion,
        priority_rollback: Option<RollbackRequest>,
    },
    RollbackPreempted {
        request: RollbackRequest,
        cancellation: RefreshCancellation,
        elapsed: Duration,
    },
    Shutdown,
}

enum ReconciliationOutcome {
    Completed { trailing_manual: bool },
    Shutdown,
}

enum EngineWork {
    Normal(EngineRequest),
    Rollback(RollbackRequest),
}

pub(crate) struct EngineReceivers {
    requests: mpsc::Receiver<EngineRequest>,
    manual_refreshes: mpsc::Receiver<ManualRefreshRequest>,
    rollbacks: mpsc::Receiver<RollbackRequest>,
}

impl EngineReceivers {
    pub(crate) const fn new(
        requests: mpsc::Receiver<EngineRequest>,
        manual_refreshes: mpsc::Receiver<ManualRefreshRequest>,
        rollbacks: mpsc::Receiver<RollbackRequest>,
    ) -> Self {
        Self {
            requests,
            manual_refreshes,
            rollbacks,
        }
    }

    fn all_closed_and_empty(&self) -> bool {
        receiver_closed_and_empty(&self.requests)
            && receiver_closed_and_empty(&self.manual_refreshes)
            && receiver_closed_and_empty(&self.rollbacks)
    }
}

fn receiver_closed_and_empty<T>(receiver: &mpsc::Receiver<T>) -> bool {
    receiver.is_closed() && receiver.is_empty()
}

fn receiver_can_receive<T>(receiver: &mpsc::Receiver<T>) -> bool {
    !receiver_closed_and_empty(receiver)
}

async fn record_manual_demand(
    events: &mpsc::Sender<EngineEvent>,
    scheduler: &mut RefreshScheduler,
    request: ManualRefreshRequest,
) -> Result<Option<RefreshDemand>, ()> {
    if let Ok(demand) = scheduler.record_manual_batch(request.count()) {
        return Ok(Some(demand));
    }
    events
        .send(EngineEvent::ManualDemandRejected {
            count: request.count(),
        })
        .await
        .map_err(|_| ())?;
    Ok(None)
}

async fn absorb_manual_demand(
    events: &mpsc::Sender<EngineEvent>,
    scheduler: &mut RefreshScheduler,
    request: ManualRefreshRequest,
) -> Result<(), ()> {
    if let Err(ManualDemandOverflow) = scheduler.absorb_manual_batch(request.count()) {
        events
            .send(EngineEvent::ManualDemandRejected {
                count: request.count(),
            })
            .await
            .map_err(|_| ())?;
    }
    Ok(())
}

fn take_next_work(
    next_work: &mut Option<EngineWork>,
    inputs: &mut EngineReceivers,
    pending_requests: &mut VecDeque<EngineRequest>,
) -> Option<EngineWork> {
    if matches!(next_work, Some(EngineWork::Rollback(_))) {
        return next_work.take();
    }
    if let Ok(rollback) = inputs.rollbacks.try_recv() {
        return Some(EngineWork::Rollback(rollback));
    }
    next_work
        .take()
        .or_else(|| pending_requests.pop_front().map(EngineWork::Normal))
}

struct PeriodicDeadline<'a> {
    timer: Pin<&'a mut Sleep>,
    armed: bool,
}

impl<'a> PeriodicDeadline<'a> {
    fn new(timer: Pin<&'a mut Sleep>) -> Self {
        Self {
            timer,
            armed: false,
        }
    }

    fn reset(&mut self, refresh_interval: Duration) {
        self.timer.as_mut().reset(Instant::now() + refresh_interval);
        self.armed = true;
    }

    fn record_active(
        &mut self,
        scheduler: &mut RefreshScheduler,
        driver: &'static str,
    ) -> Result<(), ()> {
        if scheduler.record_periodic() != RefreshDemand::Coalesced {
            tracing::error!(driver, "active scheduler rejected periodic deadline");
            return Err(());
        }
        self.armed = false;
        Ok(())
    }

    fn observe_due(
        &mut self,
        scheduler: &mut RefreshScheduler,
        driver: &'static str,
    ) -> Result<(), ()> {
        if self.armed && Instant::now() >= self.timer.deadline() {
            self.record_active(scheduler, driver)?;
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn run<B: FirewallBackend, G: RollbackGuard>(
    backend: B,
    rollback_guard: G,
    mut inputs: EngineReceivers,
    events: mpsc::Sender<EngineEvent>,
    refresh_priority: RefreshPrioritySource,
    refresh_interval: Duration,
    read_only: bool,
    rollback_timeout: Duration,
) {
    let mut scheduler = RefreshScheduler::new();
    let timer = tokio::time::sleep(refresh_interval);
    tokio::pin!(timer);
    let mut periodic_deadline = PeriodicDeadline::new(timer.as_mut());
    let mut next_trigger = Some(RefreshTrigger::Initial);
    let mut next_work = None;
    let mut pending_requests = VecDeque::with_capacity(REQUEST_CAPACITY);

    loop {
        if inputs.all_closed_and_empty() || events.is_closed() {
            return;
        }

        if let Some(work) = take_next_work(&mut next_work, &mut inputs, &mut pending_requests) {
            if execute_work(
                &backend,
                &rollback_guard,
                &events,
                work,
                read_only,
                rollback_timeout,
            )
            .await
            .is_err()
            {
                return;
            }

            match reconcile_after_request(
                &backend,
                &rollback_guard,
                &events,
                &refresh_priority,
                &mut inputs,
                &mut pending_requests,
                &mut scheduler,
                &mut periodic_deadline,
                read_only,
                rollback_timeout,
            )
            .await
            {
                Ok(ReconciliationOutcome::Completed { trailing_manual }) => {
                    next_trigger = finish_sequence(
                        next_trigger,
                        trailing_manual,
                        &mut periodic_deadline,
                        refresh_interval,
                    );
                }
                Ok(ReconciliationOutcome::Shutdown) | Err(()) => return,
            }
            continue;
        }

        let trigger = if let Some(trigger) = next_trigger.take() {
            trigger
        } else {
            tokio::select! {
                biased;
                () = events.closed() => return,
                rollback = inputs.rollbacks.recv(), if receiver_can_receive(&inputs.rollbacks) => {
                    if let Some(rollback) = rollback {
                        next_work = Some(EngineWork::Rollback(rollback));
                        continue;
                    }
                    continue;
                }
                request = inputs.requests.recv(), if receiver_can_receive(&inputs.requests) => {
                    if let Some(request) = request {
                        next_work = Some(EngineWork::Normal(request));
                    }
                    continue;
                }
                manual = inputs.manual_refreshes.recv(), if receiver_can_receive(&inputs.manual_refreshes) => {
                    let Some(request) = manual else { continue };
                    let demand = match record_manual_demand(&events, &mut scheduler, request).await {
                        Ok(Some(demand)) => demand,
                        Ok(None) => continue,
                        Err(()) => return,
                    };
                    if demand != RefreshDemand::StartNow {
                        tracing::error!("idle scheduler rejected manual refresh");
                        return;
                    }
                    RefreshTrigger::Manual
                }
                () = periodic_deadline.timer.as_mut(), if periodic_deadline.armed => {
                    periodic_deadline.armed = false;
                    if scheduler.record_periodic() != RefreshDemand::StartNow {
                        tracing::error!("idle scheduler rejected periodic refresh");
                        return;
                    }
                    RefreshTrigger::Periodic
                }
            }
        };

        let Some(start) = scheduler.start(trigger) else {
            tracing::error!(?trigger, "ordinary refresh could not start");
            return;
        };
        match drive_ordinary_lifecycle(
            &backend,
            &mut inputs,
            &events,
            &refresh_priority,
            &mut scheduler,
            &mut periodic_deadline,
            start,
        )
        .await
        {
            OrdinaryLifecycleOutcome::Completed { trailing_manual } => {
                next_trigger = finish_sequence(
                    next_trigger,
                    trailing_manual,
                    &mut periodic_deadline,
                    refresh_interval,
                );
            }
            OrdinaryLifecycleOutcome::Preempted(work) => next_work = Some(work),
            OrdinaryLifecycleOutcome::Shutdown => return,
        }
    }
}

fn finish_sequence(
    current_trigger: Option<RefreshTrigger>,
    trailing_manual: bool,
    periodic_deadline: &mut PeriodicDeadline<'_>,
    refresh_interval: Duration,
) -> Option<RefreshTrigger> {
    if trailing_manual {
        Some(RefreshTrigger::Manual)
    } else if current_trigger.is_some() {
        current_trigger
    } else {
        periodic_deadline.reset(refresh_interval);
        None
    }
}

async fn absorb_observed_requests(
    inputs: &mut EngineReceivers,
    pending_requests: &mut VecDeque<EngineRequest>,
    scheduler: &mut RefreshScheduler,
    events: &mpsc::Sender<EngineEvent>,
) -> Result<(), ()> {
    let immediately_available_manual = inputs.manual_refreshes.len();
    for _ in 0..immediately_available_manual {
        match inputs.manual_refreshes.try_recv() {
            Ok(request) => absorb_manual_demand(events, scheduler, request).await?,
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                break;
            }
        }
    }

    let immediately_available = inputs.requests.len();
    for _ in 0..immediately_available {
        if pending_requests.len() == REQUEST_CAPACITY {
            break;
        }
        match inputs.requests.try_recv() {
            Ok(request) => pending_requests.push_back(request),
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                break;
            }
        }
    }

    Ok(())
}

async fn drive_ordinary_lifecycle<B: FirewallBackend>(
    backend: &B,
    inputs: &mut EngineReceivers,
    events: &mpsc::Sender<EngineEvent>,
    refresh_priority: &RefreshPrioritySource,
    scheduler: &mut RefreshScheduler,
    periodic_deadline: &mut PeriodicDeadline<'_>,
    start: RefreshStart,
) -> OrdinaryLifecycleOutcome {
    if send_refresh_started(events, start).await.is_err() {
        return OrdinaryLifecycleOutcome::Shutdown;
    }
    match drive_ordinary_refresh(
        backend,
        inputs,
        events,
        refresh_priority,
        scheduler,
        periodic_deadline,
        start.id,
    )
    .await
    {
        OrdinaryRefreshOutcome::Completed(read) => {
            match finish_ordinary_refresh(events, scheduler, start, read).await {
                Ok(trailing_manual) => OrdinaryLifecycleOutcome::Completed { trailing_manual },
                Err(()) => OrdinaryLifecycleOutcome::Shutdown,
            }
        }
        OrdinaryRefreshOutcome::Preempted {
            work,
            schedule,
            reason,
            elapsed,
        } => {
            if send_refresh_cancelled(events, schedule, reason, elapsed)
                .await
                .is_err()
            {
                OrdinaryLifecycleOutcome::Shutdown
            } else {
                OrdinaryLifecycleOutcome::Preempted(work)
            }
        }
        OrdinaryRefreshOutcome::Shutdown => OrdinaryLifecycleOutcome::Shutdown,
    }
}

async fn drive_ordinary_refresh<B: FirewallBackend>(
    backend: &B,
    inputs: &mut EngineReceivers,
    events: &mpsc::Sender<EngineEvent>,
    refresh_priority: &RefreshPrioritySource,
    scheduler: &mut RefreshScheduler,
    periodic_deadline: &mut PeriodicDeadline<'_>,
    id: RefreshId,
) -> OrdinaryRefreshOutcome {
    let started = Instant::now();
    let snapshot = read_staged_snapshot(backend, refresh_priority, events, id);
    tokio::pin!(snapshot);

    loop {
        if inputs.all_closed_and_empty() || events.is_closed() {
            return OrdinaryRefreshOutcome::Shutdown;
        }
        tokio::select! {
            biased;
            () = events.closed() => return OrdinaryRefreshOutcome::Shutdown,
            rollback = inputs.rollbacks.recv(), if receiver_can_receive(&inputs.rollbacks) => {
                let Some(rollback) = rollback else { continue };
                if periodic_deadline.observe_due(scheduler, "ordinary").is_err() {
                    return OrdinaryRefreshOutcome::Shutdown;
                }
                let Some(schedule) = scheduler.cancel_for_mutation() else {
                    tracing::error!("ordinary refresh was not preemptible");
                    return OrdinaryRefreshOutcome::Shutdown;
                };
                return OrdinaryRefreshOutcome::Preempted {
                    work: EngineWork::Rollback(rollback),
                    schedule,
                    reason: RefreshCancellationReason::RollbackPreempted,
                    elapsed: started.elapsed(),
                };
            }
            request = inputs.requests.recv(), if receiver_can_receive(&inputs.requests) => {
                let Some(request) = request else { continue };
                if periodic_deadline.observe_due(scheduler, "ordinary").is_err() {
                    return OrdinaryRefreshOutcome::Shutdown;
                }
                let Some(schedule) = scheduler.cancel_for_mutation() else {
                    tracing::error!("ordinary refresh was not preemptible");
                    return OrdinaryRefreshOutcome::Shutdown;
                };
                return OrdinaryRefreshOutcome::Preempted {
                    work: EngineWork::Normal(request),
                    schedule,
                    reason: RefreshCancellationReason::MutationPreempted,
                    elapsed: started.elapsed(),
                };
            }
            manual = inputs.manual_refreshes.recv(), if receiver_can_receive(&inputs.manual_refreshes) => {
                if let Some(request) = manual
                    && record_manual_demand(events, scheduler, request).await.is_err()
                {
                    return OrdinaryRefreshOutcome::Shutdown;
                }
            }
            () = periodic_deadline.timer.as_mut(), if periodic_deadline.armed => {
                if periodic_deadline.record_active(scheduler, "ordinary").is_err() {
                    return OrdinaryRefreshOutcome::Shutdown;
                }
            }
            read = &mut snapshot => {
                if periodic_deadline.observe_due(scheduler, "ordinary").is_err() {
                    return OrdinaryRefreshOutcome::Shutdown;
                }
                return match read {
                    Some(read) => OrdinaryRefreshOutcome::Completed(read),
                    None => OrdinaryRefreshOutcome::Shutdown,
                };
            }
        }
    }
}

async fn read_staged_snapshot<B: FirewallBackend>(
    backend: &B,
    refresh_priority: &RefreshPrioritySource,
    events: &mpsc::Sender<EngineEvent>,
    id: RefreshId,
) -> Option<SnapshotRead> {
    let OverviewRead {
        result,
        observation: overview_observation,
    } = backend.snapshot_overview(refresh_priority).await;
    let overview = match result {
        Ok(overview) => overview,
        Err(error) => {
            return Some(SnapshotRead {
                result: Err(error),
                observation: overview_observation,
            });
        }
    };

    if let Some(value) = overview.as_ref()
        && events
            .send(EngineEvent::RefreshOverviewReady {
                id,
                overview: Arc::clone(value),
            })
            .await
            .is_err()
    {
        return None;
    }

    let hydration = backend.snapshot_hydrated(overview, refresh_priority).await;
    Some(SnapshotRead {
        result: hydration.result,
        observation: overview_observation.merge_sequential(hydration.observation),
    })
}

#[allow(clippy::too_many_arguments)]
async fn drive_mandatory_refresh<B: FirewallBackend>(
    backend: &B,
    inputs: &mut EngineReceivers,
    events: &mpsc::Sender<EngineEvent>,
    refresh_priority: &RefreshPrioritySource,
    pending_requests: &mut VecDeque<EngineRequest>,
    scheduler: &mut RefreshScheduler,
    start: RefreshStart,
    periodic_deadline: &mut PeriodicDeadline<'_>,
) -> MandatoryRefreshOutcome {
    let started = Instant::now();
    let snapshot = read_staged_snapshot(backend, refresh_priority, events, start.id);
    tokio::pin!(snapshot);

    loop {
        if inputs.all_closed_and_empty() || events.is_closed() {
            return MandatoryRefreshOutcome::Shutdown;
        }

        tokio::select! {
            biased;
            () = events.closed() => return MandatoryRefreshOutcome::Shutdown,
            read = &mut snapshot => {
                if periodic_deadline.observe_due(scheduler, "mandatory").is_err() {
                    return MandatoryRefreshOutcome::Shutdown;
                }
                let Some(read) = read else {
                    return MandatoryRefreshOutcome::Shutdown;
                };
                if inputs.all_closed_and_empty() || events.is_closed() {
                    return MandatoryRefreshOutcome::Shutdown;
                }
                let Ok(priority_rollback) = drain_post_mutation_boundary(
                    inputs,
                    pending_requests,
                    scheduler,
                    events,
                ).await else {
                    return MandatoryRefreshOutcome::Shutdown;
                };
                if inputs.all_closed_and_empty() || events.is_closed() {
                    return MandatoryRefreshOutcome::Shutdown;
                }
                let Some(completion) = scheduler.finish(start.id) else {
                    tracing::error!("post-mutation refresh lifecycle was lost");
                    return MandatoryRefreshOutcome::Shutdown;
                };
                return MandatoryRefreshOutcome::Completed {
                    read: Box::new(read),
                    completion,
                    priority_rollback,
                };
            }
            rollback = inputs.rollbacks.recv(), if receiver_can_receive(&inputs.rollbacks) => {
                let Some(request) = rollback else { continue };
                if periodic_deadline
                    .observe_due(scheduler, "mandatory")
                    .is_err()
                {
                    return MandatoryRefreshOutcome::Shutdown;
                }
                if record_available_manual_refreshes(
                    &mut inputs.manual_refreshes,
                    scheduler,
                    events,
                )
                .await
                .is_err()
                {
                    return MandatoryRefreshOutcome::Shutdown;
                }
                let Some(cancellation) = scheduler.cancel_for_rollback() else {
                    tracing::error!("mandatory refresh rollback cancellation was lost");
                    return MandatoryRefreshOutcome::Shutdown;
                };
                return MandatoryRefreshOutcome::RollbackPreempted {
                    request,
                    cancellation,
                    elapsed: started.elapsed(),
                };
            }
            () = periodic_deadline.timer.as_mut(), if periodic_deadline.armed => {
                if periodic_deadline.record_active(scheduler, "mandatory").is_err() {
                    return MandatoryRefreshOutcome::Shutdown;
                }
            }
            manual = inputs.manual_refreshes.recv(), if receiver_can_receive(&inputs.manual_refreshes) => {
                if let Some(request) = manual
                    && record_manual_demand(events, scheduler, request).await.is_err()
                {
                    return MandatoryRefreshOutcome::Shutdown;
                }
            }
            request = inputs.requests.recv(), if pending_requests.len() < REQUEST_CAPACITY
                && receiver_can_receive(&inputs.requests) => {
                if let Some(request) = request {
                    pending_requests.push_back(request);
                }
            }
        }
    }
}

async fn drain_post_mutation_boundary(
    inputs: &mut EngineReceivers,
    pending_requests: &mut VecDeque<EngineRequest>,
    scheduler: &mut RefreshScheduler,
    events: &mpsc::Sender<EngineEvent>,
) -> Result<Option<RollbackRequest>, ()> {
    record_available_manual_refreshes(&mut inputs.manual_refreshes, scheduler, events).await?;

    let priority_rollback = inputs.rollbacks.try_recv().ok();
    let immediately_available = inputs.requests.len();
    for _ in 0..immediately_available {
        if pending_requests.len() == REQUEST_CAPACITY {
            break;
        }
        match inputs.requests.try_recv() {
            Ok(request) => pending_requests.push_back(request),
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                break;
            }
        }
    }
    Ok(priority_rollback)
}

async fn record_available_manual_refreshes(
    manual_refreshes: &mut mpsc::Receiver<ManualRefreshRequest>,
    scheduler: &mut RefreshScheduler,
    events: &mpsc::Sender<EngineEvent>,
) -> Result<(), ()> {
    let immediately_available = manual_refreshes.len();
    for _ in 0..immediately_available {
        match manual_refreshes.try_recv() {
            Ok(request) => {
                let _ = record_manual_demand(events, scheduler, request).await?;
            }
            Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                break;
            }
        }
    }
    Ok(())
}

async fn begin_post_mutation_refresh(
    events: &mpsc::Sender<EngineEvent>,
    scheduler: &mut RefreshScheduler,
) -> Result<RefreshStart, ()> {
    let Some(start) = scheduler.start(RefreshTrigger::PostMutation) else {
        tracing::error!("post-mutation refresh could not start");
        return Err(());
    };
    send_refresh_started(events, start).await?;
    Ok(start)
}

#[allow(clippy::too_many_arguments)]
async fn reconcile_after_request<B: FirewallBackend, G: RollbackGuard>(
    backend: &B,
    rollback_guard: &G,
    events: &mpsc::Sender<EngineEvent>,
    refresh_priority: &RefreshPrioritySource,
    inputs: &mut EngineReceivers,
    pending_requests: &mut VecDeque<EngineRequest>,
    scheduler: &mut RefreshScheduler,
    periodic_deadline: &mut PeriodicDeadline<'_>,
    read_only: bool,
    rollback_timeout: Duration,
) -> Result<ReconciliationOutcome, ()> {
    let mut start = begin_post_mutation_refresh(events, scheduler).await?;
    let mut trailing_manual = false;
    absorb_observed_requests(inputs, pending_requests, scheduler, events).await?;

    loop {
        match drive_mandatory_refresh(
            backend,
            inputs,
            events,
            refresh_priority,
            pending_requests,
            scheduler,
            start,
            periodic_deadline,
        )
        .await
        {
            MandatoryRefreshOutcome::Completed {
                read,
                completion,
                priority_rollback,
            } => {
                trailing_manual |= completion.trailing_manual;
                send_refresh_finished(events, completion, *read).await?;
                let Some(rollback) = priority_rollback else {
                    return Ok(ReconciliationOutcome::Completed { trailing_manual });
                };
                execute_work(
                    backend,
                    rollback_guard,
                    events,
                    EngineWork::Rollback(rollback),
                    read_only,
                    rollback_timeout,
                )
                .await?;
                start = begin_post_mutation_refresh(events, scheduler).await?;
                absorb_observed_requests(inputs, pending_requests, scheduler, events).await?;
            }
            MandatoryRefreshOutcome::RollbackPreempted {
                request,
                cancellation,
                elapsed,
            } => {
                trailing_manual |= cancellation.trailing_manual;
                send_refresh_cancelled(
                    events,
                    cancellation.schedule,
                    RefreshCancellationReason::RollbackPreempted,
                    elapsed,
                )
                .await?;
                execute_work(
                    backend,
                    rollback_guard,
                    events,
                    EngineWork::Rollback(request),
                    read_only,
                    rollback_timeout,
                )
                .await?;
                start = begin_post_mutation_refresh(events, scheduler).await?;
                absorb_observed_requests(inputs, pending_requests, scheduler, events).await?;
            }
            MandatoryRefreshOutcome::Shutdown => return Ok(ReconciliationOutcome::Shutdown),
        }
    }
}

async fn finish_ordinary_refresh(
    events: &mpsc::Sender<EngineEvent>,
    scheduler: &mut RefreshScheduler,
    start: RefreshStart,
    read: SnapshotRead,
) -> Result<bool, ()> {
    let Some(completion) = scheduler.finish(start.id) else {
        tracing::error!(refresh_id = start.id.get(), "refresh completion was lost");
        return Err(());
    };
    let trailing_manual = completion.trailing_manual;
    send_refresh_finished(events, completion, read).await?;
    Ok(trailing_manual)
}

async fn send_refresh_started(
    events: &mpsc::Sender<EngineEvent>,
    start: RefreshStart,
) -> Result<(), ()> {
    events
        .send(EngineEvent::RefreshStarted {
            id: start.id,
            trigger: start.trigger,
        })
        .await
        .map_err(|_| ())
}

async fn send_refresh_cancelled(
    events: &mpsc::Sender<EngineEvent>,
    schedule: RefreshScheduleObservation,
    reason: RefreshCancellationReason,
    elapsed: Duration,
) -> Result<(), ()> {
    tracing::debug!(
        refresh_id = schedule.id.get(),
        trigger = ?schedule.trigger,
        merged_manual_requests = schedule.merged_manual_requests,
        coalesced_periodic_ticks = schedule.coalesced_periodic_ticks,
        elapsed_ms = elapsed.as_millis(),
        reason = ?reason,
        "refresh cancelled"
    );
    events
        .send(EngineEvent::RefreshCancelled {
            schedule,
            reason,
            elapsed,
        })
        .await
        .map_err(|_| ())
}

async fn execute_work<B: FirewallBackend, G: RollbackGuard>(
    backend: &B,
    rollback_guard: &G,
    events: &mpsc::Sender<EngineEvent>,
    work: EngineWork,
    read_only: bool,
    rollback_timeout: Duration,
) -> Result<(), ()> {
    match work {
        EngineWork::Normal(EngineRequest::Apply(request)) => {
            apply(
                backend,
                rollback_guard,
                events,
                request,
                read_only,
                rollback_timeout,
            )
            .await
        }
        EngineWork::Rollback(RollbackRequest {
            id,
            operation,
            watchdog_unit,
        }) => {
            apply_rollback(
                backend,
                rollback_guard,
                events,
                id,
                operation,
                watchdog_unit,
                read_only,
            )
            .await
        }
        EngineWork::Normal(EngineRequest::ApplyPlan(plan)) => {
            apply_plan(
                backend,
                rollback_guard,
                events,
                plan,
                read_only,
                rollback_timeout,
            )
            .await
        }
    }
}

/// Executes a staged plan sequentially, halting on the first outcome that is
/// not fully applied (fail-fast: continuing after a partial failure could
/// compound damage). Every per-operation outcome still flows to the UI as
/// `OperationFinished`; unexecuted operations are returned in `PlanFinished`
/// so nothing is silently lost. Returns `Err(())` when the UI is gone.
async fn apply_plan<B: FirewallBackend, G: RollbackGuard>(
    backend: &B,
    rollback_guard: &G,
    events: &mpsc::Sender<EngineEvent>,
    plan: MutationPlan,
    read_only: bool,
    rollback_timeout: Duration,
) -> Result<(), ()> {
    let MutationPlan {
        operations,
        expected,
    } = plan;
    let total = operations.len();
    if !read_only {
        let observed = match mutation_precondition(backend, &expected).await {
            Ok(observed) => observed,
            Err(error) => return reject_plan_preflight(events, operations, error).await,
        };
        if let Some(error) = operations
            .iter()
            .find_map(|operation| operation.validate(&observed).err())
        {
            return reject_plan_preflight(
                events,
                operations,
                FirewallError::Validation(error.to_string()),
            )
            .await;
        }
    }
    let mut iter = operations.into_iter();
    let mut applied = 0usize;
    let mut halted = false;
    for operation in iter.by_ref() {
        let (op_id, outcome, rollback, guard_warning) = execute_operation(
            backend,
            rollback_guard,
            operation,
            read_only,
            rollback_timeout,
            true,
        )
        .await;
        let fully_applied = matches!(outcome, OperationOutcome::Applied { .. });
        if events
            .send(EngineEvent::OperationFinished(Box::new(OperationResult {
                op_id,
                outcome,
                rollback,
                guard_warning,
                completed_rollback: None,
            })))
            .await
            .is_err()
        {
            return Err(());
        }
        if fully_applied {
            applied += 1;
        } else {
            halted = true;
            break;
        }
    }
    let remaining: Vec<_> = iter.collect();
    tracing::info!(applied, total, halted, "plan finished");
    events
        .send(EngineEvent::PlanFinished { applied, remaining })
        .await
        .map_err(|_| ())
}

/// Returns `Err(())` when the event channel is closed (UI is gone).
async fn apply<B: FirewallBackend, G: RollbackGuard>(
    backend: &B,
    rollback_guard: &G,
    events: &mpsc::Sender<EngineEvent>,
    request: MutationRequest,
    read_only: bool,
    rollback_timeout: Duration,
) -> Result<(), ()> {
    let MutationRequest {
        operation,
        expected,
    } = request;
    let (op_id, outcome, rollback, guard_warning) = if read_only {
        execute_operation(
            backend,
            rollback_guard,
            operation,
            true,
            rollback_timeout,
            false,
        )
        .await
    } else {
        match mutation_precondition(backend, &expected).await {
            Ok(observed) => match operation.validate(&observed) {
                Ok(()) => {
                    execute_operation(
                        backend,
                        rollback_guard,
                        operation,
                        false,
                        rollback_timeout,
                        false,
                    )
                    .await
                }
                Err(error) => {
                    rejected_operation(operation, FirewallError::Validation(error.to_string()))
                }
            },
            Err(error) => rejected_operation(operation, error),
        }
    };
    match &outcome {
        OperationOutcome::Applied { .. } => {
            tracing::info!(operation = %outcome.operation().describe(), "operation applied");
        }
        OperationOutcome::PartiallyApplied { .. }
        | OperationOutcome::Failed { .. }
        | OperationOutcome::Indeterminate { .. } => {
            tracing::warn!(operation = %outcome.operation().describe(), outcome = ?outcome, "operation not fully applied");
        }
    }
    events
        .send(EngineEvent::OperationFinished(Box::new(OperationResult {
            op_id,
            outcome,
            rollback,
            guard_warning,
            completed_rollback: None,
        })))
        .await
        .map_err(|_| ())
}

/// Re-reads every backend section at the mutation boundary and compares it to
/// the state reviewed by the operator. Returning the fresh snapshot also lets
/// the caller repeat domain validation without a third read.
async fn mutation_precondition<B: FirewallBackend>(
    backend: &B,
    expected: &FirewallSnapshot,
) -> Result<FirewallSnapshot, FirewallError> {
    let observed = backend.snapshot_fresh().await?;
    if observed == *expected {
        Ok(observed)
    } else {
        Err(FirewallError::StaleSnapshot)
    }
}

fn rejected_operation(
    operation: crate::domain::FirewallOperation,
    error: FirewallError,
) -> (
    u64,
    OperationOutcome,
    Option<RollbackRegistration>,
    Option<String>,
) {
    (
        next_op_id(),
        OperationOutcome::Failed {
            operation,
            steps: vec![StepReport {
                target: "precondition",
                invocation: Vec::new(),
                result: Err(error),
            }],
        },
        None,
        None,
    )
}

async fn reject_plan_preflight(
    events: &mpsc::Sender<EngineEvent>,
    operations: Vec<crate::domain::FirewallOperation>,
    error: FirewallError,
) -> Result<(), ()> {
    let Some(first) = operations.first().cloned() else {
        return events
            .send(EngineEvent::PlanFinished {
                applied: 0,
                remaining: Vec::new(),
            })
            .await
            .map_err(|_| ());
    };
    let (op_id, outcome, rollback, guard_warning) = rejected_operation(first, error);
    events
        .send(EngineEvent::OperationFinished(Box::new(OperationResult {
            op_id,
            outcome,
            rollback,
            guard_warning,
            completed_rollback: None,
        })))
        .await
        .map_err(|_| ())?;
    events
        .send(EngineEvent::PlanFinished {
            applied: 0,
            remaining: operations,
        })
        .await
        .map_err(|_| ())
}

async fn apply_rollback<B: FirewallBackend, G: RollbackGuard>(
    backend: &B,
    rollback_guard: &G,
    events: &mpsc::Sender<EngineEvent>,
    id: RollbackGuardId,
    operation: crate::domain::FirewallOperation,
    watchdog_unit: Option<String>,
    read_only: bool,
) -> Result<(), ()> {
    let op_id = next_op_id();
    tracing::warn!(op_id, rollback_id = id.get(), operation = %operation.describe(), "applying rollback inverse");
    let outcome = if read_only {
        OperationOutcome::Failed {
            operation,
            steps: vec![StepReport {
                target: "policy",
                invocation: Vec::new(),
                result: Err(FirewallError::ReadOnlyMode),
            }],
        }
    } else {
        backend.apply(&operation).await
    };

    let mut guard_warning = None;
    if matches!(outcome, OperationOutcome::Applied { .. }) {
        if let Some(unit) = watchdog_unit
            && let Err(error) = rollback_guard.disarm(&unit).await
        {
            guard_warning = Some(format!(
                "rollback applied but crash watchdog `{unit}` could not be disarmed: {error}"
            ));
        }
    } else if watchdog_unit.is_some() {
        guard_warning = Some(
            "rollback did not fully apply — crash watchdog remains armed as a safety fallback"
                .to_owned(),
        );
    }
    events
        .send(EngineEvent::OperationFinished(Box::new(OperationResult {
            op_id,
            outcome,
            rollback: None,
            guard_warning,
            completed_rollback: Some(id),
        })))
        .await
        .map_err(|_| ())
}

async fn execute_operation<B: FirewallBackend, G: RollbackGuard>(
    backend: &B,
    rollback_guard: &G,
    operation: crate::domain::FirewallOperation,
    read_only: bool,
    rollback_timeout: Duration,
    plan_item: bool,
) -> (
    u64,
    OperationOutcome,
    Option<RollbackRegistration>,
    Option<String>,
) {
    let op_id = next_op_id();
    if read_only {
        return (
            op_id,
            OperationOutcome::Failed {
                operation,
                steps: vec![StepReport {
                    target: "policy",
                    invocation: Vec::new(),
                    result: Err(FirewallError::ReadOnlyMode),
                }],
            },
            None,
            None,
        );
    }

    let (mut rollback, mut guard_warning) =
        prepare_rollback(rollback_guard, &operation, rollback_timeout).await;
    if plan_item {
        tracing::info!(op_id, operation = %operation.describe(), "applying plan operation");
    } else {
        tracing::info!(op_id, operation = %operation.describe(), "applying operation");
    }
    let outcome = backend.apply(&operation).await;

    if matches!(outcome, OperationOutcome::Failed { .. }) {
        if let Some(unit) = rollback
            .as_ref()
            .and_then(|registration| registration.watchdog_unit.as_deref())
            && let Err(error) = rollback_guard.disarm(unit).await
        {
            append_warning(
                &mut guard_warning,
                format!("failed to disarm rollback guard `{unit}` after a clean failure: {error}"),
            );
        }
        rollback = None;
    }

    (op_id, outcome, rollback, guard_warning)
}

async fn prepare_rollback<G: RollbackGuard>(
    rollback_guard: &G,
    operation: &crate::domain::FirewallOperation,
    rollback_timeout: Duration,
) -> (Option<RollbackRegistration>, Option<String>) {
    if rollback_timeout.is_zero() || operation.connectivity_warning().is_none() {
        return (None, None);
    }
    let Some(inverse) = operation.inverse() else {
        return (None, None);
    };
    let id = RollbackGuardId::new(ROLLBACK_SEQ.fetch_add(1, Ordering::Relaxed));
    match rollback_guard.arm(id, operation, rollback_timeout).await {
        Ok(Some(watchdog_unit)) => (
            Some(RollbackRegistration {
                id,
                inverse,
                watchdog_unit: Some(watchdog_unit),
            }),
            None,
        ),
        Ok(None) => (
            Some(RollbackRegistration {
                id,
                inverse,
                watchdog_unit: None,
            }),
            Some(
                "crash watchdog unavailable for this operation — in-process rollback only"
                    .to_owned(),
            ),
        ),
        Err(error) => (
            Some(RollbackRegistration {
                id,
                inverse,
                watchdog_unit: None,
            }),
            Some(format!(
                "could not arm the crash watchdog — in-process rollback only: {error}"
            )),
        ),
    }
}

fn append_warning(current: &mut Option<String>, warning: String) {
    if let Some(existing) = current {
        existing.push_str("; ");
        existing.push_str(&warning);
    } else {
        *current = Some(warning);
    }
}

/// Returns `Err(())` when the event channel is closed (UI is gone).
async fn send_refresh_finished(
    events: &mpsc::Sender<EngineEvent>,
    completion: RefreshCompletion,
    read: SnapshotRead,
) -> Result<(), ()> {
    let result = read.result.map(Arc::new);
    let observation = read.observation;
    match &result {
        Ok(snapshot) => tracing::debug!(
            refresh_id = completion.schedule.id.get(),
            trigger = ?completion.schedule.trigger,
            merged_manual_requests = completion.schedule.merged_manual_requests,
            coalesced_periodic_ticks = completion.schedule.coalesced_periodic_ticks,
            backend_elapsed_ms = observation.elapsed.as_millis(),
            process_count = observation.process_count,
            success = true,
            zones = snapshot.runtime.len(),
            "refresh finished"
        ),
        Err(err) => tracing::warn!(
            refresh_id = completion.schedule.id.get(),
            trigger = ?completion.schedule.trigger,
            merged_manual_requests = completion.schedule.merged_manual_requests,
            coalesced_periodic_ticks = completion.schedule.coalesced_periodic_ticks,
            backend_elapsed_ms = observation.elapsed.as_millis(),
            process_count = observation.process_count,
            success = false,
            error = %err,
            "refresh failed"
        ),
    }
    events
        .send(EngineEvent::RefreshFinished {
            schedule: completion.schedule,
            result,
            observation,
        })
        .await
        .map_err(|_| ())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::application::ports::{
        FirewallBackend, FirewallError, OverviewRead, RollbackGuardError, RollbackGuardId,
        SnapshotRead,
    };
    use crate::application::{
        RefreshCancellationReason, RefreshOverview, RefreshPrioritySource, RefreshTrigger,
    };
    use crate::domain::{
        FirewallOperation, FirewallSnapshot, FirewallStatus, RefreshObservation, Scoped, mock,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::sync::Semaphore;

    async fn run<B: FirewallBackend, G: RollbackGuard>(
        backend: B,
        rollback_guard: G,
        inputs: EngineReceivers,
        events: mpsc::Sender<EngineEvent>,
        refresh_interval: Duration,
        read_only: bool,
        rollback_timeout: Duration,
    ) {
        let (_publisher, refresh_priority) = crate::application::refresh_priority_channel();
        super::run(
            backend,
            rollback_guard,
            inputs,
            events,
            refresh_priority,
            refresh_interval,
            read_only,
            rollback_timeout,
        )
        .await;
    }

    #[derive(Default)]
    struct TestRollbackGuard;

    impl RollbackGuard for TestRollbackGuard {
        async fn arm(
            &self,
            _id: RollbackGuardId,
            _operation: &FirewallOperation,
            _delay: Duration,
        ) -> Result<Option<String>, RollbackGuardError> {
            Ok(None)
        }

        async fn disarm(&self, _unit: &str) -> Result<(), RollbackGuardError> {
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct GuardLog {
        armed: Vec<(RollbackGuardId, FirewallOperation)>,
        disarmed: Vec<String>,
    }

    #[derive(Clone, Default)]
    struct RecordingRollbackGuard {
        log: Arc<Mutex<GuardLog>>,
    }

    impl RollbackGuard for RecordingRollbackGuard {
        async fn arm(
            &self,
            id: RollbackGuardId,
            operation: &FirewallOperation,
            _delay: Duration,
        ) -> Result<Option<String>, RollbackGuardError> {
            self.log.lock().unwrap().armed.push((id, operation.clone()));
            Ok(Some(format!("fwdeck-rollback-test-{}", id.get())))
        }

        async fn disarm(&self, unit: &str) -> Result<(), RollbackGuardError> {
            self.log.lock().unwrap().disarmed.push(unit.to_owned());
            Ok(())
        }
    }

    struct FailingArmGuard;

    impl RollbackGuard for FailingArmGuard {
        async fn arm(
            &self,
            _id: RollbackGuardId,
            _operation: &FirewallOperation,
            _delay: Duration,
        ) -> Result<Option<String>, RollbackGuardError> {
            Err(RollbackGuardError::Process("arm timeout".to_owned()))
        }

        async fn disarm(&self, _unit: &str) -> Result<(), RollbackGuardError> {
            Ok(())
        }
    }

    struct FailingDisarmGuard;

    impl RollbackGuard for FailingDisarmGuard {
        async fn arm(
            &self,
            id: RollbackGuardId,
            _operation: &FirewallOperation,
            _delay: Duration,
        ) -> Result<Option<String>, RollbackGuardError> {
            Ok(Some(format!("fwdeck-rollback-test-{}", id.get())))
        }

        async fn disarm(&self, _unit: &str) -> Result<(), RollbackGuardError> {
            Err(RollbackGuardError::Process("disarm timeout".to_owned()))
        }
    }

    struct FakeBackend {
        calls: AtomicUsize,
        fail: bool,
    }

    impl FirewallBackend for FakeBackend {
        async fn probe(&self) -> Result<FirewallStatus, FirewallError> {
            Err(FirewallError::DaemonNotRunning)
        }

        async fn snapshot(&self) -> Result<FirewallSnapshot, FirewallError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(FirewallError::DaemonNotRunning)
            } else {
                mock::sample().map_err(|e| FirewallError::Parse(e.to_string()))
            }
        }

        async fn apply(&self, operation: &FirewallOperation) -> OperationOutcome {
            OperationOutcome::Applied {
                operation: operation.clone(),
                steps: vec![StepReport {
                    target: "runtime",
                    invocation: vec!["--fake".to_owned()],
                    result: Ok(()),
                }],
            }
        }
    }

    struct ActiveSnapshotGuard {
        active: Arc<AtomicUsize>,
    }

    impl Drop for ActiveSnapshotGuard {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[derive(Clone)]
    struct ControlledSnapshotBackend {
        active_overviews: Arc<AtomicUsize>,
        active_snapshots: Arc<AtomicUsize>,
        max_active_snapshots: Arc<AtomicUsize>,
        snapshot_calls: Arc<AtomicUsize>,
        snapshot_started: Arc<Semaphore>,
        snapshot_release: Arc<Semaphore>,
        overview_enabled: Arc<AtomicBool>,
        overview_blocked: Arc<AtomicBool>,
        overview_started: Arc<Semaphore>,
        overview_release: Arc<Semaphore>,
        overview_calls: Arc<AtomicUsize>,
        overview_completions: Arc<AtomicUsize>,
        hydration_starts: Arc<AtomicUsize>,
        hydration_completions: Arc<AtomicUsize>,
        apply_observed_zero_active: Arc<AtomicBool>,
        active_snapshots_at_apply: Arc<Mutex<Vec<usize>>>,
        applied_operations: Arc<Mutex<Vec<FirewallOperation>>>,
    }

    impl ControlledSnapshotBackend {
        fn new() -> Self {
            Self {
                active_overviews: Arc::new(AtomicUsize::new(0)),
                active_snapshots: Arc::new(AtomicUsize::new(0)),
                max_active_snapshots: Arc::new(AtomicUsize::new(0)),
                snapshot_calls: Arc::new(AtomicUsize::new(0)),
                snapshot_started: Arc::new(Semaphore::new(0)),
                snapshot_release: Arc::new(Semaphore::new(0)),
                overview_enabled: Arc::new(AtomicBool::new(false)),
                overview_blocked: Arc::new(AtomicBool::new(false)),
                overview_started: Arc::new(Semaphore::new(0)),
                overview_release: Arc::new(Semaphore::new(0)),
                overview_calls: Arc::new(AtomicUsize::new(0)),
                overview_completions: Arc::new(AtomicUsize::new(0)),
                hydration_starts: Arc::new(AtomicUsize::new(0)),
                hydration_completions: Arc::new(AtomicUsize::new(0)),
                apply_observed_zero_active: Arc::new(AtomicBool::new(false)),
                active_snapshots_at_apply: Arc::new(Mutex::new(Vec::new())),
                applied_operations: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn enable_blocked_overview(&self) {
            self.overview_enabled.store(true, Ordering::SeqCst);
            self.overview_blocked.store(true, Ordering::SeqCst);
        }

        async fn wait_for_overview_start(&self) {
            self.overview_started.acquire().await.unwrap().forget();
        }

        fn release_overview(&self) {
            self.overview_release.add_permits(1);
        }

        async fn wait_for_snapshot_start(&self) {
            self.snapshot_started.acquire().await.unwrap().forget();
        }

        fn release_snapshot(&self) {
            self.snapshot_release.add_permits(1);
        }

        fn hydration_completions(&self) -> usize {
            self.hydration_completions.load(Ordering::SeqCst)
        }

        fn hydration_starts(&self) -> usize {
            self.hydration_starts.load(Ordering::SeqCst)
        }

        fn overview_completions(&self) -> usize {
            self.overview_completions.load(Ordering::SeqCst)
        }
    }

    impl FirewallBackend for ControlledSnapshotBackend {
        async fn probe(&self) -> Result<FirewallStatus, FirewallError> {
            Err(FirewallError::DaemonNotRunning)
        }

        async fn snapshot(&self) -> Result<FirewallSnapshot, FirewallError> {
            mock::sample().map_err(|error| FirewallError::Parse(error.to_string()))
        }

        fn snapshot_observed(&self) -> impl std::future::Future<Output = SnapshotRead> + Send {
            let active = Arc::clone(&self.active_snapshots);
            let max_active = Arc::clone(&self.max_active_snapshots);
            let calls = Arc::clone(&self.snapshot_calls);
            let started = Arc::clone(&self.snapshot_started);
            let release = Arc::clone(&self.snapshot_release);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                let active_now = active.fetch_add(1, Ordering::SeqCst) + 1;
                max_active.fetch_max(active_now, Ordering::SeqCst);
                let _guard = ActiveSnapshotGuard { active };
                started.add_permits(1);
                release.acquire().await.unwrap().forget();
                SnapshotRead {
                    result: mock::sample().map_err(|error| FirewallError::Parse(error.to_string())),
                    observation: crate::domain::RefreshObservation::total_only(Duration::ZERO),
                }
            }
        }

        fn snapshot_overview(
            &self,
            _priority: &RefreshPrioritySource,
        ) -> impl std::future::Future<Output = OverviewRead> + Send {
            let enabled = Arc::clone(&self.overview_enabled);
            let blocked = Arc::clone(&self.overview_blocked);
            let active = Arc::clone(&self.active_overviews);
            let started = Arc::clone(&self.overview_started);
            let release = Arc::clone(&self.overview_release);
            let calls = Arc::clone(&self.overview_calls);
            let completions = Arc::clone(&self.overview_completions);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                if !enabled.load(Ordering::SeqCst) {
                    return OverviewRead {
                        result: Ok(None),
                        observation: RefreshObservation::total_only(Duration::ZERO),
                    };
                }

                active.fetch_add(1, Ordering::SeqCst);
                let _guard = ActiveSnapshotGuard { active };
                started.add_permits(1);
                if blocked.load(Ordering::SeqCst) {
                    release.acquire().await.unwrap().forget();
                }
                let result = mock::sample()
                    .map_err(|error| FirewallError::Parse(error.to_string()))
                    .map(|snapshot| {
                        Arc::new(RefreshOverview {
                            status: snapshot.status,
                            default_zone: snapshot.default_zone,
                            active: snapshot.active,
                            runtime: snapshot.runtime,
                            permanent: snapshot.permanent,
                            available_services: snapshot.available_services,
                            policy_names: Scoped {
                                runtime: snapshot.policies.runtime.into_keys().collect(),
                                permanent: snapshot.policies.permanent.into_keys().collect(),
                            },
                            degraded: snapshot.degraded,
                        })
                    })
                    .map(Some);
                completions.fetch_add(1, Ordering::SeqCst);
                OverviewRead {
                    result,
                    observation: RefreshObservation::total_only(Duration::ZERO),
                }
            }
        }

        fn snapshot_hydrated(
            &self,
            _overview: Option<Arc<RefreshOverview>>,
            _priority: &RefreshPrioritySource,
        ) -> impl std::future::Future<Output = SnapshotRead> + Send {
            let hydration = self.snapshot_observed();
            let starts = Arc::clone(&self.hydration_starts);
            let completions = Arc::clone(&self.hydration_completions);
            async move {
                starts.fetch_add(1, Ordering::SeqCst);
                let read = hydration.await;
                completions.fetch_add(1, Ordering::SeqCst);
                read
            }
        }

        async fn apply(&self, operation: &FirewallOperation) -> OperationOutcome {
            let active_snapshots = self.active_snapshots.load(Ordering::SeqCst)
                + self.active_overviews.load(Ordering::SeqCst);
            self.apply_observed_zero_active
                .store(active_snapshots == 0, Ordering::SeqCst);
            self.active_snapshots_at_apply
                .lock()
                .unwrap()
                .push(active_snapshots);
            self.applied_operations
                .lock()
                .unwrap()
                .push(operation.clone());
            OperationOutcome::Applied {
                operation: operation.clone(),
                steps: vec![StepReport {
                    target: "runtime",
                    invocation: vec!["--fake".to_owned()],
                    result: Ok(()),
                }],
            }
        }
    }

    struct LargeBackend;

    impl FirewallBackend for LargeBackend {
        async fn probe(&self) -> Result<FirewallStatus, FirewallError> {
            mock::sample()
                .map(|snapshot| snapshot.status)
                .map_err(|error| FirewallError::Parse(error.to_string()))
        }

        async fn snapshot(&self) -> Result<FirewallSnapshot, FirewallError> {
            mock::large().map_err(|error| FirewallError::Parse(error.to_string()))
        }

        async fn apply(&self, operation: &FirewallOperation) -> OperationOutcome {
            OperationOutcome::Applied {
                operation: operation.clone(),
                steps: Vec::new(),
            }
        }
    }

    struct DriftingBackend {
        snapshot_calls: Arc<AtomicUsize>,
        apply_calls: Arc<AtomicUsize>,
    }

    impl FirewallBackend for DriftingBackend {
        async fn probe(&self) -> Result<FirewallStatus, FirewallError> {
            Err(FirewallError::DaemonNotRunning)
        }

        async fn snapshot(&self) -> Result<FirewallSnapshot, FirewallError> {
            let call = self.snapshot_calls.fetch_add(1, Ordering::SeqCst);
            let mut snapshot = mock::sample().map_err(|e| FirewallError::Parse(e.to_string()))?;
            if call > 0 {
                snapshot.status.panic_mode = !snapshot.status.panic_mode;
            }
            Ok(snapshot)
        }

        async fn apply(&self, operation: &FirewallOperation) -> OperationOutcome {
            self.apply_calls.fetch_add(1, Ordering::SeqCst);
            OperationOutcome::Applied {
                operation: operation.clone(),
                steps: vec![StepReport {
                    target: "runtime",
                    invocation: vec!["--fake".to_owned()],
                    result: Ok(()),
                }],
            }
        }
    }

    fn reviewed(operation: FirewallOperation) -> MutationRequest {
        MutationRequest::new(operation, Arc::new(mock::sample().unwrap()))
    }

    fn reviewed_plan(operations: Vec<FirewallOperation>) -> MutationPlan {
        MutationPlan::new(operations, Arc::new(mock::sample().unwrap()))
    }

    fn manual_request() -> ManualRefreshRequest {
        ManualRefreshRequest::new(std::num::NonZeroU64::MIN)
    }

    fn numbered_port_operation(index: usize) -> FirewallOperation {
        FirewallOperation::AddPort {
            zone: crate::domain::ZoneName::parse("public").unwrap(),
            port: format!("{}/tcp", 10_000 + index).parse().unwrap(),
            target: crate::domain::ConfigurationTarget::Runtime,
        }
    }

    async fn wait_for_sender_to_drain<T>(sender: &mpsc::Sender<T>, capacity: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while sender.capacity() != capacity {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    async fn complete_queued_normal_request(
        backend: &ControlledSnapshotBackend,
        event_rx: &mut mpsc::Receiver<EngineEvent>,
        expected: &FirewallOperation,
        is_plan: bool,
    ) {
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if result.outcome.operation() == expected
                    && result.completed_rollback.is_none()
        ));
        if is_plan {
            assert!(matches!(
                event_rx.recv().await.unwrap(),
                EngineEvent::PlanFinished {
                    applied: 1,
                    ref remaining,
                } if remaining.is_empty()
            ));
        }
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::PostMutation
        ));
    }

    fn test_receivers(requests: mpsc::Receiver<EngineRequest>) -> EngineReceivers {
        let (_manual_tx, manual_refreshes) = mpsc::channel(1);
        let (_rollback_tx, rollbacks) = mpsc::channel(1);
        EngineReceivers::new(requests, manual_refreshes, rollbacks)
    }

    fn test_receiver_lanes(
        requests: mpsc::Receiver<EngineRequest>,
    ) -> (
        EngineReceivers,
        mpsc::Sender<ManualRefreshRequest>,
        mpsc::Sender<RollbackRequest>,
    ) {
        let (manual_tx, manual_refreshes) = mpsc::channel(REQUEST_CAPACITY);
        let (rollback_tx, rollbacks) = mpsc::channel(1);
        (
            EngineReceivers::new(requests, manual_refreshes, rollbacks),
            manual_tx,
            rollback_tx,
        )
    }

    #[tokio::test]
    async fn batched_manual_request_reaches_lifecycle_metadata_exactly() {
        let (_request_tx, request_rx) = mpsc::channel(8);
        let (inputs, manual_tx, _rollback_tx) = test_receiver_lanes(request_rx);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = ControlledSnapshotBackend::new();
        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            inputs,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        manual_tx
            .send(crate::application::ManualRefreshRequest::new(
                std::num::NonZeroU64::new(7).unwrap(),
            ))
            .await
            .unwrap();
        wait_for_sender_to_drain(&manual_tx, REQUEST_CAPACITY).await;

        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::Initial
                && schedule.merged_manual_requests == 7
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Manual,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::Manual
                && schedule.merged_manual_requests == 0
        ));
        tokio::task::yield_now().await;
        assert_eq!(backend.snapshot_calls.load(Ordering::SeqCst), 2);
        assert!(matches!(
            event_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn idle_batched_manual_request_retains_six_merged_requests() {
        let (_request_tx, request_rx) = mpsc::channel(8);
        let (inputs, manual_tx, _rollback_tx) = test_receiver_lanes(request_rx);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = ControlledSnapshotBackend::new();
        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            inputs,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::Initial
        ));

        manual_tx
            .send(ManualRefreshRequest::new(
                std::num::NonZeroU64::new(7).unwrap(),
            ))
            .await
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Manual,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::Manual
                && schedule.merged_manual_requests == 6
        ));
        tokio::task::yield_now().await;
        assert_eq!(backend.snapshot_calls.load(Ordering::SeqCst), 2);
        assert!(matches!(
            event_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn manual_batch_overflow_is_rejected_without_corrupting_active_lifecycle() {
        let (_request_tx, request_rx) = mpsc::channel(8);
        let (inputs, manual_tx, _rollback_tx) = test_receiver_lanes(request_rx);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = ControlledSnapshotBackend::new();
        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            inputs,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        manual_tx
            .send(crate::application::ManualRefreshRequest::new(
                std::num::NonZeroU64::new(u64::MAX).unwrap(),
            ))
            .await
            .unwrap();
        wait_for_sender_to_drain(&manual_tx, REQUEST_CAPACITY).await;
        manual_tx
            .send(crate::application::ManualRefreshRequest::new(
                std::num::NonZeroU64::MIN,
            ))
            .await
            .unwrap();

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::ManualDemandRejected { count }
                if count == std::num::NonZeroU64::MIN
        ));
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::Initial
                && schedule.merged_manual_requests == u64::MAX
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Manual,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::Manual
                && schedule.merged_manual_requests == 0
        ));
    }

    #[tokio::test]
    async fn initial_refresh_happens_without_a_request() {
        let (_request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = FakeBackend {
            calls: AtomicUsize::new(0),
            fail: false,
        };
        tokio::spawn(run(
            backend,
            TestRollbackGuard,
            test_receivers(request_rx),
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        match event_rx.recv().await.unwrap() {
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(snapshot),
                observation,
            } => {
                assert_eq!(schedule.trigger, RefreshTrigger::Initial);
                assert_eq!(snapshot.default_zone.as_str(), "public");
                assert_eq!(observation.process_count, None);
                assert!(observation.sections.is_empty());
            }
            other => panic!("expected successful refresh, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn errors_are_reported_not_swallowed() {
        let (_request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = FakeBackend {
            calls: AtomicUsize::new(0),
            fail: true,
        };
        tokio::spawn(run(
            backend,
            TestRollbackGuard,
            test_receivers(request_rx),
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        event_rx.recv().await.unwrap(); // started
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                result: Err(FirewallError::DaemonNotRunning),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn apply_reports_outcome_then_refreshes() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = FakeBackend {
            calls: AtomicUsize::new(0),
            fail: false,
        };
        tokio::spawn(run(
            backend,
            TestRollbackGuard,
            test_receivers(request_rx),
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));
        // initial refresh
        event_rx.recv().await.unwrap();
        event_rx.recv().await.unwrap();

        request_tx
            .send(EngineRequest::Apply(reviewed(FirewallOperation::Reload)))
            .await
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if matches!(result.outcome, OperationOutcome::Applied { .. })
        ));
        // post-mutation refresh follows automatically
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn stale_single_operation_is_rejected_before_apply_or_rollback_arm() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let snapshot_calls = Arc::new(AtomicUsize::new(0));
        let apply_calls = Arc::new(AtomicUsize::new(0));
        let guard = RecordingRollbackGuard::default();
        let guard_log = Arc::clone(&guard.log);
        tokio::spawn(run(
            DriftingBackend {
                snapshot_calls: Arc::clone(&snapshot_calls),
                apply_calls: Arc::clone(&apply_calls),
            },
            guard,
            test_receivers(request_rx),
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        event_rx.recv().await.unwrap();
        let expected = match event_rx.recv().await.unwrap() {
            EngineEvent::RefreshFinished {
                result: Ok(snapshot),
                ..
            } => snapshot,
            other => panic!("expected initial snapshot, got {other:?}"),
        };
        let operation = FirewallOperation::RemovePort {
            zone: crate::domain::ZoneName::parse("public").unwrap(),
            port: "8080/tcp".parse().unwrap(),
            target: crate::domain::ConfigurationTarget::Runtime,
        };
        request_tx
            .send(EngineRequest::Apply(MutationRequest::new(
                operation, expected,
            )))
            .await
            .unwrap();

        match event_rx.recv().await.unwrap() {
            EngineEvent::OperationFinished(result) => {
                assert_eq!(
                    result.outcome.first_error(),
                    Some(&FirewallError::StaleSnapshot)
                );
                assert!(result.rollback.is_none());
            }
            other => panic!("expected rejected operation, got {other:?}"),
        }
        assert_eq!(apply_calls.load(Ordering::SeqCst), 0);
        assert!(guard_log.lock().unwrap().armed.is_empty());
        assert!(snapshot_calls.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn stale_plan_rejects_the_batch_and_returns_every_operation() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let snapshot_calls = Arc::new(AtomicUsize::new(0));
        let apply_calls = Arc::new(AtomicUsize::new(0));
        tokio::spawn(run(
            DriftingBackend {
                snapshot_calls,
                apply_calls: Arc::clone(&apply_calls),
            },
            TestRollbackGuard,
            test_receivers(request_rx),
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        event_rx.recv().await.unwrap();
        let expected = match event_rx.recv().await.unwrap() {
            EngineEvent::RefreshFinished {
                result: Ok(snapshot),
                ..
            } => snapshot,
            other => panic!("expected initial snapshot, got {other:?}"),
        };
        let operations = vec![FirewallOperation::Reload, FirewallOperation::Reload];
        request_tx
            .send(EngineRequest::ApplyPlan(MutationPlan::new(
                operations.clone(),
                expected,
            )))
            .await
            .unwrap();

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if result.outcome.first_error() == Some(&FirewallError::StaleSnapshot)
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::PlanFinished {
                applied: 0,
                remaining,
            } if remaining == operations
        ));
        assert_eq!(apply_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn read_only_engine_rejects_mutations() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = FakeBackend {
            calls: AtomicUsize::new(0),
            fail: false,
        };
        tokio::spawn(run(
            backend,
            TestRollbackGuard,
            test_receivers(request_rx),
            event_tx,
            Duration::from_secs(3600),
            true,
            Duration::from_secs(30),
        ));
        event_rx.recv().await.unwrap();
        event_rx.recv().await.unwrap();

        request_tx
            .send(EngineRequest::Apply(reviewed(FirewallOperation::Reload)))
            .await
            .unwrap();
        match event_rx.recv().await.unwrap() {
            EngineEvent::OperationFinished(result) => {
                assert_eq!(
                    result.outcome.first_error(),
                    Some(&FirewallError::ReadOnlyMode)
                );
            }
            other => panic!("expected OperationFinished, got {other:?}"),
        }
    }

    /// A backend that succeeds on every `apply` except the Nth call, which it
    /// fails — enough to drive the engine's fail-fast plan logic to a known
    /// halt point without depending on any operation's semantics.
    struct CountingBackend {
        apply_calls: AtomicUsize,
        /// 1-indexed apply call that returns `Failed`; `0` never fails.
        fail_at: usize,
    }

    impl FirewallBackend for CountingBackend {
        async fn probe(&self) -> Result<FirewallStatus, FirewallError> {
            Err(FirewallError::DaemonNotRunning)
        }

        async fn snapshot(&self) -> Result<FirewallSnapshot, FirewallError> {
            mock::sample().map_err(|e| FirewallError::Parse(e.to_string()))
        }

        async fn apply(&self, operation: &FirewallOperation) -> OperationOutcome {
            let call = self.apply_calls.fetch_add(1, Ordering::SeqCst) + 1;
            let step = |result: Result<(), FirewallError>| StepReport {
                target: "runtime",
                invocation: vec!["--fake".to_owned()],
                result,
            };
            if call == self.fail_at {
                OperationOutcome::Failed {
                    operation: operation.clone(),
                    steps: vec![step(Err(FirewallError::DaemonNotRunning))],
                }
            } else {
                OperationOutcome::Applied {
                    operation: operation.clone(),
                    steps: vec![step(Ok(()))],
                }
            }
        }
    }

    #[tokio::test]
    async fn engine_validation_rejects_a_forged_request_before_apply() {
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 0,
        };
        let (event_tx, mut event_rx) = mpsc::channel(4);
        let operation = FirewallOperation::AddService {
            zone: crate::domain::ZoneName::parse("public").unwrap(),
            service: crate::domain::ServiceName::parse("https").unwrap(),
            target: crate::domain::ConfigurationTarget::RuntimeAndPermanent,
        };

        apply(
            &backend,
            &TestRollbackGuard,
            &event_tx,
            reviewed(operation),
            false,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        match event_rx.recv().await.unwrap() {
            EngineEvent::OperationFinished(result) => assert!(matches!(
                result.outcome.first_error(),
                Some(FirewallError::Validation(_))
            )),
            other => panic!("expected validation failure, got {other:?}"),
        }
        assert_eq!(backend.apply_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn plan_validation_rejects_the_whole_forged_batch_before_apply_or_arm() {
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 0,
        };
        let guard = RecordingRollbackGuard::default();
        let guard_log = Arc::clone(&guard.log);
        let (event_tx, mut event_rx) = mpsc::channel(4);
        let invalid = FirewallOperation::AddService {
            zone: crate::domain::ZoneName::parse("public").unwrap(),
            service: crate::domain::ServiceName::parse("https").unwrap(),
            target: crate::domain::ConfigurationTarget::RuntimeAndPermanent,
        };

        apply_plan(
            &backend,
            &guard,
            &event_tx,
            reviewed_plan(vec![invalid, FirewallOperation::Reload]),
            false,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if matches!(result.outcome.first_error(), Some(FirewallError::Validation(_)))
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::PlanFinished {
                applied: 0,
                ref remaining,
            } if remaining.len() == 2
        ));
        assert_eq!(backend.apply_calls.load(Ordering::SeqCst), 0);
        assert!(guard_log.lock().unwrap().armed.is_empty());
    }

    #[tokio::test]
    async fn empty_plan_with_failed_preflight_reports_an_empty_completion() {
        let backend = FakeBackend {
            calls: AtomicUsize::new(0),
            fail: true,
        };
        let (event_tx, mut event_rx) = mpsc::channel(2);

        apply_plan(
            &backend,
            &TestRollbackGuard,
            &event_tx,
            MutationPlan::new(Vec::new(), Arc::new(mock::sample().unwrap())),
            false,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::PlanFinished {
                applied: 0,
                ref remaining,
            } if remaining.is_empty()
        ));
        assert!(event_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn read_only_plan_fails_fast_without_apply_or_watchdog_arm() {
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 0,
        };
        let guard = RecordingRollbackGuard::default();
        let guard_log = Arc::clone(&guard.log);
        let (event_tx, mut event_rx) = mpsc::channel(4);

        apply_plan(
            &backend,
            &guard,
            &event_tx,
            reviewed_plan(vec![FirewallOperation::Reload, FirewallOperation::Reload]),
            true,
            Duration::from_secs(30),
        )
        .await
        .unwrap();

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if result.outcome.first_error() == Some(&FirewallError::ReadOnlyMode)
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::PlanFinished {
                applied: 0,
                ref remaining,
            } if remaining == &[FirewallOperation::Reload]
        ));
        assert_eq!(backend.apply_calls.load(Ordering::SeqCst), 0);
        assert!(guard_log.lock().unwrap().armed.is_empty());
    }

    #[tokio::test]
    async fn read_only_rollback_keeps_the_watchdog_armed_without_backend_apply() {
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 0,
        };
        let guard = RecordingRollbackGuard::default();
        let guard_log = Arc::clone(&guard.log);
        let (event_tx, mut event_rx) = mpsc::channel(2);
        let rollback_id = RollbackGuardId::new(44);

        apply_rollback(
            &backend,
            &guard,
            &event_tx,
            rollback_id,
            FirewallOperation::Reload,
            Some("fwdeck-rollback-test".to_owned()),
            true,
        )
        .await
        .unwrap();

        match event_rx.recv().await.unwrap() {
            EngineEvent::OperationFinished(result) => {
                assert_eq!(result.completed_rollback, Some(rollback_id));
                assert_eq!(
                    result.outcome.first_error(),
                    Some(&FirewallError::ReadOnlyMode)
                );
                assert!(
                    result
                        .guard_warning
                        .as_deref()
                        .is_some_and(|warning| warning.contains("remains armed"))
                );
            }
            other => panic!("expected rollback completion, got {other:?}"),
        }
        assert_eq!(backend.apply_calls.load(Ordering::SeqCst), 0);
        assert!(guard_log.lock().unwrap().disarmed.is_empty());
    }

    async fn drain_initial_refresh(rx: &mut mpsc::Receiver<EngineEvent>) {
        rx.recv().await.unwrap(); // RefreshStarted
        rx.recv().await.unwrap(); // RefreshFinished
    }

    #[tokio::test(start_paused = true)]
    async fn overview_event_arrives_before_hydration_finishes() {
        let (_request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = ControlledSnapshotBackend::new();
        backend.enable_blocked_overview();
        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            test_receivers(request_rx),
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        let refresh_id = match event_rx.recv().await.unwrap() {
            EngineEvent::RefreshStarted {
                id,
                trigger: RefreshTrigger::Initial,
            } => id,
            other => panic!("expected initial refresh start, got {other:?}"),
        };
        backend.wait_for_overview_start().await;
        assert_eq!(backend.overview_completions(), 0);

        backend.release_overview();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshOverviewReady { id, .. } if id == refresh_id && id.get() == 1
        ));
        assert_eq!(backend.hydration_completions(), 0);
        assert_eq!(backend.hydration_starts(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn mutation_cancels_overview_before_apply() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = ControlledSnapshotBackend::new();
        backend.enable_blocked_overview();
        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            test_receivers(request_rx),
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_overview_start().await;
        request_tx
            .send(EngineRequest::Apply(reviewed(FirewallOperation::Reload)))
            .await
            .unwrap();

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshCancelled {
                reason: RefreshCancellationReason::MutationPreempted,
                ..
            }
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(_)
        ));
        assert_eq!(backend.overview_completions(), 0);
        assert_eq!(backend.active_snapshots_at_apply.lock().unwrap()[0], 0);
    }

    #[tokio::test(start_paused = true)]
    async fn mutation_cancels_hydration_before_apply() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = ControlledSnapshotBackend::new();
        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            test_receivers(request_rx),
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        assert_eq!(backend.hydration_starts(), 1);
        request_tx
            .send(EngineRequest::Apply(reviewed(FirewallOperation::Reload)))
            .await
            .unwrap();

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshCancelled {
                reason: RefreshCancellationReason::MutationPreempted,
                ..
            }
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(_)
        ));
        assert_eq!(backend.hydration_completions(), 0);
        assert_eq!(backend.active_snapshots_at_apply.lock().unwrap()[0], 0);
        assert_eq!(backend.applied_operations.lock().unwrap().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn rollback_preempts_mandatory_hydration_and_restarts_it() {
        let (request_tx, request_rx) = mpsc::channel(REQUEST_CAPACITY);
        let (inputs, _manual_tx, rollback_tx) = test_receiver_lanes(request_rx);
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let backend = ControlledSnapshotBackend::new();
        let rollback = FirewallOperation::SetPanicMode { enabled: true };
        let rollback_id = RollbackGuardId::new(915);
        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            inputs,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        request_tx
            .send(EngineRequest::Apply(reviewed(FirewallOperation::Reload)))
            .await
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshCancelled { .. }
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(_)
        ));

        let mut post_mutation_starts = 0;
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        post_mutation_starts += 1;
        backend.wait_for_snapshot_start().await;
        rollback_tx
            .send(RollbackRequest {
                id: rollback_id,
                operation: rollback.clone(),
                watchdog_unit: None,
            })
            .await
            .unwrap();

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshCancelled {
                reason: RefreshCancellationReason::RollbackPreempted,
                ..
            }
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if result.completed_rollback == Some(rollback_id)
                    && result.outcome.operation() == &rollback
        ));
        assert_eq!(backend.hydration_completions(), 0);
        assert_eq!(backend.active_snapshots_at_apply.lock().unwrap()[1], 0);
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        post_mutation_starts += 1;
        backend.wait_for_snapshot_start().await;

        assert_eq!(post_mutation_starts, 2);
        assert_eq!(backend.hydration_starts(), 3);
        assert_eq!(
            backend
                .applied_operations
                .lock()
                .unwrap()
                .iter()
                .filter(|operation| *operation == &rollback)
                .count(),
            1
        );
    }

    #[tokio::test(start_paused = true)]
    async fn mutation_drops_ordinary_refresh_before_apply() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = ControlledSnapshotBackend::new();
        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            test_receivers(request_rx),
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        let cancelled_id = match event_rx.recv().await.unwrap() {
            EngineEvent::RefreshStarted {
                id,
                trigger: RefreshTrigger::Initial,
            } => id,
            other => panic!("expected initial refresh start, got {other:?}"),
        };
        backend.wait_for_snapshot_start().await;
        tokio::time::advance(Duration::from_millis(5)).await;
        request_tx
            .send(EngineRequest::Apply(reviewed(FirewallOperation::Reload)))
            .await
            .unwrap();

        match event_rx.recv().await.unwrap() {
            EngineEvent::RefreshCancelled {
                schedule,
                reason,
                elapsed,
            } => {
                assert_eq!(schedule.id, cancelled_id);
                assert_eq!(schedule.trigger, RefreshTrigger::Initial);
                assert_eq!(schedule.merged_manual_requests, 0);
                assert_eq!(schedule.coalesced_periodic_ticks, 0);
                assert_eq!(reason, RefreshCancellationReason::MutationPreempted);
                assert!(elapsed > Duration::ZERO);
            }
            other => panic!("expected refresh cancellation, got {other:?}"),
        }
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(_)
        ));
        let post_mutation_id = match event_rx.recv().await.unwrap() {
            EngineEvent::RefreshStarted {
                id,
                trigger: RefreshTrigger::PostMutation,
            } => id,
            other => panic!("expected post-mutation refresh start, got {other:?}"),
        };
        assert_ne!(post_mutation_id, cancelled_id);
        backend.wait_for_snapshot_start().await;

        assert!(backend.apply_observed_zero_active.load(Ordering::SeqCst));
        assert_eq!(backend.max_active_snapshots.load(Ordering::SeqCst), 1);

        backend.release_snapshot();
        match event_rx.recv().await.unwrap() {
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } => {
                assert_eq!(schedule.id, post_mutation_id);
                assert_ne!(schedule.id, cancelled_id);
                assert_eq!(schedule.trigger, RefreshTrigger::PostMutation);
            }
            other => panic!("expected post-mutation refresh completion, got {other:?}"),
        }
        tokio::task::yield_now().await;
        assert!(matches!(
            event_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn queued_mutation_cannot_cancel_post_mutation_refresh() {
        let (request_tx, request_rx) = mpsc::channel(REQUEST_CAPACITY);
        let (inputs, manual_tx, _rollback_tx) = test_receiver_lanes(request_rx);
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let backend = ControlledSnapshotBackend::new();
        let first = FirewallOperation::Reload;
        let second = FirewallOperation::SetPanicMode { enabled: true };

        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            inputs,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        request_tx
            .try_send(EngineRequest::Apply(reviewed(first.clone())))
            .unwrap();
        manual_tx.try_send(manual_request()).unwrap();
        request_tx
            .try_send(EngineRequest::Apply(reviewed(second.clone())))
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshCancelled {
                reason: RefreshCancellationReason::MutationPreempted,
                ..
            }
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result) if result.outcome.operation() == &first
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;

        tokio::task::yield_now().await;
        assert_eq!(backend.active_snapshots.load(Ordering::SeqCst), 1);
        assert!(matches!(
            event_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::PostMutation
                && schedule.merged_manual_requests == 1
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result) if result.outcome.operation() == &second
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::PostMutation
        ));

        assert_eq!(*backend.applied_operations.lock().unwrap(), [first, second]);
        assert_eq!(backend.max_active_snapshots.load(Ordering::SeqCst), 1);
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn rollback_preempts_blocked_post_mutation_refresh_and_preserves_normal_fifo() {
        let (request_tx, request_rx) = mpsc::channel(REQUEST_CAPACITY);
        let (inputs, manual_tx, rollback_tx) = test_receiver_lanes(request_rx);
        let (event_tx, mut event_rx) = mpsc::channel(64);
        let backend = ControlledSnapshotBackend::new();
        let first = FirewallOperation::Reload;
        let rollback = FirewallOperation::SetPanicMode { enabled: true };
        let plan_operation = FirewallOperation::Reload;
        let queued_apply = FirewallOperation::Reload;
        let rollback_id = RollbackGuardId::new(909);

        let engine = tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            inputs,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        request_tx
            .send(EngineRequest::Apply(reviewed(first.clone())))
            .await
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshCancelled { .. }
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if result.outcome.operation() == &first
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;

        request_tx
            .send(EngineRequest::ApplyPlan(reviewed_plan(vec![
                plan_operation.clone(),
            ])))
            .await
            .unwrap();
        request_tx
            .send(EngineRequest::Apply(reviewed(queued_apply.clone())))
            .await
            .unwrap();
        rollback_tx
            .send(RollbackRequest {
                id: rollback_id,
                operation: rollback.clone(),
                watchdog_unit: None,
            })
            .await
            .unwrap();

        let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match event {
            EngineEvent::RefreshCancelled {
                schedule, reason, ..
            } => {
                assert_eq!(schedule.trigger, RefreshTrigger::PostMutation);
                assert_eq!(format!("{reason:?}"), "RollbackPreempted");
            }
            other => panic!("expected rollback-priority cancellation, got {other:?}"),
        }
        match event_rx.recv().await.unwrap() {
            EngineEvent::OperationFinished(result) => {
                assert_eq!(result.completed_rollback, Some(rollback_id));
                assert_eq!(result.outcome.operation(), &rollback);
            }
            other => panic!("expected rollback completion, got {other:?}"),
        }
        assert_eq!(
            backend.active_snapshots_at_apply.lock().unwrap()[1],
            0,
            "the blocked mandatory read must drop before rollback apply"
        );
        assert_eq!(
            *backend.applied_operations.lock().unwrap(),
            [first.clone(), rollback.clone()],
            "queued normal requests must not run before the safety rollback"
        );

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::PostMutation
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if result.outcome.operation() == &plan_operation
                    && result.completed_rollback.is_none()
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::PlanFinished {
                applied: 1,
                ref remaining,
            } if remaining.is_empty()
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished { result: Ok(_), .. }
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if result.outcome.operation() == &queued_apply
                    && result.completed_rollback.is_none()
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished { result: Ok(_), .. }
        ));

        assert_eq!(
            *backend.applied_operations.lock().unwrap(),
            [first, rollback.clone(), plan_operation, queued_apply]
        );
        assert_eq!(
            backend
                .applied_operations
                .lock()
                .unwrap()
                .iter()
                .filter(|operation| *operation == &rollback)
                .count(),
            1,
            "rollback must execute exactly once"
        );
        assert_eq!(backend.max_active_snapshots.load(Ordering::SeqCst), 1);

        drop(request_tx);
        drop(manual_tx);
        drop(rollback_tx);
        engine.await.unwrap();
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn saturated_normal_fifo_still_observes_rollback_and_preserves_all_normal_work() {
        let (request_tx, request_rx) = mpsc::channel(REQUEST_CAPACITY);
        let (inputs, manual_tx, rollback_tx) = test_receiver_lanes(request_rx);
        let (event_tx, mut event_rx) = mpsc::channel(256);
        let backend = ControlledSnapshotBackend::new();
        let first = FirewallOperation::Reload;
        let rollback = FirewallOperation::SetPanicMode { enabled: true };
        let rollback_id = RollbackGuardId::new(910);
        let queued: Vec<_> = (0..REQUEST_CAPACITY)
            .map(|index| (numbered_port_operation(index), index % 2 == 1))
            .collect();

        let engine = tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            inputs,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        request_tx
            .send(EngineRequest::Apply(reviewed(first.clone())))
            .await
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshCancelled { .. }
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if result.outcome.operation() == &first
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;

        for (operation, is_plan) in &queued {
            let request = if *is_plan {
                EngineRequest::ApplyPlan(reviewed_plan(vec![operation.clone()]))
            } else {
                EngineRequest::Apply(reviewed(operation.clone()))
            };
            request_tx.send(request).await.unwrap();
        }
        wait_for_sender_to_drain(&request_tx, REQUEST_CAPACITY).await;
        rollback_tx
            .send(RollbackRequest {
                id: rollback_id,
                operation: rollback.clone(),
                watchdog_unit: None,
            })
            .await
            .unwrap();

        let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            event,
            EngineEvent::RefreshCancelled {
                schedule,
                reason: RefreshCancellationReason::RollbackPreempted,
                ..
            } if schedule.trigger == RefreshTrigger::PostMutation
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if result.outcome.operation() == &rollback
                    && result.completed_rollback == Some(rollback_id)
        ));
        assert_eq!(backend.active_snapshots_at_apply.lock().unwrap()[1], 0);
        assert_eq!(
            *backend.applied_operations.lock().unwrap(),
            [first.clone(), rollback.clone()]
        );

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished { result: Ok(_), .. }
        ));

        for (operation, is_plan) in &queued {
            complete_queued_normal_request(&backend, &mut event_rx, operation, *is_plan).await;
        }

        let mut expected = vec![first, rollback.clone()];
        expected.extend(queued.iter().map(|(operation, _)| operation.clone()));
        assert_eq!(*backend.applied_operations.lock().unwrap(), expected);
        assert_eq!(
            backend
                .applied_operations
                .lock()
                .unwrap()
                .iter()
                .filter(|operation| *operation == &rollback)
                .count(),
            1
        );
        assert_eq!(backend.max_active_snapshots.load(Ordering::SeqCst), 1);

        drop(request_tx);
        drop(manual_tx);
        drop(rollback_tx);
        engine.await.unwrap();
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn manual_after_saturated_post_mutation_start_remains_one_trailing_lifecycle() {
        let (request_tx, request_rx) = mpsc::channel(REQUEST_CAPACITY);
        let (inputs, manual_tx, _rollback_tx) = test_receiver_lanes(request_rx);
        let (event_tx, mut event_rx) = mpsc::channel(256);
        let backend = ControlledSnapshotBackend::new();
        let first = FirewallOperation::Reload;
        let queued: Vec<_> = (REQUEST_CAPACITY..REQUEST_CAPACITY * 2)
            .map(numbered_port_operation)
            .collect();

        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            inputs,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        request_tx
            .send(EngineRequest::Apply(reviewed(first)))
            .await
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshCancelled { .. }
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(_)
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;

        for operation in &queued {
            request_tx
                .send(EngineRequest::Apply(reviewed(operation.clone())))
                .await
                .unwrap();
        }
        wait_for_sender_to_drain(&request_tx, REQUEST_CAPACITY).await;
        manual_tx.send(manual_request()).await.unwrap();
        backend.release_snapshot();

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::PostMutation
                && schedule.merged_manual_requests == 1
        ));

        for operation in &queued {
            complete_queued_normal_request(&backend, &mut event_rx, operation, false).await;
        }

        let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            event,
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Manual,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::Manual
                && schedule.merged_manual_requests == 0
        ));
        tokio::task::yield_now().await;
        assert!(matches!(
            event_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert_eq!(backend.snapshot_calls.load(Ordering::SeqCst), 35);
        assert_eq!(backend.max_active_snapshots.load(Ordering::SeqCst), 1);
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn completion_boundary_manual_survives_priority_rollback_reconciliation() {
        let (request_tx, request_rx) = mpsc::channel(REQUEST_CAPACITY);
        let (inputs, manual_tx, rollback_tx) = test_receiver_lanes(request_rx);
        let (event_tx, mut event_rx) = mpsc::channel(64);
        let backend = ControlledSnapshotBackend::new();
        let first = FirewallOperation::Reload;
        let rollback = FirewallOperation::SetPanicMode { enabled: true };
        let rollback_id = RollbackGuardId::new(911);

        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            inputs,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        request_tx
            .send(EngineRequest::Apply(reviewed(first)))
            .await
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshCancelled { .. }
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(_)
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;

        manual_tx.try_send(manual_request()).unwrap();
        rollback_tx
            .try_send(RollbackRequest {
                id: rollback_id,
                operation: rollback.clone(),
                watchdog_unit: None,
            })
            .unwrap();
        backend.release_snapshot();

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::PostMutation
                && schedule.merged_manual_requests == 1
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if result.outcome.operation() == &rollback
                    && result.completed_rollback == Some(rollback_id)
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished { result: Ok(_), .. }
        ));

        let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            event,
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Manual,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::Manual
        ));
        assert_eq!(
            backend
                .applied_operations
                .lock()
                .unwrap()
                .iter()
                .filter(|operation| *operation == &rollback)
                .count(),
            1
        );
        assert_eq!(backend.max_active_snapshots.load(Ordering::SeqCst), 1);
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn queued_manual_survives_priority_rollback_of_blocked_reconciliation() {
        let (request_tx, request_rx) = mpsc::channel(REQUEST_CAPACITY);
        let (inputs, manual_tx, rollback_tx) = test_receiver_lanes(request_rx);
        let (event_tx, mut event_rx) = mpsc::channel(64);
        let backend = ControlledSnapshotBackend::new();
        let first = FirewallOperation::Reload;
        let rollback = FirewallOperation::SetPanicMode { enabled: true };
        let rollback_id = RollbackGuardId::new(912);

        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            inputs,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        request_tx
            .send(EngineRequest::Apply(reviewed(first)))
            .await
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshCancelled { .. }
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(_)
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;

        manual_tx.try_send(manual_request()).unwrap();
        rollback_tx
            .try_send(RollbackRequest {
                id: rollback_id,
                operation: rollback.clone(),
                watchdog_unit: None,
            })
            .unwrap();

        let cancelled = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            cancelled,
            EngineEvent::RefreshCancelled {
                schedule,
                reason: RefreshCancellationReason::RollbackPreempted,
                ..
            } if schedule.trigger == RefreshTrigger::PostMutation
                && schedule.merged_manual_requests == 1
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if result.outcome.operation() == &rollback
                    && result.completed_rollback == Some(rollback_id)
        ));
        assert_eq!(backend.active_snapshots_at_apply.lock().unwrap()[1], 0);
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::PostMutation
        ));

        let trailing = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            trailing,
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Manual,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::Manual
        ));
        assert_eq!(
            backend
                .applied_operations
                .lock()
                .unwrap()
                .iter()
                .filter(|operation| *operation == &rollback)
                .count(),
            1
        );
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn normal_requests_remain_fifo_while_rollback_overtakes_exactly_once() {
        let (request_tx, request_rx) = mpsc::channel(REQUEST_CAPACITY);
        let (inputs, _manual_tx, rollback_tx) = test_receiver_lanes(request_rx);
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let backend = ControlledSnapshotBackend::new();
        let mutation = FirewallOperation::Reload;
        let rollback = FirewallOperation::SetPanicMode { enabled: true };
        let plan_operation = FirewallOperation::Reload;
        let rollback_id = RollbackGuardId::new(808);

        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            inputs,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        request_tx
            .try_send(EngineRequest::Apply(reviewed(mutation.clone())))
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshCancelled { .. }
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if result.outcome.operation() == &mutation
                    && result.completed_rollback.is_none()
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        request_tx
            .try_send(EngineRequest::ApplyPlan(reviewed_plan(vec![
                plan_operation.clone(),
            ])))
            .unwrap();
        rollback_tx
            .try_send(RollbackRequest {
                id: rollback_id,
                operation: rollback.clone(),
                watchdog_unit: None,
            })
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshCancelled {
                schedule,
                reason: RefreshCancellationReason::RollbackPreempted,
                ..
            } if schedule.trigger == RefreshTrigger::PostMutation
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if result.outcome.operation() == &rollback
                    && result.completed_rollback == Some(rollback_id)
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished { result: Ok(_), .. }
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if result.outcome.operation() == &plan_operation
                    && result.completed_rollback.is_none()
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::PlanFinished {
                applied: 1,
                ref remaining,
            } if remaining.is_empty()
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished { result: Ok(_), .. }
        ));

        assert_eq!(
            *backend.applied_operations.lock().unwrap(),
            [mutation, rollback, plan_operation]
        );
        assert_eq!(backend.snapshot_calls.load(Ordering::SeqCst), 4);
        assert_eq!(backend.max_active_snapshots.load(Ordering::SeqCst), 1);
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test(start_paused = true)]
    async fn blocked_refresh_manual_burst_timer_advance_and_mutation_stay_bounded() {
        const BURST: usize = 100;
        const REFRESH_INTERVAL: Duration = Duration::from_secs(10);
        let (request_tx, request_rx) = mpsc::channel(REQUEST_CAPACITY);
        let (inputs, manual_tx, _rollback_tx) = test_receiver_lanes(request_rx);
        let (event_tx, mut event_rx) = mpsc::channel(64);
        let backend = ControlledSnapshotBackend::new();
        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            inputs,
            event_tx,
            REFRESH_INTERVAL,
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished { result: Ok(_), .. }
        ));

        manual_tx.send(manual_request()).await.unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Manual,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;

        let burst_tx = manual_tx.clone();
        let mut burst = tokio::spawn(async move {
            for _ in 0..BURST {
                burst_tx.send(manual_request()).await.unwrap();
            }
        });
        let mut unexpected_events = Vec::new();
        loop {
            tokio::select! {
                result = &mut burst => {
                    result.unwrap();
                    break;
                }
                event = event_rx.recv() => {
                    unexpected_events.push(event.unwrap());
                }
            }
        }
        assert!(
            unexpected_events.is_empty(),
            "blocked manual refresh emitted unexpected events: {unexpected_events:?}"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            while manual_tx.capacity() != REQUEST_CAPACITY {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        tokio::time::advance(REFRESH_INTERVAL * 10).await;
        request_tx
            .send(EngineRequest::Apply(reviewed(FirewallOperation::Reload)))
            .await
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshCancelled {
                schedule,
                reason: RefreshCancellationReason::MutationPreempted,
                ..
            } if schedule.trigger == RefreshTrigger::Manual
                && schedule.merged_manual_requests == BURST as u64
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if matches!(result.outcome, OperationOutcome::Applied { .. })
        ));
        assert!(backend.apply_observed_zero_active.load(Ordering::SeqCst));
        assert_eq!(backend.applied_operations.lock().unwrap().len(), 1);
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;

        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::PostMutation
        ));
        tokio::task::yield_now().await;

        assert_eq!(backend.snapshot_calls.load(Ordering::SeqCst), 3);
        assert_eq!(backend.active_snapshots.load(Ordering::SeqCst), 0);
        assert_eq!(backend.max_active_snapshots.load(Ordering::SeqCst), 1);
        assert!(matches!(
            event_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn manual_burst_produces_one_trailing_refresh() {
        const BURST: usize = 100;
        let (_request_tx, request_rx) = mpsc::channel(BURST + 1);
        let (inputs, manual_tx, _rollback_tx) = test_receiver_lanes(request_rx);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = ControlledSnapshotBackend::new();
        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            inputs,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        for _ in 0..BURST {
            manual_tx.send(manual_request()).await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while manual_tx.capacity() != REQUEST_CAPACITY {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::Initial
                && schedule.merged_manual_requests == BURST as u64
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Manual,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::Manual
                && schedule.merged_manual_requests == 0
        ));
        tokio::task::yield_now().await;
        assert_eq!(backend.snapshot_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn manual_burst_after_post_mutation_start_is_one_trailing_lifecycle() {
        const BURST: usize = 8;
        let (request_tx, request_rx) = mpsc::channel(REQUEST_CAPACITY);
        let (inputs, manual_tx, _rollback_tx) = test_receiver_lanes(request_rx);
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let backend = ControlledSnapshotBackend::new();
        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            inputs,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        request_tx
            .send(EngineRequest::Apply(reviewed(FirewallOperation::Reload)))
            .await
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshCancelled { .. }
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(_)
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;

        for _ in 0..BURST {
            manual_tx.try_send(manual_request()).unwrap();
        }
        for _ in 0..BURST {
            tokio::task::yield_now().await;
        }
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::PostMutation
                && schedule.merged_manual_requests == BURST as u64
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Manual,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::Manual
                && schedule.merged_manual_requests == 0
        ));
        tokio::task::yield_now().await;
        assert_eq!(backend.snapshot_calls.load(Ordering::SeqCst), 3);
        assert!(matches!(
            event_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test(start_paused = true)]
    async fn trailing_manual_survives_queued_mutation_reconciliation() {
        let (request_tx, request_rx) = mpsc::channel(REQUEST_CAPACITY);
        let (inputs, manual_tx, _rollback_tx) = test_receiver_lanes(request_rx);
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let backend = ControlledSnapshotBackend::new();
        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            inputs,
            event_tx,
            Duration::from_secs(10),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        request_tx
            .send(EngineRequest::Apply(reviewed(FirewallOperation::Reload)))
            .await
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshCancelled { .. }
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(_)
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;

        manual_tx.try_send(manual_request()).unwrap();
        request_tx
            .try_send(EngineRequest::Apply(reviewed(FirewallOperation::Reload)))
            .unwrap();
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::PostMutation
                && schedule.merged_manual_requests == 1
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(_)
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished { result: Ok(_), .. }
        ));

        let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            event,
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Manual,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::Manual
                && schedule.coalesced_periodic_ticks == 0
        ));

        tokio::time::advance(Duration::from_secs(9)).await;
        tokio::task::yield_now().await;
        assert!(matches!(
            event_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Periodic,
                ..
            }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_refresh_uses_fixed_delay_after_completion() {
        let (_request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = ControlledSnapshotBackend::new();
        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            test_receivers(request_rx),
            event_tx,
            Duration::from_secs(10),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        tokio::time::advance(Duration::from_secs(25)).await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished { result: Ok(_), .. }
        ));

        tokio::time::advance(Duration::from_secs(9)).await;
        tokio::task::yield_now().await;
        assert!(matches!(
            event_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Periodic,
                ..
            }
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn mutation_preempts_periodic_refresh() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let backend = ControlledSnapshotBackend::new();
        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            test_receivers(request_rx),
            event_tx,
            Duration::from_secs(10),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished { result: Ok(_), .. }
        ));

        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Periodic,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        request_tx
            .send(EngineRequest::Apply(reviewed(FirewallOperation::Reload)))
            .await
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshCancelled {
                schedule,
                reason: RefreshCancellationReason::MutationPreempted,
                ..
            } if schedule.trigger == RefreshTrigger::Periodic
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(_)
        ));
        assert!(backend.apply_observed_zero_active.load(Ordering::SeqCst));
    }

    #[tokio::test(start_paused = true)]
    async fn due_periodic_deadline_is_recorded_on_refresh_completion() {
        let (_request_tx, request_rx) = mpsc::channel(8);
        let (inputs, manual_tx, _rollback_tx) = test_receiver_lanes(request_rx);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = ControlledSnapshotBackend::new();
        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            inputs,
            event_tx,
            Duration::from_secs(10),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished { result: Ok(_), .. }
        ));

        manual_tx.send(manual_request()).await.unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Manual,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished {
                schedule,
                result: Ok(_),
                ..
            } if schedule.trigger == RefreshTrigger::Manual
                && schedule.coalesced_periodic_ticks == 1
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn due_periodic_deadline_is_recorded_on_refresh_cancellation() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (inputs, manual_tx, _rollback_tx) = test_receiver_lanes(request_rx);
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let backend = ControlledSnapshotBackend::new();
        tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            inputs,
            event_tx,
            Duration::from_secs(10),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        backend.release_snapshot();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished { result: Ok(_), .. }
        ));

        manual_tx.send(manual_request()).await.unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Manual,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        request_tx
            .send(EngineRequest::Apply(reviewed(FirewallOperation::Reload)))
            .await
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshCancelled {
                schedule,
                reason: RefreshCancellationReason::MutationPreempted,
                ..
            } if schedule.trigger == RefreshTrigger::Manual
                && schedule.coalesced_periodic_ticks == 1
        ));
    }

    #[tokio::test]
    async fn ordinary_event_channel_closure_drops_blocked_snapshot() {
        let (_request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = ControlledSnapshotBackend::new();
        let engine = tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            test_receivers(request_rx),
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        drop(event_rx);

        tokio::time::timeout(Duration::from_secs(1), engine)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(backend.active_snapshots.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn mandatory_request_channel_closure_drops_snapshot_without_cancellation() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let backend = ControlledSnapshotBackend::new();
        let engine = tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            test_receivers(request_rx),
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        request_tx
            .send(EngineRequest::Apply(reviewed(FirewallOperation::Reload)))
            .await
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshCancelled { .. }
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(_)
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        drop(request_tx);

        tokio::time::timeout(Duration::from_secs(1), engine)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(backend.active_snapshots.load(Ordering::SeqCst), 0);
        assert!(event_rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn mandatory_event_channel_closure_drops_blocked_snapshot() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let backend = ControlledSnapshotBackend::new();
        let engine = tokio::spawn(run(
            backend.clone(),
            TestRollbackGuard,
            test_receivers(request_rx),
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Initial,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        request_tx
            .send(EngineRequest::Apply(reviewed(FirewallOperation::Reload)))
            .await
            .unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshCancelled { .. }
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(_)
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::PostMutation,
                ..
            }
        ));
        backend.wait_for_snapshot_start().await;
        drop(event_rx);

        tokio::time::timeout(Duration::from_secs(1), engine)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(backend.active_snapshots.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn plan_halts_on_first_failure_and_returns_the_remainder() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 2, // the second operation fails
        };
        tokio::spawn(run(
            backend,
            TestRollbackGuard,
            test_receivers(request_rx),
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));
        drain_initial_refresh(&mut event_rx).await;

        let plan = vec![
            FirewallOperation::Reload,
            FirewallOperation::Reload,
            FirewallOperation::Reload,
            FirewallOperation::Reload,
        ];
        request_tx
            .send(EngineRequest::ApplyPlan(reviewed_plan(plan)))
            .await
            .unwrap();

        // op1 applied, op2 failed — then the plan stops.
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if matches!(result.outcome, OperationOutcome::Applied { .. })
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if matches!(result.outcome, OperationOutcome::Failed { .. })
        ));
        match event_rx.recv().await.unwrap() {
            EngineEvent::PlanFinished { applied, remaining } => {
                assert_eq!(applied, 1, "only the first op fully applied");
                assert_eq!(
                    remaining.len(),
                    2,
                    "the two unexecuted ops must be returned, not dropped"
                );
            }
            other => panic!("expected PlanFinished, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn plan_arms_only_the_current_item_and_uses_unique_guard_ids() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 2,
        };
        let guard = RecordingRollbackGuard::default();
        let guard_log = Arc::clone(&guard.log);
        tokio::spawn(run(
            backend,
            guard,
            test_receivers(request_rx),
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));
        drain_initial_refresh(&mut event_rx).await;

        let operation = FirewallOperation::RemovePort {
            zone: crate::domain::ZoneName::parse("public").unwrap(),
            port: "8080/tcp".parse().unwrap(),
            target: crate::domain::ConfigurationTarget::Runtime,
        };
        request_tx
            .send(EngineRequest::ApplyPlan(reviewed_plan(vec![
                operation.clone(),
                operation.clone(),
                operation.clone(),
            ])))
            .await
            .unwrap();

        let first_id = match event_rx.recv().await.unwrap() {
            EngineEvent::OperationFinished(result)
                if matches!(result.outcome, OperationOutcome::Applied { .. }) =>
            {
                result.rollback.unwrap().id
            }
            other => panic!("expected first applied item with rollback, got {other:?}"),
        };
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::OperationFinished(result)
                if matches!(result.outcome, OperationOutcome::Failed { .. })
                    && result.rollback.is_none()
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::PlanFinished {
                applied: 1,
                ref remaining,
            } if remaining.len() == 1
        ));

        let log = guard_log.lock().unwrap();
        assert_eq!(
            log.armed.len(),
            2,
            "the unexecuted third item stays unarmed"
        );
        assert_eq!(log.armed[0].1, operation);
        assert_eq!(log.armed[1].1, operation);
        assert_eq!(log.armed[0].0, first_id);
        assert_ne!(
            log.armed[0].0, log.armed[1].0,
            "duplicate operations must not share guard identity"
        );
        assert_eq!(
            log.disarmed,
            [format!("fwdeck-rollback-test-{}", log.armed[1].0.get())],
            "the cleanly failed current item is disarmed"
        );
    }

    #[tokio::test]
    async fn guard_arm_failure_keeps_in_process_rollback_available() {
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 0,
        };
        let operation = FirewallOperation::RemovePort {
            zone: crate::domain::ZoneName::parse("public").unwrap(),
            port: "8080/tcp".parse().unwrap(),
            target: crate::domain::ConfigurationTarget::Runtime,
        };

        let (_, outcome, rollback, warning) = execute_operation(
            &backend,
            &FailingArmGuard,
            operation.clone(),
            false,
            Duration::from_secs(30),
            false,
        )
        .await;

        assert!(matches!(outcome, OperationOutcome::Applied { .. }));
        let Some(rollback) = rollback else {
            panic!("in-process rollback must remain registered");
        };
        assert_eq!(rollback.inverse, operation.inverse().unwrap());
        assert!(rollback.watchdog_unit.is_none());
        assert!(warning.is_some_and(|message| message.contains("arm timeout")));
    }

    #[tokio::test]
    async fn clean_failure_reports_disarm_error_without_registering_inverse() {
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 1,
        };
        let operation = FirewallOperation::RemovePort {
            zone: crate::domain::ZoneName::parse("public").unwrap(),
            port: "8080/tcp".parse().unwrap(),
            target: crate::domain::ConfigurationTarget::Runtime,
        };

        let (_, outcome, rollback, warning) = execute_operation(
            &backend,
            &FailingDisarmGuard,
            operation,
            false,
            Duration::from_secs(30),
            false,
        )
        .await;

        assert!(matches!(outcome, OperationOutcome::Failed { .. }));
        assert!(rollback.is_none(), "clean failure never exposes an inverse");
        assert!(warning.is_some_and(|message| message.contains("disarm timeout")));
    }

    #[tokio::test]
    async fn rollback_applies_even_when_watchdog_disarm_fails() {
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 0,
        };
        let (event_tx, mut event_rx) = mpsc::channel(2);
        let id = RollbackGuardId::new(700);
        let operation = FirewallOperation::AddPort {
            zone: crate::domain::ZoneName::parse("public").unwrap(),
            port: "8080/tcp".parse().unwrap(),
            target: crate::domain::ConfigurationTarget::Runtime,
        };

        apply_rollback(
            &backend,
            &FailingDisarmGuard,
            &event_tx,
            id,
            operation,
            Some("fwdeck-rollback-test-700".to_owned()),
            false,
        )
        .await
        .unwrap();

        match event_rx.recv().await.unwrap() {
            EngineEvent::OperationFinished(result) => {
                assert!(matches!(result.outcome, OperationOutcome::Applied { .. }));
                assert_eq!(result.completed_rollback, Some(id));
                assert!(
                    result
                        .guard_warning
                        .is_some_and(|message| message.contains("disarm timeout"))
                );
            }
            other => panic!("expected rollback result, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn failed_rollback_leaves_watchdog_armed() {
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 1,
        };
        let guard = RecordingRollbackGuard::default();
        let guard_log = Arc::clone(&guard.log);
        let (event_tx, mut event_rx) = mpsc::channel(2);
        let id = RollbackGuardId::new(701);
        let operation = FirewallOperation::AddPort {
            zone: crate::domain::ZoneName::parse("public").unwrap(),
            port: "8080/tcp".parse().unwrap(),
            target: crate::domain::ConfigurationTarget::Runtime,
        };

        apply_rollback(
            &backend,
            &guard,
            &event_tx,
            id,
            operation,
            Some("fwdeck-rollback-test-701".to_owned()),
            false,
        )
        .await
        .unwrap();

        match event_rx.recv().await.unwrap() {
            EngineEvent::OperationFinished(result) => {
                assert!(matches!(result.outcome, OperationOutcome::Failed { .. }));
                assert_eq!(result.completed_rollback, Some(id));
                assert!(
                    result
                        .guard_warning
                        .is_some_and(|message| message.contains("remains armed"))
                );
            }
            other => panic!("expected rollback result, got {other:?}"),
        }
        assert!(
            guard_log.lock().unwrap().disarmed.is_empty(),
            "failed inverse must not cancel its external fallback"
        );
    }

    #[tokio::test]
    async fn plan_applies_every_step_when_all_succeed() {
        let (request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 0, // never fails
        };
        tokio::spawn(run(
            backend,
            TestRollbackGuard,
            test_receivers(request_rx),
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));
        drain_initial_refresh(&mut event_rx).await;

        let plan = vec![FirewallOperation::Reload, FirewallOperation::Reload];
        request_tx
            .send(EngineRequest::ApplyPlan(reviewed_plan(plan)))
            .await
            .unwrap();

        for _ in 0..2 {
            assert!(matches!(
                event_rx.recv().await.unwrap(),
                EngineEvent::OperationFinished(result)
                    if matches!(result.outcome, OperationOutcome::Applied { .. })
            ));
        }
        match event_rx.recv().await.unwrap() {
            EngineEvent::PlanFinished { applied, remaining } => {
                assert_eq!(applied, 2);
                assert!(remaining.is_empty(), "nothing left when the plan succeeds");
            }
            other => panic!("expected PlanFinished, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_is_not_coalesced_away_by_surrounding_refreshes() {
        let (request_tx, request_rx) = mpsc::channel(16);
        let (inputs, manual_tx, _rollback_tx) = test_receiver_lanes(request_rx);
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let backend = CountingBackend {
            apply_calls: AtomicUsize::new(0),
            fail_at: 0,
        };
        tokio::spawn(run(
            backend,
            TestRollbackGuard,
            inputs,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));
        drain_initial_refresh(&mut event_rx).await;

        // A burst with refreshes on both sides of an Apply. Queued refreshes may
        // coalesce into one; the Apply must survive and execute exactly once.
        manual_tx.send(manual_request()).await.unwrap();
        request_tx
            .send(EngineRequest::Apply(reviewed(FirewallOperation::Reload)))
            .await
            .unwrap();
        manual_tx.send(manual_request()).await.unwrap();

        // Bounded drain: a coalescing bug that swallowed the Apply would let this
        // loop finish without ever seeing the outcome.
        let mut applied = 0;
        for _ in 0..16 {
            if let EngineEvent::OperationFinished(result) = event_rx.recv().await.unwrap()
                && matches!(result.outcome, OperationOutcome::Applied { .. })
            {
                applied += 1;
                break;
            }
        }
        assert_eq!(applied, 1, "the Apply must survive refresh coalescing");
    }

    #[tokio::test]
    async fn manual_refresh_request_triggers_refresh() {
        let (_request_tx, request_rx) = mpsc::channel(8);
        let (inputs, manual_tx, _rollback_tx) = test_receiver_lanes(request_rx);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let backend = FakeBackend {
            calls: AtomicUsize::new(0),
            fail: false,
        };
        tokio::spawn(run(
            backend,
            TestRollbackGuard,
            inputs,
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        // initial refresh
        event_rx.recv().await.unwrap();
        event_rx.recv().await.unwrap();

        manual_tx.send(manual_request()).await.unwrap();
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshStarted {
                trigger: RefreshTrigger::Manual,
                ..
            }
        ));
        assert!(matches!(
            event_rx.recv().await.unwrap(),
            EngineEvent::RefreshFinished { result: Ok(_), .. }
        ));
    }

    #[tokio::test]
    async fn performance_budget_large_snapshot_refresh_stays_under_two_seconds() {
        let (_request_tx, request_rx) = mpsc::channel(8);
        let (event_tx, mut event_rx) = mpsc::channel(8);
        let started = std::time::Instant::now();
        tokio::spawn(run(
            LargeBackend,
            TestRollbackGuard,
            test_receivers(request_rx),
            event_tx,
            Duration::from_secs(3600),
            false,
            Duration::from_secs(30),
        ));

        let result = tokio::time::timeout(Duration::from_secs(2), async {
            assert!(matches!(
                event_rx.recv().await.unwrap(),
                EngineEvent::RefreshStarted { .. }
            ));
            event_rx.recv().await.unwrap()
        })
        .await
        .unwrap();

        assert!(matches!(
            result,
            EngineEvent::RefreshFinished {
                result: Ok(snapshot),
                ..
            } if snapshot.zone_names().len() == 100
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
