# Phase 5C2 Refresh Scheduler Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make ordinary refreshes cancellable by confirmed mutations, keep manual and periodic demand bounded and coalesced, and guarantee one complete reconciliation after every mutation.

**Architecture:** Add a pure application-layer scheduler that owns refresh policy and typed lifecycle metadata while the existing engine remains the single owner of backend I/O. The engine polls one ordinary snapshot alongside requests, drops that read before a preempting mutation, runs post-mutation refreshes non-preemptibly, and schedules periodic work with a fixed delay after completion. The UI tracks refresh identity and preserves stale data across cancellation or failure.

**Tech Stack:** Rust 1.88, Tokio bounded MPSC/time/test-util, ratatui pure reducer, tracing, cargo-llvm-cov, Bash/jq, Docker Compose real-firewalld matrix.

---

## Guardrails

- Never run a real-firewalld test on the host; use only the disposable Compose services.
- Never cancel, reorder, coalesce, or concurrently poll a mutation, plan, or rollback future.
- Keep exactly one backend snapshot future active and drop it before starting a preempting mutation.
- Treat `PostMutation` refresh as mandatory and non-preemptible.
- Preserve stale snapshots and categorized backend errors; cancellation is not an error.
- Keep request/event channels bounded and cap any local FIFO at the request-channel capacity.
- Do not change backend fetch algorithms, snapshot schema, refresh configuration, selected-zone behavior, or lazy details in this slice.
- Do not use `unwrap`, `expect`, `panic!`, or shell interpolation in production code.

## File Responsibility Map

- `src/application/api.rs`: public engine protocol, refresh identity, trigger, cancellation reason, and lifecycle observations.
- `src/application/refresh_scheduler.rs`: pure refresh state machine; no Tokio, backend, channels, or I/O.
- `src/application/engine.rs`: fixed-delay timer, one active backend future, request serialization, cancellation, and tracing.
- `src/application/ports.rs`: cancellation-safety contract for backend snapshot futures.
- `src/ui/action.rs`: lifecycle actions crossing from engine events into the reducer.
- `src/ui/state.rs`: active refresh identity and last completed observation.
- `src/ui/update/mod.rs`: identity-aware, cancellation-safe reducer behavior.
- `src/ui/mod.rs`: event mapping and reliable manual-refresh delivery.
- `src/ui/components.rs`: spinner derived from active refresh identity.
- `Cargo.toml`: Tokio test-time control for deterministic scheduler tests.
- `scripts/check-critical-coverage.sh`: independent 95% line floor for the scheduler.
- `site/docs/index.html`: operator-facing fixed-delay and priority semantics.

## Task 1: Define typed refresh lifecycle metadata

**Files:**

- Modify: `src/application/api.rs:80-145`
- Modify: `src/application/mod.rs:5-14`
- Test: `src/application/api.rs`

- [x] **Step 1: Write the failing value-contract test.**

Add a test module at the end of `api.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_schedule_observation_preserves_identity_trigger_and_counts() {
        let observation = RefreshScheduleObservation {
            id: RefreshId::new(7),
            trigger: RefreshTrigger::Manual,
            merged_manual_requests: 4,
            coalesced_periodic_ticks: 3,
        };

        assert_eq!(observation.id.get(), 7);
        assert_eq!(observation.trigger, RefreshTrigger::Manual);
        assert_eq!(observation.merged_manual_requests, 4);
        assert_eq!(observation.coalesced_periodic_ticks, 3);
        assert!(RefreshTrigger::Initial.is_preemptible());
        assert!(!RefreshTrigger::PostMutation.is_preemptible());
    }
}
```

- [x] **Step 2: Run RED.**

Run:

```bash
rtk cargo test --locked application::api::tests
```

Expected: compilation fails because the refresh lifecycle types do not exist.

- [x] **Step 3: Add the minimal application-layer types.**

Add above `EngineRequest`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefreshId(u64);

impl RefreshId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshTrigger {
    Initial,
    Periodic,
    Manual,
    PostMutation,
}

impl RefreshTrigger {
    #[must_use]
    pub const fn is_preemptible(self) -> bool {
        !matches!(self, Self::PostMutation)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshScheduleObservation {
    pub id: RefreshId,
    pub trigger: RefreshTrigger,
    pub merged_manual_requests: u64,
    pub coalesced_periodic_ticks: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshCancellationReason {
    MutationPreempted,
}
```

Re-export all four types from `application::mod` beside the existing engine API types. Keep them in the application layer; do not add them to `domain::observation`.

- [x] **Step 4: Run GREEN and lint the touched target.**

```bash
rtk cargo test --locked application::api::tests
rtk cargo clippy --locked --lib -- -D warnings
```

Expected: the new unit test passes and Clippy reports no warnings.

- [x] **Step 5: Commit.**

```bash
rtk git add src/application/api.rs src/application/mod.rs
rtk git commit -m "feat(refresh): define scheduler lifecycle metadata"
```

## Task 2: Build the pure refresh scheduler with TDD

**Files:**

- Create: `src/application/refresh_scheduler.rs`
- Modify: `src/application/mod.rs:1-8`

- [x] **Step 1: Create the scheduler test module first.**

Cover these exact transitions:

```rust
#[cfg(test)]
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
    fn absorbed_manual_demand_does_not_create_a_trailing_refresh() {
        let mut scheduler = RefreshScheduler::new();
        let post = scheduler.start(RefreshTrigger::PostMutation).unwrap();
        scheduler.absorb_manual();
        let finished = scheduler.finish(post.id).unwrap();
        assert!(!finished.trailing_manual);
        assert_eq!(finished.schedule.merged_manual_requests, 1);
    }
}
```

Also add focused tests for idle `StartNow`, mismatched finish identity, monotonic IDs, and attempting to start while active.

- [x] **Step 2: Run RED.**

```bash
rtk cargo test --locked application::refresh_scheduler::tests
```

Expected: compilation fails because the module and scheduler types do not exist.

- [x] **Step 3: Implement only the pure state machine.**

Use this complete pure implementation, followed by the tests from Step 1:

```rust
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
```

Rules:

- `start` returns `None` while another lifecycle is active.
- IDs begin at 1 and advance with `wrapping_add(1).max(1)`; no panic path is introduced.
- The first active manual demand returns `Trailing`; later ones return `Coalesced`.
- `absorb_manual` increments the active manual counter without setting the trailing flag.
- Periodic demand while active only increments its counter.
- `cancel_for_mutation` takes only a preemptible active lifecycle and clears its trailing flag.
- `finish` ignores a mismatched ID without changing state.

- [x] **Step 4: Run GREEN, format, and lint.**

```bash
rtk cargo test --locked application::refresh_scheduler::tests
rtk cargo fmt --all -- --check
rtk cargo clippy --locked --lib -- -D warnings
```

- [x] **Step 5: Commit.**

```bash
rtk git add src/application/mod.rs src/application/refresh_scheduler.rs
rtk git commit -m "feat(refresh): add pure scheduling policy"
```

## Task 3: Integrate cancellable refresh lifecycles into the engine

**Files:**

- Modify: `Cargo.toml:115-117`
- Modify: `src/application/api.rs:90-145`
- Modify: `src/application/engine.rs:1-125,533-565,574-820,1538-1645`
- Modify: `src/ui/action.rs:205-225`
- Modify: `src/ui/mod.rs:90-175`
- Modify: `src/ui/update/mod.rs:575-635`

- [x] **Step 1: Add deterministic engine tests and a cancellation-aware fake backend.**

Add Tokio's test-only clock support without adding it to release builds:

```toml
[dev-dependencies]
tokio = { version = "1", features = ["test-util"] }
```

Create a fake whose snapshot holds an RAII guard across a semaphore wait. The
guard decrements `active_snapshots` on drop; `apply` records whether it observed
zero active snapshots. Add tests named
`mutation_drops_ordinary_refresh_before_apply`,
`manual_burst_produces_one_trailing_refresh`, and the paused-clock
`periodic_refresh_uses_fixed_delay_after_completion`.

The mutation test must observe this order:

```rust
assert!(matches!(event_rx.recv().await.unwrap(), EngineEvent::RefreshCancelled {
    reason: RefreshCancellationReason::MutationPreempted,
    ..
}));
assert!(matches!(event_rx.recv().await.unwrap(), EngineEvent::OperationFinished(_)));
assert!(matches!(event_rx.recv().await.unwrap(), EngineEvent::RefreshStarted {
    trigger: RefreshTrigger::PostMutation,
    ..
}));
```

It must also assert `active_snapshots == 0` when `apply` begins and `max_active_snapshots == 1`.

- [x] **Step 2: Run RED.**

```bash
rtk cargo test --locked application::engine::tests::mutation_drops_ordinary_refresh_before_apply
rtk cargo test --locked application::engine::tests::manual_burst_produces_one_trailing_refresh
rtk cargo test --locked application::engine::tests::periodic_refresh_uses_fixed_delay_after_completion
```

Expected: compilation fails because lifecycle events and the cancellable driver do not exist.

- [x] **Step 3: Extend the engine protocol.**

Rename `EngineRequest::Refresh` to `EngineRequest::ManualRefresh`. Replace the two refresh event variants with:

```rust
RefreshStarted {
    id: RefreshId,
    trigger: RefreshTrigger,
},
RefreshFinished {
    schedule: RefreshScheduleObservation,
    result: Result<Arc<FirewallSnapshot>, FirewallError>,
    observation: RefreshObservation,
},
RefreshCancelled {
    schedule: RefreshScheduleObservation,
    reason: RefreshCancellationReason,
    elapsed: Duration,
},
```

Temporarily map the new fields through `UiAction`; the reducer may still use a boolean until Task 5, but cancellation must clear it without setting an error or replacing `last_refresh`.

- [x] **Step 4: Replace the fixed-rate `run` loop with an explicit driver.**

Introduce private outcomes with no backend types exposed through the public API:

```rust
enum OrdinaryRefreshOutcome {
    Completed(SnapshotRead),
    Preempted {
        request: EngineRequest,
        schedule: RefreshScheduleObservation,
        elapsed: Duration,
    },
    RequestsClosed,
}
```

Implement these helpers:

```rust
async fn drive_ordinary_refresh<B: FirewallBackend>(
    backend: &B,
    requests: &mut mpsc::Receiver<EngineRequest>,
    scheduler: &mut RefreshScheduler,
    start: RefreshStart,
) -> OrdinaryRefreshOutcome;

async fn drive_mandatory_refresh<B: FirewallBackend>(
    backend: &B,
    scheduler: &mut RefreshScheduler,
    start: RefreshStart,
) -> Option<(SnapshotRead, RefreshCompletion)>;

async fn send_refresh_started(
    events: &mpsc::Sender<EngineEvent>,
    start: RefreshStart,
) -> Result<(), ()>;

async fn send_refresh_finished(
    events: &mpsc::Sender<EngineEvent>,
    completion: RefreshCompletion,
    read: SnapshotRead,
) -> Result<(), ()>;
```

`drive_ordinary_refresh` pins exactly one `snapshot_observed` future and selects between it and `requests.recv()`:

- manual request: call `record_manual` and keep polling the same future;
- mutation/plan/rollback: call `cancel_for_mutation`, return `Preempted`, and let the pinned future drop when the helper returns;
- closed receiver: return `RequestsClosed` so the future drops and the engine exits;
- completed read: call `finish` and return the same backend result and observation.

The outer loop must not call `execute_request` until `drive_ordinary_refresh` has returned. After a preemption, emit `RefreshCancelled`, execute the exact returned request, then start one `PostMutation` refresh. Await mandatory refresh directly without selecting the request channel.

Replace `tokio::time::interval` with one resettable `tokio::time::Sleep`. Arm it for `now + refresh_interval` only after the final completed refresh in a lifecycle. A trailing manual refresh starts immediately and delays timer arming until it completes.
Use `tokio::time::Instant` for cancellation elapsed time so paused-clock tests
remain deterministic; keep backend `RefreshObservation` timing unchanged.

- [x] **Step 5: Preserve existing event semantics and update call sites.**

Update all engine tests to match structured variants. Keep `RefreshObservation`
from the same `SnapshotRead` and keep the existing refresh success/failure logs
compiling with the structured event fields. Emit the cancellation event here;
Task 6 adds the final aggregate tracing records after behavior is green.

- [x] **Step 6: Run GREEN and the complete engine target.**

```bash
rtk cargo test --locked application::engine::tests
rtk cargo test --locked ui::update::tests::refresh
rtk cargo clippy --locked --lib -- -D warnings
```

Expected: all engine tests pass; no mutation begins before the snapshot drop guard runs.

- [x] **Step 7: Commit.**

```bash
rtk git add Cargo.toml Cargo.lock src/application/api.rs src/application/engine.rs src/ui/action.rs src/ui/mod.rs src/ui/update/mod.rs
rtk git commit -m "feat(refresh): preempt ordinary reads for mutations"
```

If `Cargo.lock` is byte-identical after adding the dev feature, do not stage it.

## Task 4: Prove mandatory reconciliation, FIFO safety, and bounded load

**Files:**

- Modify: `src/application/api.rs:135-175`
- Modify: `src/application/engine.rs:33-170,574-900,1538-1700`

- [x] **Step 1: Add the failing mandatory-refresh and load tests.**

Add the exact scenarios
`queued_mutation_cannot_cancel_post_mutation_refresh`,
`mutations_and_rollbacks_remain_fifo_and_exactly_once`, and the paused-clock
`blocked_refresh_manual_burst_timer_advance_and_mutation_stay_bounded`.

The load test sequence is:

1. release and drain the initial refresh;
2. start and block one manual refresh;
3. send 100 manual demands while draining lifecycle events so the bounded request channel cannot deadlock the test;
4. advance virtual time by ten refresh intervals;
5. send one reviewed mutation;
6. assert cancellation occurs without releasing the blocked snapshot;
7. assert the mutation executes exactly once with no active snapshot;
8. release exactly one mandatory post-mutation snapshot; and
9. assert snapshot calls are bounded, maximum concurrency is one, and no immediate periodic start appears.

- [x] **Step 2: Run RED.**

```bash
rtk cargo test --locked application::engine::tests::queued_mutation_cannot_cancel_post_mutation_refresh
rtk cargo test --locked application::engine::tests::mutations_and_rollbacks_remain_fifo_and_exactly_once
rtk cargo test --locked application::engine::tests::blocked_refresh_manual_burst_timer_advance_and_mutation_stay_bounded
```

Expected: at least the mandatory/FIFO assertions fail until queued-request handling is explicit.

- [x] **Step 3: Add one bounded pending-request FIFO.**

Define the channel capacities once in `api.rs`:

```rust
pub(crate) const REQUEST_CAPACITY: usize = 32;
const EVENT_CAPACITY: usize = 64;
```

Use them in `spawn`. The engine local FIFO must never exceed `REQUEST_CAPACITY`.

Immediately after executing a preempting request:

1. start the `PostMutation` scheduler lifecycle;
2. while the local FIFO has capacity, drain immediately available channel requests;
3. call `scheduler.absorb_manual()` for each observed `ManualRefresh`;
4. retain every mutation/plan/rollback in arrival order; and
5. await the mandatory snapshot without polling the receiver.

After the mandatory refresh completes, consume the local FIFO before receiving newer channel items. If the local FIFO is full, stop draining; never create a second queue or grow it beyond 32. A manual request not yet observed remains in the bounded channel and may legitimately become one later trailing refresh.

- [x] **Step 4: Make the mandatory boundary explicit.**

`drive_mandatory_refresh` must not accept a request receiver. Its signature is the proof that no later request can cancel a post-mutation snapshot. Add a comment at the call site explaining that later mutations wait because each engine mutation needs one complete observed-state reconciliation.

- [x] **Step 5: Run GREEN and regression tests.**

```bash
rtk cargo test --locked application::engine::tests
rtk cargo test --locked --release performance_budget -- --test-threads=1
```

Expected: the new load/FIFO tests pass and the large snapshot budget remains below two seconds.

- [x] **Step 6: Commit.**

```bash
rtk git add src/application/api.rs src/application/engine.rs
rtk git commit -m "fix(refresh): guarantee bounded post-mutation reconciliation"
```

## Task 5: Make UI lifecycle handling identity-aware and manual delivery reliable

**Files:**

- Modify: `src/ui/action.rs:205-230`
- Modify: `src/ui/state.rs:125-165,215-245`
- Modify: `src/ui/update/mod.rs:575-640,1350-1420`
- Modify: `src/ui/mod.rs:90-230,505-590`
- Modify: `src/ui/components.rs:220-235`

- [x] **Step 1: Add failing reducer and delivery tests.**

Add reducer tests named
`stale_refresh_completion_cannot_replace_newer_lifecycle`,
`matching_cancellation_clears_spinner_without_error_or_snapshot_loss`, and
`mismatched_cancellation_does_not_clear_active_refresh`.

The matching-cancellation test seeds `snapshot`, `last_refresh`, and `backend_error`, starts ID 9, cancels ID 9, and asserts only active lifecycle state changes. Cancellation must not clear or overwrite those three values.

In `ui::mod` add an async test with a capacity-one request channel. Fill the channel, begin the manual refresh effect, drain the first request, and assert the waiting effect reliably sends `EngineRequest::ManualRefresh` rather than returning early.

- [x] **Step 2: Run RED.**

```bash
rtk cargo test --locked ui::update::tests::stale_refresh_completion_cannot_replace_newer_lifecycle
rtk cargo test --locked ui::update::tests::matching_cancellation_clears_spinner_without_error_or_snapshot_loss
rtk cargo test --locked ui::tests::manual_refresh_waits_for_bounded_channel_capacity
```

- [x] **Step 3: Replace the boolean with refresh identity.**

In `UiState` replace:

```rust
pub refreshing: bool,
```

with:

```rust
pub active_refresh: Option<crate::application::RefreshId>,
```

Initialize it to `None`; render the spinner with `state.active_refresh.is_some()`.

Make UI lifecycle actions carry the same ID and trigger as engine events. Add `RefreshCancelled` and a separate `EngineStopped(FirewallError)` action so an event-channel failure remains visible even when no refresh ID is active.

Reducer rules:

```rust
UiAction::RefreshStarted { id, .. } => state.active_refresh = Some(id),
UiAction::RefreshCancelled { id, .. } => {
    if state.active_refresh == Some(id) {
        state.active_refresh = None;
    }
}
UiAction::RefreshCompleted { id, result, observation, .. } => {
    if state.active_refresh != Some(id) {
        return Vec::new();
    }
    state.active_refresh = None;
    state.last_refresh = Some(observation);
    // Preserve the existing success/error reconciliation unchanged.
}
UiAction::EngineStopped(error) => {
    state.active_refresh = None;
    state.backend_error = Some(error);
}
```

- [x] **Step 4: Use the reliable send path for manual refresh.**

Replace the `try_send` arm with:

```rust
Effect::Refresh => {
    if !send_request(engine, pending, EngineRequest::ManualRefresh).await {
        state.toast(state::ToastKind::Error, "engine is gone — refresh not sent");
    }
}
```

Keep `send_request`'s event-draining `reserve` loop unchanged. Do not add an unbounded channel or block without draining events.

- [x] **Step 5: Run GREEN and UI regression targets.**

```bash
rtk cargo test --locked ui::update::tests
rtk cargo test --locked ui::tests
rtk cargo clippy --locked --lib -- -D warnings
```

- [x] **Step 6: Commit.**

```bash
rtk git add src/ui/action.rs src/ui/state.rs src/ui/update/mod.rs src/ui/mod.rs src/ui/components.rs
rtk git commit -m "fix(ui): track refresh lifecycles by identity"
```

## Task 6: Complete scheduler observability and backend cancellation contract

**Files:**

- Modify: `src/application/engine.rs:500-620`
- Modify: `src/application/ports.rs:215-240`
- Test: `src/application/engine.rs`

- [x] **Step 1: Strengthen lifecycle metadata assertions.**

Extend engine tests to assert that:

- a completed manual burst reports trigger `Manual` and the exact merged count;
- a cancelled refresh reports its original trigger, non-zero elapsed time when virtual time advanced, and `MutationPreempted`;
- the post-mutation completion reports trigger `PostMutation`; and
- cancellation produces no `RefreshFinished` for the cancelled ID.

- [x] **Step 2: Run RED against exact metadata.**

```bash
rtk cargo test --locked application::engine::tests::manual_burst_produces_one_trailing_refresh
rtk cargo test --locked application::engine::tests::mutation_drops_ordinary_refresh_before_apply
```

Expected: any missing trigger, count, elapsed, or event-order field fails explicitly.

- [x] **Step 3: Emit one aggregate lifecycle record.**

For completion, include `refresh_id`, `trigger`, `merged_manual_requests`, `coalesced_periodic_ticks`, backend elapsed milliseconds, process count, and success/failure. For cancellation, emit the aggregate debug record from Task 3. Do not log each coalesced key press or timer race.

- [x] **Step 4: Document the port-level cancellation requirement.**

Extend `snapshot_observed` documentation with this exact contract:

```rust
/// The returned future must be cancellation-safe: dropping it must not mutate
/// firewall state, detach unbounded work, or leave a child process running.
/// The engine may drop ordinary refreshes before a confirmed mutation.
```

Do not change `snapshot_fresh` or `apply`; mutation preflight and mutation futures are never scheduler-cancelled.

- [x] **Step 5: Run GREEN plus process/backend regressions.**

```bash
rtk cargo test --locked application::engine::tests
rtk cargo test --locked infrastructure::process::tests
rtk cargo test --locked --test backend
```

- [x] **Step 6: Commit.**

```bash
rtk git add src/application/engine.rs src/application/ports.rs
rtk git commit -m "feat(observability): report refresh scheduling outcomes"
```

## Task 7: Enforce scheduler coverage and document operator semantics

**Files:**

- Modify: `scripts/check-critical-coverage.sh:35-45`
- Modify: `site/docs/index.html:726-740`

- [x] **Step 1: Generate the current coverage report before changing the floor.**

```bash
rtk cargo llvm-cov --locked --all-features --json --summary-only --output-path target/coverage-summary.json
rtk proxy ./scripts/check-critical-coverage.sh target/coverage-summary.json
```

Expected: existing overall and critical floors pass; scheduler coverage is present in the JSON but is not yet independently enforced.

- [x] **Step 2: Add the scheduler threshold.**

Append beside the engine check:

```bash
check_file "/src/application/refresh_scheduler.rs" 95 "refresh scheduler"
```

Do not lower the existing engine, rollback, snapshot-store, D-Bus, or overall thresholds.

- [x] **Step 3: Verify the new threshold against the real report.**

```bash
rtk proxy ./scripts/check-critical-coverage.sh target/coverage-summary.json
```

Expected output includes `refresh scheduler line coverage` at or above 95%. If it is below 95%, add behavior-focused pure scheduler tests and regenerate the report; do not lower the floor or exclude lines.

- [x] **Step 4: Document fixed-delay and priority behavior.**

Immediately below the configuration example, add this exact operator text:

```html
<p><code>refresh_interval_ms</code> is a fixed delay after the previous refresh
attempt completes. Manual refresh requests are reliable and coalesced. A
confirmed change or rollback takes priority over an ordinary background read;
FWDeck then completes a fresh reconciliation before accepting the next change.</p>
```

Do not add a new configuration key or imply that mutations themselves can be cancelled.

- [ ] **Step 5: Validate the script and static site.**

```bash
rtk bash -n scripts/check-critical-coverage.sh
rtk shellcheck scripts/check-critical-coverage.sh
rtk rg -n "fixed delay after the previous refresh|Manual refresh requests are reliable" site/docs/index.html
```

Expected: both phrases appear in the configuration section. The site is plain HTML with no build step; do not run `preview-site.sh` because it opens a browser.

- [x] **Step 6: Commit.**

```bash
rtk git add scripts/check-critical-coverage.sh site/docs/index.html
rtk git commit -m "docs(refresh): document bounded scheduler behavior"
```

## Task 8: Run complete local and real-daemon validation

**Files:**

- Modify only files required to fix failures caused by Tasks 1-7.

- [x] **Step 1: Run formatting and both lint configurations.**

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy --locked --all-targets -- -D warnings
rtk cargo clippy --locked --all-targets --features dbus -- -D warnings
```

- [x] **Step 2: Run complete tests and deterministic performance budget.**

```bash
rtk cargo test --locked --all-features
rtk cargo test --locked --release performance_budget -- --test-threads=1
```

- [x] **Step 3: Enforce overall and critical coverage.**

```bash
rtk cargo llvm-cov --locked --all-features --fail-under-lines 75 --json --summary-only --output-path target/coverage-summary.json
rtk proxy ./scripts/check-critical-coverage.sh target/coverage-summary.json
```

- [x] **Step 4: Run the real firewalld matrix only in disposable containers.**

```bash
rtk docker compose -f docker-compose.yml run --rm dev cargo test --offline --locked --features dbus --test real_firewalld -- --ignored --test-threads=1
rtk docker compose -f docker-compose.yml run --rm dev-debian cargo test --offline --locked --features dbus --test real_firewalld -- --ignored --test-threads=1
rtk docker compose -f docker-compose.yml run --rm dev-el9 cargo test --offline --locked --features dbus --test real_firewalld -- --ignored --test-threads=1
```

Expected: every distribution passes serially. Never substitute a host invocation.

- [x] **Step 5: Inspect the final diff and run targeted impact checks.**

```bash
rtk git diff --check develop...HEAD
rtk git status --short --branch
```

Confirm no unrelated file, generated coverage report, container target, `.agents`, `.forge`, `.idea`, or `skills-lock.json` is staged.

- [x] **Step 6: Commit only genuine validation fixes.**

If validation required code changes:

```bash
rtk git add Cargo.toml Cargo.lock src/application/api.rs src/application/engine.rs src/application/mod.rs src/application/ports.rs src/application/refresh_scheduler.rs src/ui/action.rs src/ui/components.rs src/ui/mod.rs src/ui/state.rs src/ui/update/mod.rs scripts/check-critical-coverage.sh site/docs/index.html
rtk git commit -m "fix(refresh): resolve scheduler validation findings"
```

If all gates pass without changes, do not create an empty commit.

## Task 9: Publish through the protected integration path

**Files:** None.

- [ ] **Step 1: Push the feature branch.**

```bash
rtk git push -u origin feat/phase5c2-refresh-scheduler
```

- [ ] **Step 2: Open a PR to `develop`.**

Use a concise title such as `feat(refresh): add cancellable refresh scheduler`. The body must summarize ordinary-refresh preemption, mandatory post-mutation reconciliation, fixed-delay scheduling, bounded manual coalescing, test evidence, coverage, and the three-distribution matrix.

- [ ] **Step 3: Wait for every required check and resolve review threads.**

Do not bypass the solo-safe ruleset, force-push reviewed history, or merge with a failing/pending required check.

- [ ] **Step 4: Merge through the PR and verify `develop`.**

After merge, verify the exact merge commit on `origin/develop`, confirm the post-merge CI run is green, then fast-forward the local `develop`. Keep local, pushed, merged, and released states distinct in the status report.
