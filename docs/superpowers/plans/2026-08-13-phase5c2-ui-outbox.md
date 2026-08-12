# Phase 5C2 Non-Blocking UI Outbox Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep the TUI responsive under engine backpressure so an in-process dead-man rollback always reaches its reserved priority lane without losing confirmed normal work or manual demand.

**Architecture:** Add a bounded `EngineOutbox` owned by the UI shell and poll its three lane reservations from the main Tokio `select!`. Normal submission uses one pending slot, manual demand is count-aggregated, and rollback uses a capacity-32 UI FIFO before the existing capacity-1 engine lane. Pure reducer state exposes backpressure and reserves rollback capacity before accepting risky confirmations.

**Tech Stack:** Rust 1.88, Tokio bounded MPSC and paused-time tests, ratatui TEA reducer, existing fake firewall backend and drop guards, cargo-llvm-cov, Docker Compose real-firewalld matrix.

## Global Constraints

- The engine remains the only backend owner; no second worker or shared backend mutex.
- Normal engine channel capacity stays 32, manual engine channel capacity stays 32, rollback engine channel capacity stays 1, and engine event capacity stays 64.
- UI normal outbox capacity is exactly 1; UI rollback outbox and combined armed/reserved/pending rollback capacity are exactly 32.
- Manual demand uses one checked `u64` aggregate and must retain its exact count.
- Rollback dispatch priority is strict; normal requests remain FIFO and exactly once.
- No engine-bound effect may await channel capacity inside the UI effect worklist.
- No unbounded queue, detached per-request task, lossy `try_send`, production `unwrap`/`expect`/`panic!`, shell interpolation, or host-firewall test.
- Cancellation remains distinct from backend failure and stale snapshot/error behavior stays unchanged.

---

## File Responsibility Map

- `src/application/api.rs`: typed batched manual demand and existing bounded engine lanes.
- `src/application/refresh_scheduler.rs`: count-preserving manual-demand transition.
- `src/application/engine.rs`: consume one batched manual request without changing snapshot/mutation serialization.
- `src/ui/outbox.rs`: pure bounded outbox storage and priority-independent queue operations.
- `src/ui/action.rs`: reducer actions that reflect shell outbox capacity.
- `src/ui/state.rs`: normal backpressure plus rollback reservation/pending counts.
- `src/ui/update/mod.rs`: confirmation gates and reservation lifecycle.
- `src/ui/update/lifecycle.rs`: release reservations when operation/plan results arrive.
- `src/ui/mod.rs`: enqueue engine effects synchronously and poll send permits in the main event loop.
- `docs/superpowers/specs/2026-08-13-phase5c2-ui-outbox-design.md`: accepted behavior.
- `docs/superpowers/plans/2026-08-09-phase5c2-refresh-scheduler.md`: Phase 5C2 execution state and outbox amendment link.

---

## Task 1: Add count-preserving manual demand and a pure bounded outbox

**Files:**

- Modify: `src/application/api.rs`
- Modify: `src/application/mod.rs`
- Modify: `src/application/refresh_scheduler.rs`
- Modify: `src/application/engine.rs`
- Create: `src/ui/outbox.rs`
- Modify: `src/ui/mod.rs`

**Interfaces:**

- Produces: `ManualRefreshRequest::new(count: NonZeroU64) -> Self` and `count(self) -> NonZeroU64`.
- Produces: `RefreshScheduler::record_manual_batch(count: NonZeroU64) -> Result<RefreshDemand, ManualDemandOverflow>`.
- Produces: `EngineEvent::ManualDemandRejected { count: NonZeroU64 }` when a
  batch cannot be represented without corrupting lifecycle metadata.
- Produces: `EngineOutbox::{enqueue_normal, add_manual, enqueue_rollback, take_normal, take_manual, take_rollback}`.
- Bounds: one normal slot, one `u64` manual counter, 32 rollback slots.

- [ ] **Step 1: Add failing scheduler and engine tests for batched manual demand.**

Add tests that exercise a batch rather than looping over individual `()` values:

```rust
#[test]
fn manual_batch_preserves_exact_count() {
    let mut scheduler = RefreshScheduler::new();
    let start = scheduler.start(RefreshTrigger::Manual).unwrap();
    assert_eq!(
        scheduler.record_manual_batch(NonZeroU64::new(7).unwrap()),
        Ok(RefreshDemand::Trailing),
    );
    let completion = scheduler.complete(start.id).unwrap();
    assert_eq!(completion.schedule.merged_manual_requests, 7);
}

#[tokio::test]
async fn batched_manual_request_reaches_lifecycle_metadata_exactly() {
    // Send ManualRefreshRequest::new(7), complete the active read, and assert
    // the single trailing lifecycle reports merged_manual_requests == 7.
}
```

- [ ] **Step 2: Run the RED tests.**

```bash
rtk cargo test --locked application::refresh_scheduler::tests::manual_batch_preserves_exact_count -- --exact
rtk cargo test --locked application::engine::tests::batched_manual_request_reaches_lifecycle_metadata_exactly -- --exact
```

Expected: compile failure because `ManualRefreshRequest` and
`record_manual_batch` do not exist.

- [ ] **Step 3: Introduce the typed manual request and count transition.**

Use a non-zero count so an empty batch cannot enter the engine:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManualRefreshRequest(NonZeroU64);

impl ManualRefreshRequest {
    pub const fn new(count: NonZeroU64) -> Self { Self(count) }
    pub const fn count(self) -> NonZeroU64 { self.0 }
}
```

Change `EngineHandle.manual_refreshes` and `EngineReceivers.manual_refreshes`
to the typed request. Replace each one-at-a-time scheduler call with:

```rust
let demand = scheduler.record_manual_batch(request.count());
```

The pure transition must use checked addition and return
`ManualDemandOverflow` before state mutation; it must never wrap or partially
add. The engine maps this practically unreachable error to one visible
engine-event error and keeps the existing active lifecycle valid.

- [ ] **Step 4: Add RED tests for `EngineOutbox` bounds and ordering.**

Create `src/ui/outbox.rs` with tests first:

```rust
#[test]
fn normal_slot_never_drops_or_reorders_confirmed_work() {
    let mut outbox = EngineOutbox::new();
    let first = normal_request("http");
    let second = normal_request("https");
    assert!(outbox.enqueue_normal(first.clone()).is_ok());
    assert_eq!(outbox.enqueue_normal(second.clone()), Err(NormalEnqueueError::Full(second)));
    assert_eq!(outbox.take_normal(), Some(first));
}

#[test]
fn manual_demand_aggregates_exactly_and_rejects_overflow() {
    let mut outbox = EngineOutbox::new();
    outbox.add_manual(NonZeroU64::new(u64::MAX).unwrap()).unwrap();
    assert_eq!(outbox.add_manual(NonZeroU64::MIN), Err(ManualEnqueueError::CountOverflow));
    assert_eq!(outbox.take_manual().map(ManualRefreshRequest::count), NonZeroU64::new(u64::MAX));
}

#[test]
fn rollback_fifo_is_bounded_at_thirty_two() {
    let mut outbox = EngineOutbox::new();
    for id in 1..=32 {
        outbox.enqueue_rollback(rollback_request(id)).unwrap();
    }
    let overflow = rollback_request(33);
    assert_eq!(outbox.enqueue_rollback(overflow.clone()), Err(RollbackEnqueueError::Full(overflow)));
    assert_eq!(outbox.take_rollback(), Some(rollback_request(1)));
}
```

Define `normal_request` and `rollback_request` as test-only constructors using
the existing valid zone/service fixtures; they must not bypass domain
validation. Their signatures are
`fn normal_request(service: &str) -> EngineRequest` and
`fn rollback_request(id: u64) -> RollbackRequest`.

- [ ] **Step 5: Implement the minimal pure outbox.**

Use explicit result types that return rejected values to the caller:

```rust
pub(super) const ROLLBACK_OUTBOX_CAPACITY: usize = 32;

pub(super) struct EngineOutbox {
    normal: Option<EngineRequest>,
    manual_count: u64,
    rollbacks: VecDeque<RollbackRequest>,
}

pub(super) enum NormalEnqueueError { Full(EngineRequest) }
pub(super) enum ManualEnqueueError { CountOverflow }
pub(super) enum RollbackEnqueueError { Full(RollbackRequest) }
```

Queue methods perform no I/O and never mutate on error. `take_*` removes work
only after the caller has obtained the matching MPSC permit.

- [ ] **Step 6: Run focused GREEN gates.**

```bash
rtk cargo test --locked application::refresh_scheduler::tests
rtk cargo test --locked application::engine::tests::batched_manual_request_reaches_lifecycle_metadata_exactly -- --exact
rtk cargo test --locked ui::outbox::tests
rtk cargo clippy --locked --lib -- -D warnings
rtk cargo fmt --all -- --check
```

- [ ] **Step 7: Commit Task 1.**

```bash
rtk git add src/application/api.rs src/application/mod.rs src/application/refresh_scheduler.rs src/application/engine.rs src/ui/outbox.rs src/ui/mod.rs
rtk git commit -m "feat(ui): add bounded engine outbox protocol"
```

## Task 2: Gate confirmations and reserve rollback capacity in the pure reducer

**Files:**

- Modify: `src/ui/action.rs`
- Modify: `src/ui/state.rs`
- Modify: `src/ui/update/mod.rs`
- Modify: `src/ui/update/lifecycle.rs`

**Interfaces:**

- Consumes: `ROLLBACK_OUTBOX_CAPACITY = 32` from `ui::outbox`.
- Produces: `UiAction::EngineOutboxChanged { normal_pending: bool, rollback_pending: usize }`.
- Produces: `UiAction::ManualDemandRejected { count: NonZeroU64 }`, mapped from
  either local aggregate overflow or the engine overflow event.
- Produces state fields `engine_normal_backpressured: bool`, `rollback_outbox_pending: usize`, and `rollback_reservations: usize`.
- Invariant: `pending_rollback.len() + rollback_outbox_pending + rollback_reservations <= 32`.

- [ ] **Step 1: Add failing reducer tests.**

Add exact tests:

```rust
#[test]
fn normal_backpressure_keeps_confirmation_open_without_emitting_effect() {
    let mut state = state_with_confirmed_remove_service();
    state.engine_normal_backpressured = true;
    let overlay_count = state.overlays.len();
    assert!(update(&mut state, UiAction::ConfirmAccept).is_empty());
    assert_eq!(state.overlays.len(), overlay_count);
}

#[test]
fn risky_confirmation_is_refused_before_rollback_capacity_can_overflow() {
    let mut state = state_with_confirmed_connectivity_change();
    state.rollback_outbox_pending = 10;
    state.rollback_reservations = 10;
    state.pending_rollback = pending_rollbacks(12);
    assert!(update(&mut state, UiAction::ConfirmAccept).is_empty());
    assert_eq!(state.rollback_reservations, 10);
}

#[test]
fn operation_outcome_converts_one_reservation_to_armed_or_releases_it() {
    let mut state = state();
    state.rollback_reservations = 1;
    update(&mut state, applied_risky_result_with_registration());
    assert_eq!(state.rollback_reservations, 0);
    assert_eq!(state.pending_rollback.len(), 1);
}

#[test]
fn halted_plan_releases_reservations_for_unexecuted_risky_operations() {
    let mut state = state();
    state.rollback_reservations = 2;
    update(&mut state, UiAction::PlanFinished { applied: 0, remaining: two_risky_operations() });
    assert_eq!(state.rollback_reservations, 0);
}
```

The named test helpers construct real validated operations and the existing
`OperationResult`; they do not introduce production shortcuts. Use these exact
test-only signatures:

```rust
fn state_with_confirmed_remove_service() -> UiState;
fn state_with_confirmed_connectivity_change() -> UiState;
fn pending_rollbacks(count: usize) -> Vec<PendingRollback>;
fn applied_risky_result_with_registration() -> UiAction;
fn two_risky_operations() -> Vec<FirewallOperation>;
```

- [ ] **Step 2: Run RED.**

```bash
rtk cargo test --locked ui::update::tests::normal_backpressure_keeps_confirmation_open_without_emitting_effect -- --exact
rtk cargo test --locked ui::update::tests::risky_confirmation_is_refused_before_rollback_capacity_can_overflow -- --exact
rtk cargo test --locked ui::update::tests::operation_outcome_converts_one_reservation_to_armed_or_releases_it -- --exact
rtk cargo test --locked ui::update::tests::halted_plan_releases_reservations_for_unexecuted_risky_operations -- --exact
```

Expected: missing action/state fields and current confirmation dispatches.

- [ ] **Step 3: Implement explicit backpressure state.**

Initialize all fields to zero/false. Apply shell state only through:

```rust
UiAction::EngineOutboxChanged { normal_pending, rollback_pending } => {
    state.engine_normal_backpressured = normal_pending;
    state.rollback_outbox_pending = rollback_pending;
}

UiAction::ManualDemandRejected { count } => {
    state.toast(
        ToastKind::Error,
        format!("manual refresh demand limit reached — {count} request(s) not queued"),
    );
}
```

Before popping a mutation/plan confirmation, calculate whether it needs one or
more rollback reservations using `rollback_ticks != 0`,
`operation.connectivity_warning().is_some()`, and plan contents. If normal
backpressure is active or the exact combined rollback bound would exceed 32,
leave the overlay open, emit no engine effect, and show one bounded warning
toast. Otherwise increment reservations before emitting the effect.

- [ ] **Step 4: Release or convert reservations exactly once.**

Every `OperationFinished` consumes one reservation associated with a risky
submitted operation. A successful outcome with `RollbackRegistration` converts
it to `pending_rollback`; failure or no registration releases it. A halted plan
uses `remaining` to release reservations for risky operations never executed.
Use checked arithmetic and treat invariant violation as a visible internal
error, not a production panic.

- [ ] **Step 5: Run reducer GREEN and regression tests.**

```bash
rtk cargo test --locked ui::update::tests
rtk cargo clippy --locked --lib -- -D warnings
rtk cargo fmt --all -- --check
```

- [ ] **Step 6: Commit Task 2.**

```bash
rtk git add src/ui/action.rs src/ui/state.rs src/ui/update/mod.rs src/ui/update/lifecycle.rs
rtk git commit -m "fix(ui): gate mutations on bounded outbox capacity"
```

## Task 3: Poll engine sends without blocking the TUI loop

**Files:**

- Modify: `src/ui/mod.rs`
- Modify: `src/ui/outbox.rs`
- Test: `src/ui/mod.rs`

**Interfaces:**

- Consumes: `EngineOutbox` and `EngineHandle` typed senders.
- Produces: main-loop send branches ordered rollback, manual, normal.
- Produces: synchronous `enqueue_engine_effect(outbox: &mut EngineOutbox, effect: Effect) -> Result<EngineEffectDisposition, OutboxEnqueueError>`; `EngineEffectDisposition::Queued` means the effect was engine-bound and fully handled by the outbox, while `NotEngineBound(Effect)` returns other effects unchanged.

- [ ] **Step 1: Add the end-to-end RED regression.**

Build a paused-time UI-shell harness with the real bounded channels and fake
engine driver. The test must:

```rust
#[tokio::test(start_paused = true)]
async fn tick_dispatches_rollback_while_normal_outbox_waits_on_full_engine() {
    // Fill engine local normal FIFO with 32 and normal channel with 32.
    // Block mandatory snapshot with watchdog_unit: None.
    // Confirm one more normal request; assert it enters the one-slot UI outbox.
    // Advance the UI rollback deadline.
    // Assert rollback reaches priority lane before snapshot release/capacity.
    // Assert drop-before-rollback, exactly once, fresh reconciliation, then
    // all earlier normal work plus waiting normal request execute FIFO once.
}
```

Also add focused tests for manual aggregation under normal backpressure, closed
lane visibility, and clean-exit rollback delivery.

- [ ] **Step 2: Run RED.**

```bash
rtk cargo test --locked ui::tests::tick_dispatches_rollback_while_normal_outbox_waits_on_full_engine -- --exact
rtk cargo test --locked ui::tests::manual_batch_dispatches_during_normal_backpressure -- --exact
rtk cargo test --locked ui::tests::closed_outbox_lane_surfaces_engine_stopped_without_silent_loss -- --exact
```

Expected: the first test times out because `execute_effect(...).await` owns the
loop; the other tests fail because outbox dispatch is not integrated.

- [ ] **Step 3: Enqueue engine effects synchronously.**

Before `execute_effect`, route `Effect::Apply`, `Effect::ApplyPlan`,
`Effect::Refresh`, and `Effect::ApplyRollback` into `EngineOutbox`. Remove their
awaiting send arms. After every enqueue/dequeue transition, push one
`EngineOutboxChanged` action when observable capacity state changes.

- [ ] **Step 4: Poll one prioritized dispatch future from the main `tokio::select!`.**

`EngineOutbox::dispatch_one` borrows only the three sender fields and its own
queue state. Its internal select is biased rollback, manual, normal. Poll that
single future as one fair branch of the outer event loop, so continuous input,
ticks, logs, or events cannot starve sends and a blocked send cannot starve UI
work:

```rust
let action = tokio::select! {
    _ = &mut ctrl_c => Some(UiAction::QuitConfirmed),
    dispatch = outbox.dispatch_one(
        &engine.rollbacks,
        &engine.manual_refreshes,
        &engine.requests,
    ), if !outbox.is_empty() => Some(dispatch.into_ui_action()),
    event = engine.events.recv(), if engine_alive => if let Some(event) = event {
        Some(engine_event_action(event))
    } else {
        engine_alive = false;
        Some(UiAction::EngineStopped(FirewallError::Process(
            "engine task stopped unexpectedly".to_owned(),
        )))
    },
    _ = tick.tick() => Some(UiAction::Tick),
    maybe_event = events.next() => match maybe_event {
        Some(Ok(Event::Key(key))) => keymap::translate(&state, key),
        Some(Ok(Event::Resize(width, height))) => Some(UiAction::Resize(width, height)),
        Some(Ok(_)) => None,
        Some(Err(err)) => return Err(AppError::Terminal(err)),
        None => Some(UiAction::QuitConfirmed),
    },
    received = logs.recv_many(&mut log_batch, 64), if logs_alive => {
        if received == 0 {
            logs_alive = false;
            None
        } else {
            Some(UiAction::LogsReceived(std::mem::take(&mut log_batch)))
        }
    }
};
```

Do not remove an outbox item until `reserve()` returns `Ok(permit)`. On channel
closure, keep enough identity to show the existing engine-gone error and stop
retrying the closed lane without a busy loop.

- [ ] **Step 5: Preserve bounded clean shutdown.**

Change `drain_rollbacks_on_exit` to enqueue all armed rollbacks into the bounded
priority outbox, dispatch one permit at a time while draining engine events,
and retain the existing five-second deadline. Normal/manual pending work may be
abandoned on confirmed quit; rollback work may not be silently abandoned.

- [ ] **Step 6: Run GREEN and affected regressions.**

```bash
rtk cargo test --locked ui::tests
rtk cargo test --locked ui::update::tests
rtk cargo test --locked application::engine::tests
rtk cargo test --locked application::refresh_scheduler::tests
rtk cargo test --locked --test backend
rtk cargo clippy --locked --all-targets -- -D warnings
rtk cargo fmt --all -- --check
```

- [ ] **Step 7: Commit Task 3.**

```bash
rtk git add src/ui/mod.rs src/ui/outbox.rs
rtk git commit -m "fix(ui): keep rollback ticks live under backpressure"
```

## Task 4: Synchronize documentation and run complete validation

**Files:**

- Modify: `docs/superpowers/plans/2026-08-09-phase5c2-refresh-scheduler.md`
- Modify only failure-causing files from Tasks 1-3 if a validation gate exposes a genuine regression.

**Interfaces:**

- Consumes: the accepted outbox behavior and all green focused tests.
- Produces: final validation evidence and publication-ready Phase 5C2 branch.

- [ ] **Step 1: Update the parent plan narrative and checkboxes.**

Link the accepted outbox spec and record exact UI bounds `normal=1`,
`manual=u64 aggregate`, `rollback=32`. Mark only completed outbox steps. Leave
ShellCheck unchecked if the binary is still unavailable and leave every Task 9
publication checkbox unchecked until its action succeeds.

- [ ] **Step 2: Run formatting and both lint configurations.**

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy --locked --all-targets -- -D warnings
rtk cargo clippy --locked --all-targets --features dbus -- -D warnings
```

- [ ] **Step 3: Run full behavior and performance suites.**

```bash
rtk cargo test --locked --all-features
rtk cargo test --locked --release performance_budget -- --test-threads=1
```

- [ ] **Step 4: Enforce overall and critical coverage.**

```bash
rtk cargo llvm-cov --locked --all-features --fail-under-lines 75 --json --summary-only --output-path target/coverage-summary.json
rtk proxy ./scripts/check-critical-coverage.sh target/coverage-summary.json
```

- [ ] **Step 5: Run the real firewalld matrix only in disposable containers.**

```bash
rtk docker compose -p fwdeck -f docker-compose.yml run --rm -v /Users/daniz/.cargo/registry:/root/.cargo/registry dev cargo test --offline --locked --features dbus --test real_firewalld -- --ignored --test-threads=1
rtk docker compose -p fwdeck -f docker-compose.yml run --rm -v /Users/daniz/.cargo/registry:/root/.cargo/registry dev-debian cargo test --offline --locked --features dbus --test real_firewalld -- --ignored --test-threads=1
rtk docker compose -p fwdeck -f docker-compose.yml run --rm -v /Users/daniz/.cargo/registry:/root/.cargo/registry dev-el9 cargo test --offline --locked --features dbus --test real_firewalld -- --ignored --test-threads=1
```

- [ ] **Step 6: Audit the final branch.**

```bash
rtk git diff --check develop...HEAD
rtk git status --short --branch
rtk git diff --cached --name-status
rtk git ls-files --others --exclude-standard
```

Confirm no coverage artifact, container target, `.agents`, `.forge`, `.idea`,
or `skills-lock.json` is tracked or staged.

- [ ] **Step 7: Commit only genuine documentation or validation changes.**

```bash
rtk git add docs/superpowers/plans/2026-08-09-phase5c2-refresh-scheduler.md
rtk git commit -m "docs(ui): record non-blocking outbox guarantees"
```

Do not create an empty validation commit. After this task, request one focused
whole-range review before any push, PR, or merge.
