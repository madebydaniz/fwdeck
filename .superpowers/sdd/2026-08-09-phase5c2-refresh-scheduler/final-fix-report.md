# Phase 5C2 Final Fix Report

## Scope and revision

- Final review fix wave for `feat/phase5c2-refresh-scheduler`, starting from
  `99b1d61c646ebbed0136aa5d682ad76c712e2e83`.
- Production changes are limited to the application refresh protocol, scheduler,
  and engine. Documentation changes synchronize the accepted design and plan.
- The engine remains the sole backend owner. The existing request-channel and
  local pending-request bounds remain 32.
- No backend, process, UI production, lockfile, workflow, or container file was
  changed. No host firewall command was run.

## Finding resolution

### 1. Rollback safety priority during mandatory reconciliation

- Added `RefreshCancellationReason::RollbackPreempted` and an explicit pure
  scheduler transition for cancelling an active `PostMutation` lifecycle.
- The mandatory driver now polls the snapshot together with requests, event
  closure, request closure, and the one-shot periodic deadline. Normal requests
  are retained in the existing bounded FIFO; manual demand is coalesced.
- A rollback observed during mandatory reconciliation cancels and drops the
  snapshot future before rollback execution, overtakes queued normal work,
  executes exactly once, and starts a fresh mandatory reconciliation.
- `Apply` and `ApplyPlan` remain FIFO and cannot preempt mandatory
  reconciliation.
- `rollback_preempts_blocked_post_mutation_refresh_and_preserves_normal_fifo`
  uses `watchdog_unit: None` and proves drop-before-rollback, rollback exactly
  once, normal plan/apply FIFO preservation, and successful fresh
  reconciliation.
- `normal_requests_remain_fifo_while_rollback_overtakes_exactly_once` covers the
  same ordering contract after requests have already entered the local queue.

### 2. Manual burst at the post-mutation boundary

- The completion boundary drains the already-observable request batch before
  finishing `PostMutation`, merging queued manual requests into one lifecycle
  count.
- Exactly one trailing `Manual` lifecycle is emitted for that batch. Requests
  not yet observable may form later demand.
- `manual_burst_after_post_mutation_start_is_one_trailing_lifecycle` verifies
  the exact merged count and bounded lifecycle count.
- `trailing_manual_survives_queued_mutation_reconciliation` additionally proves
  that a trailing manual trigger is not lost when queued normal work requires
  another mandatory reconciliation.

### 3. Active-lifecycle periodic metadata

- Replaced production-dead timer accounting with a single explicit
  `PeriodicDeadline`. While a lifecycle is active, at most one due deadline is
  observed and recorded as `coalesced_periodic_ticks = 1`.
- The deadline does not create an interval, backlog, catch-up refresh, or storm.
  Fixed delay is reset only after the final lifecycle in a sequence completes.
- Paused-clock tests
  `due_periodic_deadline_is_recorded_on_refresh_completion` and
  `due_periodic_deadline_is_recorded_on_refresh_cancellation` verify honest
  completion and cancellation metadata.
- `trailing_manual_survives_queued_mutation_reconciliation` verifies that the
  next periodic lifecycle starts one full delay after final completion.

### 4. Prompt shutdown of in-flight reads

- Ordinary and mandatory snapshot drivers now select against
  `events.closed()` and request-channel closure.
- Closure returns a shutdown outcome, drops the in-flight snapshot/child, and
  exits without converting cancellation into a backend error or cancellation
  event.
- Drop-guard regressions:
  `ordinary_event_channel_closure_drops_blocked_snapshot`,
  `mandatory_request_channel_closure_drops_snapshot_without_cancellation`, and
  `mandatory_event_channel_closure_drops_blocked_snapshot`.

### 5. Execution-plan state

- Marked completed Task 1-8 steps `[x]`.
- Task 7 Step 5 remains `[ ]` because ShellCheck is unavailable; the report does
  not claim a ShellCheck pass.
- Every Task 9 publication step remains `[ ]`.

### 6. Scoped recommendations

- Ordinary preemption coverage now includes all three triggers:
  `mutation_drops_ordinary_refresh_before_apply` (`Initial`),
  `mutation_preempts_periodic_refresh` (`Periodic`), and
  `blocked_refresh_manual_burst_timer_advance_and_mutation_stay_bounded`
  (`Manual`).
- A new real `TokioRunner` child-liveness test was not added. No process source
  changed, and a portable deterministic proof would require OS-specific PID
  probing beyond this engine/scheduler fix. Existing production
  `kill_on_drop(true)` behavior and all four process regressions remain green.

## TDD evidence

Tests were added before production behavior. The focused RED runs failed with
exit code 101 as expected:

```text
rtk cargo test --locked application::engine::tests::rollback_preempts_blocked_post_mutation_refresh_and_preserves_normal_fifo -- --exact
  timed out: the mandatory snapshot await starved rollback

rtk cargo test --locked application::engine::tests::manual_burst_after_post_mutation_start_is_one_trailing_lifecycle -- --exact
  failed: the merged manual count did not include the boundary batch

rtk cargo test --locked application::engine::tests::due_periodic_deadline_is_recorded_on_refresh_completion -- --exact
rtk cargo test --locked application::engine::tests::due_periodic_deadline_is_recorded_on_refresh_cancellation -- --exact
  failed: coalesced periodic count was 0 instead of 1

rtk cargo test --locked application::engine::tests::ordinary_event_channel_closure_drops_blocked_snapshot -- --exact
rtk cargo test --locked application::engine::tests::mandatory_request_channel_closure_drops_snapshot_without_cancellation -- --exact
rtk cargo test --locked application::engine::tests::mandatory_event_channel_closure_drops_blocked_snapshot -- --exact
  timed out: the blocked snapshot was not dropped on closure

rtk cargo test --locked application::refresh_scheduler::tests::safety_rollback_cancels_post_mutation_refresh -- --exact
  failed to compile: `cancel_for_rollback` did not exist

rtk cargo test --locked application::engine::tests::trailing_manual_survives_queued_mutation_reconciliation -- --exact
  first failed by timeout from a lost trailing trigger, then failed because an
  intermediate fixed-delay reset started periodic work too early
```

The corresponding focused GREEN runs passed. Final focused regression totals:

```text
rtk cargo test --locked application::refresh_scheduler::tests
  10 passed; 0 failed

rtk cargo test --locked application::engine::tests
  36 passed; 0 failed

rtk cargo test --locked infrastructure::process::tests
  4 passed; 0 failed

rtk cargo test --locked ui::update::tests
  102 passed; 0 failed

rtk cargo test --locked ui::tests
  3 passed; 0 failed

rtk cargo test --locked --test backend
  16 passed; 0 failed
```

## Final validation

All final code gates were rerun after the last production change and passed
with exit code 0:

```text
rtk cargo fmt --all -- --check

rtk cargo clippy --locked --all-targets -- -D warnings

rtk cargo clippy --locked --all-targets --features dbus -- -D warnings

rtk cargo test --locked --all-features
  446 passed; 14 ignored; 0 failed (6 suites)

rtk cargo test --locked --release performance_budget -- --test-threads=1
  2 passed; 445 filtered out; 0 failed

rtk cargo llvm-cov --locked --all-features --fail-under-lines 75 --json \
  --summary-only --output-path target/coverage-summary.json
  446 exercised tests: 417 unit, 16 backend, 13 CLI
  14 real-firewalld tests ignored
  overall lines: 16,397 / 20,899 = 78.45829944016461%

rtk proxy ./scripts/check-critical-coverage.sh target/coverage-summary.json
  engine: 92.84% (minimum 90.00%)
  refresh scheduler: 100.00% (minimum 95.00%)
  systemd rollback guard: 91.95% (minimum 85.00%)
  snapshot store: 84.92% (minimum 80.00%)
```

Documentation checks retained the following evidence:

```text
rtk bash -n scripts/check-critical-coverage.sh
  exit 0

rtk rg -n "fixed delay after the previous refresh|Manual refresh requests are reliable" site/docs/index.html
  both phrases found

rtk shellcheck scripts/check-critical-coverage.sh
  exit 127
  [rtk: No such file or directory (os error 2)]
```

The three-distribution real-firewalld matrix was not rerun in this final fix
wave, as explicitly allowed when changes do not reach backend/process code. The
prior Task 8 report records passing Fedora 44, Debian 13, and AlmaLinux 9 runs.

## Changed files

- `src/application/api.rs`
- `src/application/engine.rs`
- `src/application/refresh_scheduler.rs`
- `docs/superpowers/specs/2026-08-09-phase5c2-refresh-scheduler-design.md`
- `docs/superpowers/plans/2026-08-09-phase5c2-refresh-scheduler.md`
- `.superpowers/sdd/2026-08-09-phase5c2-refresh-scheduler/final-fix-report.md`

## Self-review and residual concerns

- Snapshot and mutation futures are never polled concurrently; driver outcomes
  ensure the snapshot future is out of scope before rollback or mutation work.
- Normal mutations and plans remain exactly once and FIFO. Only rollback has the
  documented safety-priority exception.
- Cancellation metadata uses the active lifecycle identity and accumulated
  counts; shutdown emits neither a false backend failure nor a false operator
  cancellation.
- No production `unwrap`, `expect`, or `panic!` was added.
- The generated coverage JSON remains ignored and is not part of the change.
- ShellCheck remains unavailable. Task 7 Step 5 therefore remains unresolved.
- No publication action was taken; all Task 9 steps remain open.
