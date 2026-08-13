# Phase 5C2 Non-Blocking UI Outbox Design

**Status:** Accepted on 2026-08-13 after written review.

## Problem

The engine now exposes separate bounded lanes for normal mutations, manual
refresh demand, and safety rollback. The rollback lane remains observable while
mandatory reconciliation is blocked, even when normal engine capacity is fully
saturated.

The UI can still prevent that priority path from being reached. It executes an
engine-send effect by awaiting channel capacity inside the only terminal event
loop. If a normal send waits while the normal channel and the engine's local
FIFO are both full, the UI stops consuming input and timer ticks. An
in-process-only dead-man rollback can therefore expire without being submitted
to the reserved rollback lane.

## Goals

- Keep terminal input, ticks, engine events, and Ctrl-C responsive while any
  engine lane is backpressured.
- Dispatch rollback before manual and normal outbound work.
- Preserve every confirmed normal mutation in FIFO order and exactly once.
- Preserve manual-refresh coalescing counts without an unbounded UI queue.
- Keep rollback delivery reliable and bounded.
- Preserve the engine as the only backend owner and retain the existing
  capacity-32 normal/manual lanes and capacity-1 rollback lane.
- Make backpressure visible before another mutation is confirmed.

## Non-Goals

- Moving rollback deadlines or rollback ownership into the engine.
- Adding an unbounded queue, detached per-request task, or second backend
  worker.
- Changing mutation, reconciliation, refresh, or rollback semantics already
  accepted by the Phase 5C2 scheduler design.
- Refactoring unrelated file, audit, snapshot, export, or clipboard effects.

## Selected Approach

Add an `EngineOutbox` owned by the UI shell. Enqueuing engine-bound effects is
synchronous and non-blocking. Channel readiness is polled as dedicated branches
of the main Tokio `select!`, alongside input, ticks, engine events, logs, and
Ctrl-C. No engine-bound effect awaits capacity inside `execute_effect`.

The alternatives remain rejected:

1. A dispatcher task would require another lifecycle, shutdown protocol, and
   error channel for state already owned by the UI shell.
2. Moving dead-man deadlines into the engine would be a larger ownership and
   protocol redesign outside this targeted correction.

## Architecture

### EngineOutbox

`EngineOutbox` is UI-shell state, not reducer state and not an application
backend owner. It contains three bounded classes of outbound intent:

- one pending normal `EngineRequest` slot;
- one aggregated manual-refresh demand counter; and
- a capacity-32 FIFO of typed `RollbackRequest` values.

Rollback dispatch has strict priority over manual and normal dispatch. Manual
dispatch has priority over normal dispatch. Priority changes only which lane is
offered capacity first; it never reorders values within a lane.

The normal outbox has capacity one. Once it reaches its limit, the shell emits a pure
UI action that marks mutation submission backpressured. The reducer must not
accept another mutation or plan confirmation while that flag is set. A request
that was already confirmed always has a reserved outbox slot and is never
dropped, replaced, or converted back into an unconfirmed action.

Manual requests are semantically coalescible. The outbox stores one `u64`
aggregate count rather than one allocation per key press, and a typed
manual-lane request carries that count to the engine. The engine adds the batch
to the active lifecycle's exact merged count. Increment is checked; at the
numeric limit a new request is rejected visibly instead of wrapping, silently
losing demand, or allocating memory.

Rollback requests are not coalesced. Both the outbox and the number of
simultaneously armed UI rollbacks are capped at 32. The reducer refuses to
confirm another risky mutation before that safety bound can be exceeded.
Already-armed rollbacks therefore always have outbox capacity when they expire.

### Main event loop

The main `tokio::select!` gains readiness branches for the three outbox lanes.
The ordering is biased only for safety dispatch:

1. Ctrl-C and rollback-lane capacity;
2. engine events and timer/input processing;
3. manual-lane capacity; and
4. normal-lane capacity.

Each send branch reserves one channel slot, removes exactly one corresponding
outbox item only after reservation succeeds, and sends through the permit. A
closed lane produces the existing visible engine-gone outcome; it does not
silently discard the pending item.

The loop continues polling ticks and input whenever a sender has no capacity.
An expired in-process rollback can therefore be enqueued and offered to the
capacity-1 safety lane even while a previously confirmed normal mutation is
waiting for normal capacity.

### Reducer boundary

The reducer remains pure. Shell capacity changes enter through explicit UI
actions. State exposes whether normal mutation submission is backpressured and
whether the armed-rollback safety limit has been reached.

Confirmation acceptance checks those flags. If submission is temporarily
unavailable, the confirmation remains open and the operator receives a clear
busy message; no `Effect::Apply` or `Effect::ApplyPlan` is emitted. Once the
outbox drains below its limit, a follow-up action clears backpressure.

Manual refresh remains available during normal backpressure. Rollback actions
always remain available while their fixed safety bound is respected.

## Data Flow

### Saturated normal send followed by rollback

1. The engine's local normal FIFO and normal channel are saturated.
2. One already-confirmed normal request waits in the bounded UI outbox.
3. The main loop continues consuming ticks instead of awaiting normal capacity.
4. The dead-man deadline expires and the reducer emits a rollback effect.
5. The shell enqueues the rollback and the next safety-priority reservation
   sends it through the rollback lane.
6. The engine drops the blocked reconciliation, applies rollback exactly once,
   completes fresh reconciliation, then resumes the original normal FIFO.
7. The waiting normal request remains queued and is sent exactly once when
   normal capacity returns.

### Manual burst under backpressure

1. Manual key presses increment the outbox's bounded aggregate.
2. The UI loop remains responsive and continues processing engine events.
3. One manual-lane reservation sends the aggregate count.
4. The engine records the full count and preserves the existing one-trailing
   lifecycle rule.

## Error Handling and Shutdown

- A closed engine lane leaves the pending intent available long enough to
  surface the existing engine-gone error; no send is reported as successful.
- Engine-event closure still clears active lifecycle state through
  `EngineStopped`.
- Clean quit keeps its bounded rollback-drain contract. It first moves armed
  rollbacks into the priority outbox, then waits up to the existing deadline for
  their operation results.
- Ctrl-C remains an emergency exit and is never gated behind normal outbox
  capacity.
- No engine send path uses `try_send` as a lossy fallback.

## Test Design

Add deterministic paused-time UI-shell tests that prove:

- with the engine local FIFO and normal channel each saturated at 32 and a
  mandatory snapshot blocked, a further confirmed normal request waits in the
  UI outbox without blocking Tick processing;
- an armed rollback with `watchdog_unit: None` expires and reaches the rollback
  lane before the snapshot is released or normal capacity returns;
- the blocked snapshot drops before rollback application;
- the rollback executes exactly once and fresh reconciliation completes;
- the waiting normal request is retained, later delivered exactly once, and
  remains FIFO behind earlier normal work;
- manual demand remains available during normal backpressure and its aggregate
  count reaches the scheduler exactly;
- reaching the normal outbox or armed-rollback bound prevents a new
  confirmation before an effect is emitted;
- lane closure produces a visible error without losing an already-confirmed
  request silently; and
- clean exit still dispatches armed rollbacks through the priority path.

Run focused UI/reducer/engine tests first, followed by formatting, both Clippy
feature configurations, the full all-features suite, release performance,
coverage gates, and the disposable three-distribution real-firewalld matrix
before publication.

## Acceptance Criteria

- No engine-bound effect awaits channel capacity inside the UI worklist.
- UI ticks and input remain live under normal-channel saturation.
- Safety rollback reaches its reserved lane without waiting for normal
  capacity.
- Confirmed normal work is bounded, FIFO, reliable, and exactly once.
- Manual demand is bounded and count-preserving.
- No unbounded queue, detached send task, backend concurrency, or host-firewall
  access is introduced.
