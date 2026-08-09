# Phase 5C2 Refresh Scheduler Design

**Status:** Proposed for written review. The runtime behavior was approved in
conversation on 2026-08-09; implementation begins only after this committed
specification is reviewed.

## Problem

FWDeck already refreshes immediately at startup, periodically on a configured
interval, manually on operator request, and after every engine mutation. The
engine owns the backend serially and coalesces refresh requests that are already
waiting in its bounded channel. However, an in-progress snapshot currently
blocks the engine until it completes. A slow refresh therefore delays a
confirmed mutation or rollback, and the existing tests do not measure
cancellation, trailing manual refreshes, or refresh bursts under load.

The current Tokio interval is also fixed-rate. When a snapshot lasts longer
than the configured interval, an already-due tick can produce an immediate
follow-up refresh. That behavior can sustain load precisely when firewalld is
already responding slowly.

## Goals

- Keep exactly one snapshot read active at a time.
- Let a confirmed mutation or rollback cancel an ordinary in-progress refresh,
  execute with priority, and then complete one mandatory post-mutation refresh.
- Merge any number of manual requests received during an ordinary active
  refresh into exactly one trailing manual refresh.
- Drop periodic demand while a refresh is active instead of building a backlog.
- Use fixed-delay periodic scheduling, measured from the end of a completed
  refresh attempt, so slow reads cannot cause back-to-back polling.
- Preserve FIFO ordering and reliable delivery for mutations and rollbacks.
- Measure refresh triggers, cancellations, and coalescing with typed lifecycle
  metadata and structured tracing.
- Preserve stale snapshot behavior, honest backend errors, bounded channels,
  and the engine's single ownership of the backend.

## Non-goals

- Concurrent snapshot reads or concurrent read/mutation access to a backend.
- Cancellation, reordering, or coalescing of a mutation, mutation plan, or
  rollback request.
- Changing the snapshot schema, backend fetch algorithms, heavy-section cache,
  refresh interval configuration, or default interval.
- Selected-zone priority or lazy service/policy detail loading; those remain a
  separate Phase 5C slice.
- A new UI dashboard, user-facing cancellation toast, or Doctor output for the
  TUI scheduler. Doctor invokes a backend directly and has no scheduler.
- Touching or testing against the developer host firewall.

## Selected Approach

Implement an explicit scheduler state machine inside the existing engine task.
The state machine decides what should start, trail, coalesce, or cancel; the
engine remains responsible for channels, timers, backend futures, mutations,
and ordered event delivery.

This approach preserves structural serialization and does not require sharing
the backend behind `Arc`, a mutex, or a second worker task. An ordinary refresh
future is polled together with engine requests. Returning from that polling
scope drops the future before the engine executes a preempting mutation.

Two alternatives were rejected:

1. A separate refresh task with an abort handle would make cancellation direct,
   but would require shared backend ownership and a second serialization
   mechanism to prevent reads from racing mutations.
2. Queue-only coalescing would be simpler, but a confirmed mutation would still
   wait for a slow snapshot and would not satisfy the approved latency policy.

## Architecture

### Pure scheduling policy

Add `application::refresh_scheduler` as a small, pure policy module. It owns no
backend, Tokio channel, timer, or task. It tracks:

- the monotonically increasing refresh identity;
- the trigger of the active refresh;
- whether the active refresh is preemptible;
- whether one trailing manual refresh is pending; and
- the number of manual and periodic demands merged into the active lifecycle.

The scheduler accepts lifecycle inputs and returns explicit decisions such as
start, queue one trailing manual refresh, coalesce, cancel for mutation, or wait.
This boundary makes request policy deterministic and independently testable
without wall-clock sleeps.

Refresh triggers are application-layer values:

- `Initial` for the first snapshot;
- `Periodic` for configured background refresh;
- `Manual` for an operator request; and
- `PostMutation` for the required reconciliation after an engine request that
  may have changed or invalidated observed state.

`Initial`, `Periodic`, and `Manual` refreshes are preemptible. A
`PostMutation` refresh is mandatory and non-preemptible: later mutations remain
FIFO-queued until it completes. Without this exception, a burst of mutations
could repeatedly cancel reconciliation and violate the guarantee that every
mutation is followed by one complete fresh snapshot.

### Engine ownership

`application::engine` continues to be the only backend owner. It starts the
initial refresh immediately, polls ordinary refresh futures alongside incoming
requests, and drops an ordinary future before executing a preempting request.
The engine never polls a snapshot and a mutation future concurrently.

Rename the UI-originated `EngineRequest::Refresh` variant to
`EngineRequest::ManualRefresh`. Periodic demand remains internal to the engine.
All other engine requests retain FIFO order and are never discarded.

The engine maintains a small local FIFO for requests it has already removed
from the bounded receiver. Immediately before a post-mutation refresh it may
drain currently available requests into that FIFO. Manual requests already
present are absorbed by the newer post-mutation snapshot; mutation and rollback
requests are retained in their original order. Manual requests arriving after
the post-mutation snapshot starts follow the normal rule and produce one
trailing manual refresh.

### Fixed-delay timer

The initial refresh starts without waiting for a timer. A periodic deadline is
armed only after a refresh attempt finishes. Completion includes both success
and a reported backend failure. Manual and post-mutation refresh completion
also reset the deadline.

No periodic interval accumulates ticks while a snapshot is active. Any timer
readiness race resolved after another refresh starts is treated as coalesced
periodic demand. `MissedTickBehavior` is no longer the primary load-control
mechanism because scheduling is based on one explicit next deadline.

## Data Flow

### Ordinary refresh completion

1. The scheduler allocates an identity and trigger.
2. The engine emits `RefreshStarted` and begins one snapshot future.
3. Manual requests set one trailing-manual flag; further manual requests merge
   into it. Periodic demand is coalesced.
4. The snapshot completes and the engine emits `RefreshFinished` with the same
   identity, trigger, backend result, existing `RefreshObservation`, and
   scheduling metadata.
5. A pending trailing manual refresh starts immediately. Otherwise the next
   periodic deadline is armed.

### Mutation preemption

1. A mutation, plan, or rollback arrives during an ordinary refresh.
2. The engine drops the snapshot future and emits `RefreshCancelled` with its
   identity, trigger, elapsed duration, cancellation reason, and accumulated
   coalescing counts.
3. Only after the future is dropped does the engine execute the request.
4. Existing operation or plan events are emitted unchanged.
5. Manual demand already queued before the post-mutation read is absorbed, and
   one mandatory `PostMutation` refresh runs to completion.
6. Later mutations wait in FIFO order until that mandatory refresh completes.

Every engine request that currently receives a post-request refresh keeps that
behavior, including validation failure, read-only rejection, partial outcome,
indeterminate outcome, or rollback failure. The daemon may have changed before
reporting the outcome, so reconciliation remains mandatory.

## Cancellation Contract

Document on `FirewallBackend::snapshot_observed` that dropping its returned
future must be cancellation-safe: it must not mutate firewall state, detach
unbounded work, or leave a child process running.

The production CLI and offline paths satisfy the process boundary through
`TokioRunner` and `kill_on_drop(true)`. Dropping an in-flight command future
therefore terminates its child. The native D-Bus adapter performs read-only
method calls in the dropped snapshot future and does not spawn detached work.
Test backends use a drop guard to prove the engine releases the active read
before beginning a mutation.

No mutation future is ever dropped for scheduler preemption.

## Events and UI State

Extend refresh lifecycle events with a refresh identity and trigger. Add a
distinct `RefreshCancelled` event rather than reporting cancellation as a
`FirewallError`.

The UI tracks the active refresh identity instead of a bare boolean. A finish
or cancellation only changes lifecycle state when its identity matches the
active refresh. This is defensive against future event-source changes even
though the current bounded channel preserves order.

A cancellation:

- clears only the matching active lifecycle;
- does not replace the last completed refresh observation;
- does not set `backend_error`;
- does not discard the last good snapshot; and
- does not show a warning or error toast.

The following post-mutation `RefreshStarted` event restores the spinner while
reconciliation runs. Existing success and failure reconciliation in the pure
reducer remains unchanged.

Manual refresh effects use the reliable request-send path that drains engine
events while waiting for bounded-channel capacity. The current best-effort
`try_send` is insufficient because a full queue does not prove that a manual
refresh newer than the active snapshot will occur. Periodic demand never uses
the request channel.

## Observability

Scheduling metadata belongs in `application::api`, not in the domain snapshot
or backend `RefreshObservation`. It includes refresh identity, trigger, merged
manual demand, and coalesced periodic demand. A cancellation additionally
records elapsed time and `MutationPreempted` as its typed reason.

The engine writes one structured tracing record when a refresh finishes or is
cancelled. Burst requests are aggregated into the lifecycle record instead of
emitting one log line per key press or timer race.

The existing UI header continues to show latency and subprocess count from the
last completed backend observation. Scheduling counters remain available to
tests and logs without adding permanent header noise.

## Error Handling and Backpressure

- Backend failures still emit `RefreshFinished`, retain stale data, and expose
  the categorized error to the operator.
- Cancellation is a scheduler outcome, never a backend failure.
- A closed event channel stops the engine cleanly, as it does today.
- Mutation, plan, and rollback requests continue using reliable bounded sends.
- Manual refresh switches to the same deadlock-safe reserving send; engine
  events are drained while the UI waits for capacity.
- The scheduler stores only booleans, counters, one active lifecycle, and a
  bounded-channel-derived local FIFO. It cannot create an unbounded queue.
- If the engine stops while the UI is waiting to send, the existing visible
  engine-gone handling remains in effect.

## Test Design

### Pure scheduler tests

Cover every state transition without Tokio time:

- initial refresh starts immediately;
- one manual request during an active refresh creates one trailing refresh;
- a burst of 100 manual requests still creates exactly one trailing refresh;
- periodic demand during an active refresh creates no trailing work;
- a mutation cancels each ordinary trigger;
- a post-mutation refresh refuses cancellation and leaves the mutation queued;
- manual demand queued before post-mutation refresh is absorbed;
- manual demand received after post-mutation refresh starts creates one trailing
  refresh; and
- counters and refresh identities remain monotonic and lifecycle-scoped.

### Async engine tests

Use Tokio's paused clock plus a cancellation-aware fake backend controlled by
barriers and a future drop guard. Assert that:

- at most one snapshot is active;
- the active snapshot is dropped before `apply` begins;
- event ordering is cancel, operation outcome, post-mutation start, and
  post-mutation finish;
- mutations and rollbacks retain FIFO order and execute exactly once;
- a mandatory post-mutation refresh cannot be starved by queued mutations;
- a slow snapshot does not create an immediate periodic refresh storm;
- a manual burst has a bounded snapshot-call count; and
- receiver or event-channel closure terminates without leaked work.

One load regression combines a blocked snapshot, 100 manual demands, periodic
deadline advancement, and a mutation. It proves bounded snapshot calls, maximum
snapshot concurrency of one, mutation progress without releasing the blocked
read, and exactly one complete post-mutation reconciliation.

### Existing gates

Run formatting, default and D-Bus Clippy, all-features tests, the deterministic
release performance budget, overall coverage, and critical-path coverage. Add
the pure scheduler file to the critical coverage checker at a 95% line floor;
the existing engine floor remains at 90%.

Run the serialized real-firewalld suite in disposable Fedora 44, Debian 13,
and AlmaLinux 9 containers. These tests verify compatibility and lifecycle
regression only; cancellation load behavior remains deterministic in fake
backend tests. The host firewall is never accessed.

## Documentation

Update the operator configuration documentation to define
`refresh_interval_ms` as a fixed delay after the previous refresh attempt, not
a fixed-rate polling promise. Document that manual refreshes are reliable and
coalesced, while confirmed changes take priority over ordinary background
reads.

No new configuration key, migration, snapshot format, or CLI flag is required.

## Acceptance Criteria

- Exactly one backend snapshot is active at any time.
- A confirmed mutation or rollback cancels an ordinary blocked refresh and
  begins only after the refresh future has been dropped.
- Every engine mutation request is followed by one complete, non-preemptible
  post-mutation refresh before the next mutation executes.
- Manual bursts during an active refresh produce exactly one trailing manual
  refresh; periodic demand produces none.
- A slow refresh cannot generate an immediate fixed-rate refresh loop.
- Refresh cancellation never becomes a backend error, toast, or loss of stale
  snapshot data.
- Mutation and rollback requests remain reliable, FIFO, and exactly-once at the
  engine boundary.
- Scheduling lifecycle records expose trigger, identity, elapsed cancellation
  time, and aggregate coalescing counts.
- The scheduler reaches at least 95% line coverage and engine coverage remains
  at least 90%.
- All local gates and the three-distribution real-firewalld matrix pass without
  touching the host firewall.
