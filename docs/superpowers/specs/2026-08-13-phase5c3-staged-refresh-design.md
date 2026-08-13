# Phase 5C3 Staged Refresh and Lazy Detail Design

**Status:** Accepted on 2026-08-13 after written review.

## Problem

The CLI backend does not publish a snapshot until status, zones, IP sets,
direct rules, every policy detail, and every referenced service definition have
finished loading. Per-object service and policy calls use bounded fan-out, but
large installations still delay the first useful zone view behind unrelated
detail work. The UI's selected zone is also local state, so the backend cannot
prioritize data the operator is currently viewing.

Making `FirewallSnapshot` partially populated would be unsafe. Missing details
would be indistinguishable from healthy empty data in validation, dependency
analysis, saved snapshots, and exports. Phase 5C3 therefore needs a fast preview
without weakening the authoritative snapshot contract or the Phase 5C2
mutation and rollback guarantees.

## Goals

- Publish a useful status and zone overview before unrelated service and
  policy detail calls finish.
- Prioritize details referenced by the selected or default zone, followed by
  the currently selected service or policy, before remaining detail work.
- Keep one backend owner and one active refresh lifecycle.
- Preserve ordinary-refresh mutation preemption, rollback priority, mandatory
  post-mutation reconciliation, fixed-delay scheduling, and bounded channels.
- Keep `FirewallSnapshot` authoritative: complete or explicitly degraded,
  never implicitly partial.
- Reprioritize detail work that has not started when UI selection changes,
  without cancelling an active subprocess or creating a cancellation storm.
- Retain exact refresh observations and add deterministic measurements for
  time-to-overview and time-to-full-snapshot.

## Non-goals

- Concurrent reads and mutations against a backend.
- A second backend worker or detached detail-fetch task.
- Changing snapshot serialization or accepting partially hydrated saved
  snapshots.
- Fetching zone details one command at a time when the existing firewalld
  aggregate zone command is already cheaper and fixture-tested.
- Optimizing D-Bus in the first implementation. Non-CLI backends use the
  existing complete-snapshot fallback and remain behaviorally correct.
- Changing cache invalidation or mutation target semantics.

## Selected Approach

Use a two-stage refresh inside the existing engine-owned snapshot future.

Stage one returns a typed `RefreshOverview` containing daemon status, default
and active zones, runtime/permanent zone data, and the available service and
policy names needed to render navigation. It is not a `FirewallSnapshot` and
cannot be passed to mutation validation, persistence, export, audit, restore,
or dependency analysis.

The engine emits an identity-bearing `RefreshOverviewReady` event, then keeps
polling the same cancellable lifecycle while the CLI backend hydrates heavy
details. Stage two produces the unchanged authoritative `FirewallSnapshot`.
Other backends may return no overview and continue producing only the final
snapshot.

This preserves the existing single-owner boundary and avoids introducing a
second task, shared backend mutex, partial snapshot schema, or independent
detail lifecycle.

## Application Contracts

Add application-layer values with no UI dependency:

- `RefreshPriority` carries an optional zone, service, and policy preference.
- `RefreshPrioritySource` exposes the latest value without queueing historical
  selections. UI selection updates replace the previous hint through a
  bounded/latest-value channel.
- `RefreshOverview` is a read-only preview value. The engine event, not the
  backend value, attaches the refresh identity.

Extend `FirewallBackend` with two sequential staged-read methods:

- `snapshot_overview` returns an optional overview; and
- `snapshot_hydrated` consumes that optional overview and returns the final
  `SnapshotRead`.

The default overview returns `None`, and the default hydration delegates to
`snapshot_observed`. The D-Bus backend and test fakes therefore keep their
current behavior until explicitly optimized. The engine can emit the overview
between the two awaits instead of waiting for an aggregate result that would
make early delivery impossible.

The CLI implementation splits its current `snapshot` flow after the overview
sections. `snapshot_fresh` remains a full eager read: mutation preconditions
must observe every required section immediately and must not reuse a partial
or tiered result.

## Priority and Hydration Policy

The UI publishes its latest effective zone and optional selected service or
policy. At refresh start, the engine supplies the latest hint. Before launching
each bounded detail batch, the CLI backend reads the latest hint again and
orders work as follows:

1. service definitions referenced by the preferred zone;
2. the explicitly selected service or policy;
3. remaining referenced service definitions and policy details in stable name
   order.

Already-running subprocesses finish normally. Only work that has not started
is reordered. Fan-out remains capped at the existing limit of eight, and every
command still goes through `CommandRunner` with typed argv and existing
timeouts/cancellation behavior.

The final snapshot contains the same data as the current eager implementation.
The optimization changes availability order, not final semantics.

## Engine and UI Flow

The engine captures one refresh ID for both stages. An ordinary lifecycle may
be cancelled during either stage. Dropping it drops all outstanding bounded
fan-out futures before a mutation executes. A post-mutation lifecycle is not
complete until final hydration finishes; a safety rollback remains the only
request that may preempt it.

`EngineEvent::RefreshOverviewReady` and the matching UI action carry the
refresh ID. The reducer accepts the overview only when it matches the active
lifecycle. A cancellation, final completion, or newer lifecycle clears the
preview, so stale overview data cannot overwrite current state.

`UiState` stores the overview separately from its authoritative snapshot.
Zone/status views may render the matching overview with a visible
"loading details" state. Views that require service or policy details continue
using the last authoritative snapshot or show a loading placeholder when none
exists.

At startup, mutations remain disabled until the first authoritative snapshot
arrives. When a previous authoritative snapshot exists, normal mutations stay
available and retain Phase 5C2 behavior: confirmation is based on authoritative
state, the ordinary staged refresh is cancelled, and `snapshot_fresh` performs
the existing full precondition revalidation. Rollbacks are never gated by
overview hydration.

Persistence and export never consume `RefreshOverview`; they operate only on
the authoritative snapshot.

## Error and Closure Semantics

- An overview failure follows the existing refresh failure path and retains
  the last authoritative snapshot.
- A service or policy detail failure is recorded as an exact object/scope
  `DegradedSection` in the final snapshot.
- "Not loaded yet" exists only in the preview path and is never represented as
  an empty authoritative section.
- Cancelling a lifecycle discards its preview and unfinished detail work
  without producing a backend error.
- Engine/UI channel closure keeps the existing identity-preserving error and
  no-busy-loop behavior.
- A mandatory reconciliation that cannot finish details remains incomplete;
  it is not reported as a successful refresh.

## Observability

Keep the existing final `RefreshObservation` contract and add staged timing to
structured tracing:

- time to overview;
- time from overview to final hydration;
- priority hint used for each detail batch;
- preferred versus background detail counts; and
- cancellation stage (`overview` or `hydration`).

The UI may display the loading state but does not need a new dashboard. Final
header metrics continue to describe the completed authoritative refresh.

## Testing

### Pure policy and reducer tests

- stable priority ordering and replacement of stale selection hints;
- matching overview accepted and stale overview ignored;
- cancellation/final completion clears only the matching preview;
- startup mutation gate remains closed without an authoritative snapshot;
- an existing authoritative snapshot preserves normal mutation preemption;
- rollback effects remain available during hydration.

### CLI/backend tests

- a delayed detail runner proves overview availability before hydration;
- preferred-zone service commands launch before background service commands;
- selected policy/service reprioritizes work not yet launched;
- active subprocesses are not restarted when priority changes;
- per-object failures remain typed degraded entries;
- the final staged snapshot equals the current eager snapshot for the same
  fixture and command responses;
- `snapshot_fresh` always performs a complete read.

### Engine and load tests

- paused-time cancellation during both stages drops the read before mutation;
- mandatory post-mutation hydration cannot report early success;
- rollback preempts blocked mandatory hydration and restarts a fresh full
  lifecycle exactly once;
- repeated selection changes remain latest-value bounded and do not grow a
  queue;
- the large synthetic fixture proves the overview reaches the reducer without
  blocking a TUI turn over 50 ms;
- final performance, coverage, MSRV, D-Bus, and three-distribution real-daemon
  gates remain green.

## Delivery Slices

Implement Phase 5C3 as two reviewable code slices on one feature branch:

1. staged backend/application contract, CLI overview, engine lifecycle event,
   identity-aware reducer, and cancellation tests;
2. latest-value selection hints, deterministic detail priority, lazy loading
   placeholders, load/performance evidence, and full validation.

Each slice follows RED, minimal GREEN, focused regression, self-review, and a
conventional commit. Publication uses one protected PR to `develop` only after
a whole-range review and all required checks pass.
