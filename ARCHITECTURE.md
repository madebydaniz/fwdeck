# FWDeck architecture

FWDeck is a safety-first terminal interface for Linux firewalld. Its design is
optimized for three properties: firewall state stays honest, risky mutations
remain recoverable, and the terminal stays responsive while firewalld is slow.

## System shape

FWDeck is a single Rust crate and one binary. The code follows a hexagonal
architecture with dependencies pointing inward:

```text
src/domain/          Validated value types, snapshots, operations, restore diffs
       ^
       |
src/application/     Backend ports, engine protocol, scheduling and orchestration
       ^
       |
src/infrastructure/  CLI, D-Bus, process, rollback, audit and storage adapters

src/ui/              TEA state, actions, reducer, views and terminal rendering
src/main.rs          Process startup, adapter selection and dependency wiring
```

The domain has no I/O and no Tokio dependency. The application layer owns use
case sequencing and depends on backend traits rather than concrete adapters.
Infrastructure implements those traits. `main.rs` is the composition root.

## Domain model

Values that can reach firewalld commands are validated newtypes such as
`ZoneName`, `ServiceName`, and `PortSpec`. Validation happens before an
operation reaches an adapter, so command construction never has to interpret
untrusted free-form input.

`FirewallSnapshot` is the authoritative model of runtime and permanent state.
The two scopes remain distinguishable throughout the domain, UI, audit trail,
and operation result. A runtime success followed by a permanent failure is a
partial application, never a success.

`FirewallOperation` owns validation, user-facing descriptions, connectivity
warnings, and inverse operations where a safe inverse exists. Rich rules remain
verbatim strings; FWDeck does not parse and reconstruct their grammar.

## Application engine

One engine task owns the backend. This prevents concurrent mutation sessions
from racing through the same adapter and gives the application a single place
to enforce ordering and safety.

The UI communicates with the engine through bounded channels. Normal
operations preserve FIFO order. Manual refresh demand is coalesced, while
rollback has reserved capacity and priority so a saturated normal queue cannot
block recovery.

The engine emits typed lifecycle events. The UI reducer accepts an event only
when its identity matches the active lifecycle, which prevents stale completion
events from overwriting newer state.

## Staged refresh

A refresh has two stages:

1. **Overview:** fetch inexpensive zone and policy summaries and publish a
   responsive, read-only preview.
2. **Hydration:** fetch service and policy details in bounded batches, ordered by
   the latest UI selection priority.

Only the final hydrated snapshot is authoritative for mutations and exports.
Preview data may improve rendering, but it never satisfies a mutation
precondition. A new refresh, shutdown, or priority mutation can cancel the
active read; owned subprocesses terminate when their future is dropped.

Periodic and manual refresh requests are single-flight and coalesced. A
confirmed mutation preempts an ordinary refresh, applies through the sole
backend owner, and is followed by a fresh mandatory reconciliation.

## Mutation safety

Every mutation follows the same path:

```text
validated input
    -> confirmation
    -> authoritative snapshot identity check
    -> rollback guard for risky changes
    -> runtime/permanent apply
    -> honest per-step result
    -> mandatory refresh
```

The snapshot identity reviewed by the operator travels with the operation. The
engine bypasses refresh caches and fails closed when firewalld changed between
confirmation and execution.

Risky changes arm a systemd-backed rollback unit before the mutation starts.
That out-of-process guard survives a crash, `SIGKILL`, or a dropped SSH session.
When systemd is unavailable, FWDeck reports the reduced guarantee and uses the
in-process fallback. Rollback requests have a dedicated priority lane and are
executed exactly once.

An OS-backed mutation lock allows one mutation-capable FWDeck session at a
time. Read-only sessions remain concurrent, and process exit releases the lock.

## Backend boundary

`src/application/ports.rs` defines the backend contract. The engine is generic
over the backend; it does not use a trait object.

The default adapter invokes `firewall-cmd`. Native D-Bus support is optional
through the `dbus` Cargo feature, and offline mode uses
`firewall-offline-cmd`. Unsupported backend capabilities are visible errors or
degraded states, not empty configuration.

All firewalld mutation argv is built in
`src/infrastructure/firewalld/command.rs`. External programs receive typed
argument vectors through `CommandRunner`; FWDeck never constructs a shell
command. Auxiliary read-only probes and the rollback watchdog also use trusted
executable resolution, a cleared environment, timeouts, and direct argv.

Parser behavior is fixture-tested against output captured from real firewalld
daemons. New CLI or D-Bus behavior must be verified in the disposable daemon
matrix before it becomes a documented capability.

## UI architecture

The terminal UI follows The Elm Architecture:

```text
input or engine event -> UiAction -> pure update -> UiState -> render
                                      |
                                      +-> explicit effects
```

The reducer performs no I/O. Effects are dispatched by the outer event loop,
which keeps rendering, input, refresh delivery, and rollback delivery
observable and testable. Shared values read by the UI live in the domain layer
so the dependency direction stays inward.

## Local state and trust boundaries

Configuration follows XDG at `~/.config/fwdeck/config.toml`. Audit records,
logs, snapshots, and exports live below `~/.local/state/fwdeck/` by default.

State files use bounded retention, strict filename matching, and symlink
refusal. The JSONL audit chain detects accidental corruption and ordinary
editing; it is not a cryptographic defense against an attacker who can rewrite
both records and chain values.

Unprivileged startup degrades to a visible read-only mode. FWDeck never
re-executes itself with `sudo` and never performs an implicit network update.

## Change rules

- Keep domain code pure and validate values before adapter construction.
- Preserve runtime and permanent scope in every model and result.
- Report partial application explicitly.
- Keep rich rules verbatim.
- Route every mutation through confirmation and engine validation.
- Do not add production `unwrap`, `expect`, `panic!`, or shell interpolation.
- Add real-daemon evidence before claiming new firewalld behavior.
- Keep release, rollback, and connectivity behavior fail-closed.

See [DEVELOPMENT.md](DEVELOPMENT.md) for local commands and verification gates.
