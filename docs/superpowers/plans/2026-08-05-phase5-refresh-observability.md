# Phase 5A Refresh Observability Implementation Plan

> **For Codex:** Execute this plan task-by-task with TDD and conventional commits.

**Goal:** Replace the UI's tick-derived refresh timing with exact backend observations, expose CLI subprocess count and per-section latency, and establish a deterministic performance regression gate.

**Architecture:** Pure refresh observation value types live in `domain::observation`. The application backend port returns a snapshot read containing both the result and its observation, with a total-only default for non-CLI adapters. The CLI adapter scopes an internal recorder around a refresh so every subprocess and logical section is measured without serializing telemetry into `FirewallSnapshot`. The engine transports the observation to the pure UI reducer; Doctor renders the same data. Performance tests use domain-owned synthetic snapshots and fake runners, never invented firewalld output.

**Tech Stack:** Rust 1.88, Tokio task-local scopes, ratatui reducer tests, cargo test, cargo llvm-cov.

---

## Task 1: Define the typed refresh observation contract

**Files:**
- Modify: `src/domain/observation.rs`
- Modify: `src/domain/mod.rs`
- Modify: `src/application/ports.rs`
- Test: `src/domain/observation.rs`

1. Add a failing unit test proving section records are sorted and total/process counts are preserved.
2. Add `RefreshSection`, `RefreshSectionObservation`, and `RefreshObservation` pure value types.
3. Add `SnapshotRead` to the backend port, containing the snapshot result and observation.
4. Add a default `snapshot_observed` method that measures exact total latency and reports no adapter-specific section/process data.
5. Run `rtk cargo test --locked domain::observation application::ports`.

## Task 2: Instrument the CLI adapter by section and subprocess

**Files:**
- Modify: `src/infrastructure/firewalld/mod.rs`
- Test: `tests/backend.rs`

1. Extend the existing exact-command snapshot test to assert total subprocess count and counts for Status, Zones, IpSets, DirectRules, Services, and Policies.
2. Add a refresh-scoped recorder using Tokio task-local state; mutation and non-refresh commands remain unobserved.
3. Measure wall latency for every logical section and increment the recorder around every `CommandRunner::run` call.
4. Override `snapshot_observed` for `CliBackend`; keep `snapshot` and `snapshot_fresh` behavior and caches unchanged.
5. Run `rtk cargo test --locked --test backend snapshot_observation` and the full backend integration test target.

## Task 3: Carry exact metrics through engine and UI

**Files:**
- Modify: `src/application/api.rs`
- Modify: `src/application/engine.rs`
- Modify: `src/ui/action.rs`
- Modify: `src/ui/mod.rs`
- Modify: `src/ui/state.rs`
- Modify: `src/ui/update/mod.rs`
- Modify: `src/ui/components.rs`
- Test: `src/application/engine.rs`
- Test: `src/ui/update/mod.rs`

1. Add failing engine and reducer tests proving the observation survives the channel boundary and replaces tick-derived duration.
2. Change `EngineEvent::RefreshFinished` and `UiAction::RefreshCompleted` to carry both result and observation.
3. Store the last typed observation in `UiState`; remove `refresh_started_tick` and `last_refresh_ms`.
4. Render exact milliseconds and subprocess count in the header without changing snapshot/error reconciliation.
5. Run `rtk cargo test --locked application::engine::tests ui::update::tests`.

## Task 4: Expose observations in Doctor

**Files:**
- Modify: `src/main.rs`
- Test: compilation plus CLI smoke tests in `src/cli.rs`

1. Make Doctor use `snapshot_observed` for its read pass.
2. Print total refresh latency, total subprocess count when known, and stable per-section rows.
3. Preserve the existing degraded/read-access reporting on errors.
4. Run `rtk cargo test --locked cli::tests` and `rtk cargo check --locked --all-features`.

## Task 5: Add the first deterministic performance gate

**Files:**
- Modify: `src/domain/mock.rs`
- Modify: `src/application/engine.rs`
- Modify: `src/ui/views.rs`
- Modify: `.github/workflows/ci.yml`

1. Build a large domain fixture with 100 zones, 500 services, 100 IP sets, and 100 policies; do not synthesize firewalld text.
2. Assert representative view/model transformations stay below the 50 ms TUI-event budget in release mode.
3. Assert an engine refresh of the large in-memory snapshot stays below the 2 s large-snapshot budget.
4. Add a dedicated step to the required `Tests` job running `rtk cargo test --locked --release performance_budget -- --test-threads=1`.
5. Run the performance target three times locally to detect obvious variance.

## Task 6: Validate and publish the Phase 5A PR

**Files:**
- Modify: plan status only if implementation details changed.

1. Run `rtk cargo fmt --all -- --check`.
2. Run `rtk cargo clippy --locked --all-targets -- -D warnings`.
3. Run `rtk cargo clippy --locked --all-targets --features dbus -- -D warnings`.
4. Run `rtk cargo test --locked --all-features`.
5. Run `rtk cargo llvm-cov --locked --all-features --fail-under-lines 75 --summary-only`.
6. Commit with conventional commits, push `feat/phase5-observability-baseline`, open a PR to `develop`, wait for every required check, and merge only through the protected PR path.

## Follow-up Phase 5 PRs

- **Phase 5B:** raise critical-path coverage for rollback lifecycle, engine plan execution, systemd guard, snapshot store, and real D-Bus integration.
- **Phase 5C:** selected-zone priority, lazy service/policy detail fetches, and measured refresh cancellation/coalescing under load.
- **Phase 5D:** enforce the final overall and critical-path coverage thresholds after the new tests land.
