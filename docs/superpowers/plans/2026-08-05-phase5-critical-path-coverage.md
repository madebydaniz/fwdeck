# Phase 5B Critical-Path Coverage Implementation Plan

> **For Codex:** Execute this plan task-by-task with TDD and conventional commits.

**Goal:** Raise and enforce line coverage for mutation orchestration, the systemd rollback guard, and snapshot persistence without weakening production safety boundaries.

**Architecture:** Production entry points keep their current public contracts. Snapshot persistence delegates parsing/listing/envelope work to directory-scoped helpers so tests never race on process-global XDG environment variables. The systemd rollback adapter delegates capability-dependent behavior to path/uid-aware private methods so a fake `CommandRunner` can exercise the real request and error lifecycle. Engine tests drive public request/event channels to cover plan and rollback branches. CI reads llvm-cov JSON and fails on per-file thresholds.

**Tech Stack:** Rust 1.88, Tokio, cargo-llvm-cov JSON, jq, ShellCheck.

---

## Task 1: Cover snapshot persistence and compatibility safety

**Files:**
- Modify: `src/infrastructure/snapshot_store.rs`

1. Add failing tests for same-host envelope round-trip, future schema rejection, cross-host rejection, legacy envelope marking, bare snapshot marking, traversal rejection, and stable newest-first listing with pin metadata.
2. Extract `snapshot_file`, `load_from_dir`, and `list_in_dir` private helpers; public `save`, `load`, and `list` remain behaviorally identical.
3. Reject non-regular snapshot inputs before reading so list/load behavior stays aligned.
4. Run `rtk cargo test --locked infrastructure::snapshot_store::tests`.

## Task 2: Cover the systemd rollback guard lifecycle

**Files:**
- Modify: `src/infrastructure/rollback.rs`

1. Add a queue-backed fake `CommandRunner` and failing tests for unavailable prerequisites, successful arm/disarm, process errors, non-zero exits, stdout fallback, and operations without runtime inverses.
2. Extract private `arm_with_prerequisites` and `disarm_with_path` seams; production `arm` and `disarm` still resolve trusted executables and process uid.
3. Assert every request remains argv-only, timeout-bounded, and uses the existing watchdog grace.
4. Run `rtk cargo test --locked infrastructure::rollback::tests`.

## Task 3: Close engine plan and rollback orchestration branches

**Files:**
- Modify: `src/application/engine.rs`

1. Add request/channel tests for an empty plan with failed preflight, forged invalid plan validation, read-only plan fail-fast, and read-only rollback.
2. Assert no backend apply or watchdog arm occurs when policy/preflight rejects work.
3. Preserve the existing event order and remaining-operation guarantees.
4. Run `rtk cargo test --locked application::engine::tests`.

## Task 4: Enforce critical-path thresholds in CI

**Files:**
- Add: `scripts/check-critical-coverage.sh`
- Modify: `.github/workflows/ci.yml`

1. Add a strict JSON reader that fails on missing files, malformed percentages, or thresholds below engine 90%, systemd rollback guard 85%, and snapshot store 80%.
2. Generate llvm-cov JSON once in the required Coverage job, run the checker, then render the text summary.
3. Add the script to the existing ShellCheck job.
4. Run `rtk shellcheck scripts/check-critical-coverage.sh` and a passing/failing fixture smoke test.

## Task 5: Validate and publish the Phase 5B PR

**Files:**
- Modify: plan status only if implementation details changed.

1. Run `rtk cargo fmt --all -- --check`.
2. Run `rtk cargo clippy --locked --all-targets -- -D warnings`.
3. Run `rtk cargo clippy --locked --all-targets --features dbus -- -D warnings`.
4. Run `rtk cargo test --locked --all-features`.
5. Run `rtk cargo llvm-cov --locked --all-features --fail-under-lines 75 --json --summary-only --output-path target/coverage-summary.json`.
6. Run `rtk scripts/check-critical-coverage.sh target/coverage-summary.json`.
7. Commit, push, open a PR to `develop`, wait for every required check, merge through the protected PR path, and verify post-merge CI.

## Follow-up Phase 5C

- Measure D-Bus coverage inside the real-firewalld container and enforce its 60% integration target separately.
- Add selected-zone priority, lazy service/policy detail fetches, and measured refresh cancellation/coalescing.
