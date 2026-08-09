# Phase 5C1 D-Bus Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove and enforce at least 60% line coverage for the native D-Bus adapter while exercising supported behavior against a disposable real firewalld daemon.

**Architecture:** Preserve the hexagonal boundary: production changes stay inside the D-Bus adapter and are limited to a pure error-classification helper; real-daemon evidence stays in `tests/real_firewalld.rs`; coverage orchestration stays in Docker, shell scripts, Make, and CI. The existing three-distribution behavioral matrix remains independent from Fedora-only coverage measurement.

**Tech Stack:** Rust 1.88+, zbus 5.18, Tokio, cargo-llvm-cov 0.8.7, Fedora 44, Docker Compose, Bash, jq, ShellCheck, GitHub Actions.

---

## Guardrails

- Never execute firewalld tests on the host.
- Do not add permanent D-Bus mutations, signal refresh, unsupported object families, coverage exclusions, or test-only production branches.
- Keep IP sets, policies, direct rules, and service definitions explicitly degraded.
- Keep the overall 75% floor and all existing critical-file thresholds unchanged.
- Run real-daemon tests with `--test-threads=1` and retain the process-wide lock.
- Restore runtime state before assertions that may panic.
- Do not update the ignored local `ROADMAP.md`; ruleset status is recorded only after a green merged `develop` run.

## Task 1: Cover pure D-Bus adapter helpers

**Files:**

- Modify: `src/infrastructure/firewalld/dbus.rs:623-720`

- [ ] Add failing unit tests for authorization names/details, missing service names, unrelated method errors, valid/invalid port pairs, and invalid-token filtering.

The structured-error tests call a pure helper:

```rust
#[test]
fn method_error_maps_authorization_failures() {
    for (name, detail) in [
        ("org.freedesktop.DBus.Error.AccessDenied", "denied"),
        (
            "org.fedoraproject.FirewallD1.Exception.NotAuthorized",
            "denied",
        ),
        (
            "org.fedoraproject.FirewallD1.Exception",
            "NOT_AUTHORIZED: action denied",
        ),
    ] {
        let error = map_method_error(name, detail, "rendered error".into());
        assert!(matches!(error, FirewallError::PermissionDenied { .. }));
    }
}

#[test]
fn method_error_maps_missing_daemon_names() {
    for name in [
        "org.freedesktop.DBus.Error.ServiceUnknown",
        "org.freedesktop.DBus.Error.NameHasNoOwner",
    ] {
        assert!(matches!(
            map_method_error(name, "missing", "rendered error".into()),
            FirewallError::DaemonNotRunning
        ));
    }
}
```

Parser tests assert `pair_to_port("443", "tcp") == "443/tcp".parse().ok()`, reject an invalid protocol, and prove `parsed` keeps a valid service while dropping an invalid token. Tests may use `expect`; production code may not.

- [ ] Run RED:

```bash
cargo test --locked --features dbus infrastructure::firewalld::dbus::tests
```

Expected: compilation fails because `map_method_error` does not exist.

- [ ] Add the pure classifier immediately above `dbus_err`:

```rust
fn map_method_error(name: &str, detail: &str, rendered: String) -> FirewallError {
    if name == "org.freedesktop.DBus.Error.AccessDenied"
        || name.contains("NotAuthorized")
        || detail.starts_with("NOT_AUTHORIZED")
    {
        FirewallError::PermissionDenied { detail: rendered }
    } else if name == "org.freedesktop.DBus.Error.ServiceUnknown"
        || name == "org.freedesktop.DBus.Error.NameHasNoOwner"
    {
        FirewallError::DaemonNotRunning
    } else {
        FirewallError::Process(rendered)
    }
}
```

Refactor only the `zbus::Error::MethodError` arm to delegate with `name.as_str()`, `detail.as_deref().unwrap_or_default()`, and the original rendered error. Leave transport handling unchanged.

- [ ] Run GREEN and lint:

```bash
cargo test --locked --features dbus infrastructure::firewalld::dbus::tests
cargo clippy --all-targets --features dbus --locked -- -D warnings
```

- [ ] Commit:

```bash
git add src/infrastructure/firewalld/dbus.rs
git commit -m "test(dbus): Cover structured adapter helpers"
```

## Task 2: Strengthen real-daemon read and reporting evidence

**Files:**

- Modify: `tests/real_firewalld.rs:376-510`

- [ ] Add `assert_applied_method(outcome, expected)` that requires one successful runtime step and verifies the first invocation token equals the exact D-Bus method.
- [ ] Add `assert_zone_parity(cli, dbus)` comparing services, ports, forward ports, rich rules, interfaces, sources, ICMP blocks, and masquerade.
- [ ] Extend `dbus_backend_agrees_with_cli_on_read_path` to compare both runtime and permanent details for the seeded default zone.
- [ ] Preserve assertions that unsupported D-Bus sections remain degraded.
- [ ] Strengthen the existing service round trip with exact `addService` and `removeService` invocation assertions.
- [ ] Keep permanent-scope refusal and prove it returns a failed step without a mutation method.
- [ ] Compile without touching a firewall:

```bash
cargo test --locked --features dbus --test real_firewalld --no-run
```

- [ ] Commit:

```bash
git add tests/real_firewalld.rs
git commit -m "test(dbus): Strengthen real-daemon evidence"
```

## Task 3: Add self-restoring runtime mutation round trips

**Files:**

- Modify: `tests/real_firewalld.rs:376-580`

- [ ] Add a port round-trip test for reserved `49152/tcp` in `public`.

Sequence: lock, connect, pre-clean the reserved port, add at runtime, take a fresh snapshot, remove before assertions, take another snapshot, then assert `addPort`, `removePort`, present-after-add, and absent-after-remove. Preserve both the primary and cleanup result in any failure message.

- [ ] Add a masquerade round trip that reads the initial runtime value, toggles it, snapshots, restores the initial value before assertions, snapshots again, and verifies exact `addMasquerade`/`removeMasquerade` method names.
- [ ] Use the current `FirewallOperation` field names; do not change domain types.
- [ ] Compile on the host without running ignored tests:

```bash
cargo test --locked --features dbus --test real_firewalld --no-run
```

- [ ] Run only in Fedora:

```bash
docker compose -f docker-compose.yml run --rm dev cargo test --offline --locked \
  --features dbus --test real_firewalld -- --ignored --test-threads=1
```

- [ ] Commit:

```bash
git add tests/real_firewalld.rs
git commit -m "test(dbus): Cover runtime mutation round trips"
```

## Task 4: Build a fail-closed coverage checker

**Files:**

- Create: `scripts/check-dbus-coverage.sh`
- Create: `scripts/test-dbus-coverage-checker.sh`

- [ ] Write the checker contract test first. Use `mktemp -d` plus a trap scoped to that exact directory.
- [ ] Assert these exit codes:

| Fixture | Exit |
|---|---:|
| one D-Bus entry at 60.00 | 0 |
| one D-Bus entry at 59.99 | 1 |
| missing D-Bus entry | 2 |
| duplicate D-Bus entries | 2 |
| non-numeric percentage | 2 |
| malformed JSON | 2 |

- [ ] Run RED: `bash scripts/test-dbus-coverage-checker.sh`; expect missing-checker failure.
- [ ] Implement the checker using the exact suffix `/src/infrastructure/firewalld/dbus.rs`, require exactly one numeric `.summary.lines.percent`, print the observed value, exit 1 below 60, and exit 2 for usage, jq, parsing, missing, duplicate, or malformed-report failures.
- [ ] Make both files executable and run:

```bash
bash scripts/test-dbus-coverage-checker.sh
shellcheck scripts/check-dbus-coverage.sh scripts/test-dbus-coverage-checker.sh
```

- [ ] Commit:

```bash
git add scripts/check-dbus-coverage.sh scripts/test-dbus-coverage-checker.sh
git commit -m "test(coverage): Enforce D-Bus report contract"
```

## Task 5: Add the isolated coverage image and runner

**Files:**

- Modify: `docker/Dockerfile:1-45`
- Modify: `docker-compose.yml:1-105`
- Modify: `Makefile:40-55`
- Create: `scripts/run-dbus-coverage.sh`

- [ ] Convert the current Dockerfile body into `FROM ${BASE_IMAGE} AS base`.
- [ ] Add a Fedora-only `coverage` stage:

```dockerfile
FROM base AS coverage
ARG CARGO_LLVM_COV_VERSION=0.8.7
RUN rustup component add llvm-tools-preview \
    && cargo install cargo-llvm-cov --version "${CARGO_LLVM_COV_VERSION}" --locked

FROM base AS dev
```

Existing services continue using the final `dev` stage.

- [ ] Add `dev-coverage` with `target: coverage`, Fedora 44, privileged mode, the existing source/registry volumes, and a new `cargo-target-coverage:/workspace/target-coverage` volume.
- [ ] Add `scripts/run-dbus-coverage.sh`. It explicitly uses `docker compose -f docker-compose.yml`, builds `dev-coverage`, optionally mounts a validated `FWDECK_CARGO_REGISTRY` directory read-only, runs offline and locked, writes `target/dbus-coverage-summary.json`, then invokes the host checker.
- [ ] Use this exact instrumented command inside the container:

```bash
cargo llvm-cov --offline --locked --features dbus --test real_firewalld \
  --json --summary-only --output-path target/dbus-coverage-summary.json -- \
  --ignored --test-threads=1
```

- [ ] Add:

```make
.PHONY: coverage-dbus
coverage-dbus: ## Measure real-daemon D-Bus coverage in an isolated Fedora container
	./scripts/run-dbus-coverage.sh
```

- [ ] Validate:

```bash
docker compose -f docker-compose.yml config --quiet
shellcheck scripts/run-dbus-coverage.sh scripts/check-dbus-coverage.sh \
  scripts/test-dbus-coverage-checker.sh
FWDECK_CARGO_REGISTRY="$HOME/.cargo/registry" make coverage-dbus
```

Expected: all real-daemon tests pass and D-Bus line coverage is at least 60%. If not, add behavior-focused tests; never weaken the gate.

- [ ] Commit:

```bash
git add docker/Dockerfile docker-compose.yml Makefile scripts/run-dbus-coverage.sh
git commit -m "build(dbus): Add isolated coverage environment"
```

## Task 6: Wire the independent CI context

**Files:**

- Modify: `.github/workflows/ci.yml:115-300`

- [ ] Add all three new scripts to the existing ShellCheck command.
- [ ] Add a ShellCheck-job step that runs `./scripts/test-dbus-coverage-checker.sh`.
- [ ] Add job id `dbus-real-coverage` with display name exactly `D-Bus real-daemon coverage`, Ubuntu runner, 30-minute timeout, pinned checkout/toolchain actions, host `cargo fetch --locked`, and `FWDECK_CARGO_REGISTRY="$HOME/.cargo/registry" ./scripts/run-dbus-coverage.sh`.
- [ ] Publish the measured value to `$GITHUB_STEP_SUMMARY` only when the report exists.
- [ ] Keep the existing `real-firewalld` Fedora/Debian/Alma matrix unchanged.
- [ ] Inspect YAML for untrusted interpolation and run:

```bash
shellcheck docker/entrypoint.sh scripts/install.sh scripts/preview-site.sh \
  scripts/check-critical-coverage.sh scripts/check-dbus-coverage.sh \
  scripts/test-dbus-coverage-checker.sh scripts/run-dbus-coverage.sh
```

- [ ] Commit:

```bash
git add .github/workflows/ci.yml
git commit -m "ci(dbus): Enforce real-daemon coverage"
```

## Task 7: Document the evidence boundary

**Files:**

- Modify: `CONTRIBUTING.md:23-50`
- Modify: `src/infrastructure/firewalld/dbus.rs:1-12`
- Optionally modify: `site/docs/index.html:855-900`

- [ ] Replace the stale nonexistent `docs/backend.md` module link with `CONTRIBUTING.md`.
- [ ] Document `make coverage-dbus`, Fedora-only measurement, the three-distro behavioral matrix, the 60% adapter floor, host-firewall prohibition, serial container execution, and the rule against threshold reduction/exclusions.
- [ ] If the public site already lists real-firewalld developer commands, add `make coverage-dbus` without exposing rollout or branch-protection state.
- [ ] Run `cargo fmt --all -- --check` and `git diff --check`.
- [ ] Commit:

```bash
git add CONTRIBUTING.md src/infrastructure/firewalld/dbus.rs
git add site/docs/index.html  # only when changed
git commit -m "docs(dbus): Document coverage workflow"
```

## Task 8: Full local verification

**Files:** None unless a verified failure needs a focused fix.

- [ ] Run host-safe gates:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo clippy --all-targets --features dbus --locked -- -D warnings
cargo test --locked --all-features
cargo +1.88 check --all-targets --locked
bash scripts/test-dbus-coverage-checker.sh
shellcheck docker/entrypoint.sh scripts/install.sh scripts/preview-site.sh \
  scripts/check-critical-coverage.sh scripts/check-dbus-coverage.sh \
  scripts/test-dbus-coverage-checker.sh scripts/run-dbus-coverage.sh
docker compose -f docker-compose.yml config --quiet
```

- [ ] Run the canonical Fedora gate:

```bash
FWDECK_CARGO_REGISTRY="$HOME/.cargo/registry" make coverage-dbus
```

- [ ] Run the three services serially:

```bash
for service in dev dev-debian dev-el9; do
  docker compose -f docker-compose.yml run --rm "$service" cargo test \
    --offline --locked --features dbus --test real_firewalld -- \
    --ignored --test-threads=1
done
```

If an offline distro cache is unavailable, report that exact local limitation and rely on the PR matrix; do not claim local success.

- [ ] Inspect scope:

```bash
git status --short --branch
git diff --check origin/develop...HEAD
git log --oneline --decorate origin/develop..HEAD
```

Expected: only Phase 5C1 files and focused commits; clean worktree.

## Task 9: Protected integration and post-merge audit

**Files:** None.

- [ ] Push `feat/phase5c1-dbus-evidence`.
- [ ] Open a PR to `develop` documenting the Fedora measurement/three-distro behavior split, exact local results, measured percentage, unchanged degraded sections, host-firewall isolation, and unchanged existing floors.
- [ ] Wait for every required check, all real-firewalld matrix entries, and `D-Bus real-daemon coverage`.
- [ ] Merge through the protected PR path and verify `origin/develop` contains the merge.
- [ ] Wait for a successful merged `develop` run and confirm the exact check context `D-Bus real-daemon coverage`.
- [ ] Only then add that exact context to both `main` and `develop` solo-safe rulesets.
- [ ] Re-audit both rulesets: active, PR required, strict required checks, new context exactly once, no bypass actors, no direct-push path.
- [ ] Report local, pushed, PR, merged, post-merge, and ruleset states separately. Phase 5C1 is incomplete until merged evidence and both rulesets are verified.
