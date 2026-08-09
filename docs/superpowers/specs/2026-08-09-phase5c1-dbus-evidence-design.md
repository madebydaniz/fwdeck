# Phase 5C1 D-Bus Evidence Design

**Status:** Proposed for written review. The Phase 5C decomposition was approved
on 2026-08-09; implementation begins only after this specification is reviewed.

## Problem

FWDeck's optional native D-Bus backend is built and exercised against real
firewalld in the three-distribution integration matrix, but ordinary host-side
coverage does not execute those ignored tests. As a result, the existing
coverage report substantially understates the adapter's exercised behavior and
CI does not prevent D-Bus test coverage from regressing.

The adapter is safety-sensitive. It must keep unsupported resource families
visible as degraded, reject permanent scope before mutation, retain exact D-Bus
method diagnostics, and never use a developer's host firewall for validation.

## Goals

- Measure `src/infrastructure/firewalld/dbus.rs` while tests run against a real
  firewalld daemon and system bus in a disposable Fedora 44 container.
- Enforce at least 60% line coverage for the D-Bus adapter without exclusions,
  generated-source filtering, or lowering the existing project-wide floor.
- Cover the supported read path, safe runtime mutation round trips, scope
  refusal, helper parsing, and structured error categorization.
- Preserve the existing Fedora, Debian, and AlmaLinux behavioral matrix.
- Provide one reproducible developer command and one independently named CI
  check that can be added to both solo-safe branch rulesets.

## Non-goals

- Adding new D-Bus capabilities, permanent D-Bus mutations, signal-driven
  refresh, or support for IP sets, policies, direct rules, or service
  definitions.
- Replacing the CLI backend as the full-featured reference implementation.
- Measuring coverage on all three distributions. Compatibility remains a
  three-distribution behavioral concern; one modern Fedora environment is the
  canonical coverage environment.
- Refactoring the `FirewallBackend` port or weakening degraded-state reporting
  solely to make coverage easier.

## Selected Approach

Use a dedicated Fedora coverage container and extend the existing real-daemon
suite. This keeps coverage execution in the same isolated environment that
provides firewalld and D-Bus, while avoiding instrumentation overhead in every
distribution job.

Two alternatives were rejected:

1. Host-only mocks would produce deterministic coverage but would not prove
   that generated zbus proxies agree with a real daemon.
2. Instrumenting the complete three-distribution matrix would triple the most
   expensive coverage work without adding meaningful line-coverage evidence.

## Architecture

### Coverage container

Add a `dev-coverage` Compose service derived from the Fedora development image.
The service uses the same privileged network namespace, entrypoint, seeded
firewalld state, source mount, Cargo registry cache, and Linux target volume as
the existing `dev` service.

The coverage-only image installs `llvm-tools-preview` and pins
`cargo-llvm-cov` to version `0.8.7`. The normal Fedora, Debian, and AlmaLinux
images remain unchanged, so ordinary development and compatibility jobs do not
pay the extra image size or installation time.

### Coverage runner

Add `scripts/run-dbus-coverage.sh` as the single entry point for local and CI
execution. It will:

1. build the dedicated coverage service;
2. run only the ignored `real_firewalld` integration target with the `dbus`
   feature and `--test-threads=1`;
3. emit an llvm-cov JSON summary under the ignored `target/` directory; and
4. invoke the strict D-Bus coverage checker on the host.

All Cargo dependency resolution inside the test container remains offline.
Image construction is the only step that installs the pinned coverage tool.

### Threshold checker

Add `scripts/check-dbus-coverage.sh`, following the existing critical-path
checker conventions. The script will require `jq`, require exactly one coverage
entry ending in `/src/infrastructure/firewalld/dbus.rs`, validate a numeric line
percentage, print the observed value, and fail below 60%.

Malformed or missing reports exit with a configuration error. A valid report
below the threshold exits with a test failure. ShellCheck covers both scripts.

### CI integration

Add a separate `D-Bus real-daemon coverage` job rather than extending the
ordinary coverage job. The new job will use Fedora 44, retain the existing
30-minute timeout and offline Cargo registry mount pattern, run the coverage
entry point, and write the measured adapter percentage to the job summary.

The existing real-firewalld matrix remains unchanged and continues to verify
behavior on Fedora 44, Debian 13, and AlmaLinux 9. After the new job succeeds on
the merged `develop` commit, add its exact check context to the `main` and
`develop` solo-safe rulesets with no bypass actor.

## Test Design

### Real-daemon tests

Extend `tests/real_firewalld.rs` with serialized, self-restoring D-Bus cases:

- compare CLI and D-Bus runtime/permanent zone details for seeded services,
  ports, interfaces, sources, rich rules, forward ports, and masquerade;
- add and remove one unused runtime port and verify both states through a fresh
  D-Bus snapshot;
- enable and disable runtime masquerade and verify both states;
- keep the existing service round trip and permanent-scope refusal checks; and
- assert every successful operation reports its exact D-Bus method invocation.

Each mutation uses values reserved for integration tests. Cleanup is attempted
before assertions are allowed to fail. The process-wide lock and
`--test-threads=1` remain mandatory. The disposable container is the final
containment boundary if cleanup itself fails.

Global operations that can destabilize the suite, including panic mode,
runtime-to-permanent, and default-zone changes, are not exercised merely to
increase a percentage.

### Unit tests

Add focused tests in `dbus.rs` for:

- structured authorization errors mapping to `PermissionDenied`;
- missing service/name-owner errors mapping to `DaemonNotRunning`;
- unrelated method and transport errors mapping to `Process`;
- valid and invalid port/protocol pairs; and
- forward-compatible filtering of invalid tokens.

No fake test may replace a real-daemon assertion for behavior already supported
by the adapter.

### Checker tests

Exercise the checker with a real generated report plus minimal valid fixtures
for missing entry, duplicate entry, malformed percentage, below-threshold, and
passing-threshold behavior.

## Failure Handling

- If firewalld or the system bus fails to start, the integration test fails;
  the entrypoint warning is never treated as a skip.
- If a supported D-Bus read fails, the snapshot fails rather than rendering an
  empty configuration. Existing intentionally unsupported sections remain degraded.
- If a mutation succeeds but cleanup fails, the test reports both outcomes and
  fails. The container is destroyed after the command.
- If the measured coverage is below 60%, add behavior-focused tests. Do not
  lower the threshold, exclude adapter code, or introduce unreachable test-only
  production branches.

## Documentation and Operator Impact

- Add `make coverage-dbus` for the reproducible developer command.
- Document the Fedora-only measurement and three-distribution behavioral matrix
  in the contributor backend/testing documentation.
- Update `ROADMAP.md` only when the threshold is enforced and the protected
  check has been audited on both branches.
- No runtime UI, configuration, permissions, or firewall behavior changes are
  expected in this slice.

## Acceptance Criteria

- The existing all-features test suite remains green.
- All real-firewalld tests pass on Fedora 44, Debian 13, and AlmaLinux 9.
- The Fedora coverage run reports at least 60% line coverage for `dbus.rs`.
- The checker fails closed for missing, duplicate, malformed, and low reports.
- Formatting, both Clippy configurations, ShellCheck, MSRV 1.88, existing
  critical-path coverage, CodeQL, and release-canary remain green.
- The new CI context is required by the `main` and `develop` solo-safe rulesets
  only after a successful merged run proves the exact context name.
