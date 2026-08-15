# Developing FWDeck

This guide covers the supported development workflow, verification gates, and
repository conventions. Read [ARCHITECTURE.md](ARCHITECTURE.md) before changing
engine sequencing, mutation behavior, command construction, or backend state.

## Prerequisites

- Rust 1.88 or newer
- Docker Compose for real-firewalld development and integration tests
- `make` for the repository command shortcuts
- Optional: `cargo-deny`, `cargo-llvm-cov`, and ShellCheck for extended gates

The host firewall must never be used for development tests. Real-daemon tests
run only in disposable privileged containers.

## Run the application

Warm the shared container cache once, then launch FWDeck against a seeded Fedora
firewalld daemon:

```bash
make warm
make run
```

On macOS or when Docker DNS is unavailable, use the host Cargo registry as the
offline source:

```bash
make run-offline
```

Open an interactive development shell when you need to run Cargo commands in
the same real-daemon environment:

```bash
make shell
cargo run
```

`cargo test` and the host-runnable checks use fakes and fixtures. They do not
touch firewalld.

## Fast local verification

Run the focused test for the code being changed first. Before opening a pull
request, run the host gate:

```bash
make check
```

That target runs formatting verification, Clippy with warnings denied, and the
unit/integration suite. The explicit commands are:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

Changes affecting the optional backend must also pass:

```bash
cargo clippy --all-targets --features dbus -- -D warnings
cargo build --locked --features dbus
```

Verify the minimum supported Rust version when dependencies or public language
features change:

```bash
make msrv
```

## Real-firewalld verification

Run the real-daemon suite serially inside the disposable container:

```bash
make test-real
```

The compatibility matrix covers Fedora, Debian, and AlmaLinux. Tests are
serialized with `--test-threads=1` because they mutate shared daemon state.
Never run an ignored real-firewalld test against the host.

For native D-Bus coverage:

```bash
make coverage-dbus
```

On a cold Docker cache, expose the host Cargo registry read-only as documented
by `make help`. Coverage floors are safety gates; improve them with meaningful
tests rather than exclusions or test-only production branches.

## Working in the architecture

### Domain

Add validating constructors for values that can reach argv or persisted state.
Keep domain types independent from Tokio, process execution, terminal widgets,
and adapter errors.

### Application

Keep backend ownership in the engine. Preserve bounded queues, normal-operation
FIFO ordering, rollback priority, refresh coalescing, lifecycle identity, and
drop-before-apply cancellation. A mutation must finish with a mandatory fresh
snapshot.

### Infrastructure

Build firewalld mutation arguments only in
`src/infrastructure/firewalld/command.rs`. Use `CommandRunner` and direct argv;
never use shell interpolation. Keep timeouts, locale control, trusted executable
resolution, and exact error context.

When parsing new firewalld output, capture the fixture from a real daemon and
add a parser regression. Do not create output fixtures from memory or from the
documentation alone.

### UI

Keep `update` pure. Model terminal input and engine events as `UiAction`, return
effects explicitly, and test behavior without a terminal. Preview refresh data
may render early, but mutations must continue to use the authoritative snapshot.

## Error handling

Production paths do not use `unwrap`, `expect`, or `panic!`. Use `thiserror`
where callers match typed variants. Leaf I/O helpers may return
`Result<_, String>` when their only consumer displays the error to the operator.

Partial runtime/permanent failure is a first-class result. Never simplify it to
success, and never hide unsupported backend behavior behind an empty response.

## Documentation and website

The README is the repository entry point. The static website and operator guide
live under `site/`, while shared screenshots and the demo live under `assets/`.

Assemble the website locally with:

```bash
make site
```

Version strings marked with `x-release-please-version` are owned by
release-please. Do not edit generated changelog version sections by hand.

## Commits and pull requests

Pull requests target `develop`. Keep commits focused and use Conventional
Commits because release-please derives versions and changelog entries from them:

```text
feat: add a user-visible capability
fix: correct unsafe or incorrect behavior
perf: reduce observable work or latency
docs: update documentation only
chore: maintain tooling or dependencies
```

Document connectivity risk in `connectivity_warning()`, include the focused
regression command in the pull request, and complete the repository pull request
checklist. Release, packaging, dependency, and shell changes also exercise the
release canary in CI.

## Release ownership

Release Please owns version bumps and `CHANGELOG.md`. Merging its release pull
request publishes the GitHub release, then the binary workflow builds four Linux
targets, native packages, checksums, an SBOM, and keyless Cosign signatures.
Never create a competing manual version section or retag an existing release.
