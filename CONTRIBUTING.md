# Contributing to FWDeck

Thanks for considering a contribution. Ground rules:

## Before you start

Open an issue for anything larger than a bugfix — architecture discussions
happen before code. Read [ARCHITECTURE.md](ARCHITECTURE.md) before changing
layer boundaries or safety sequencing, and use [DEVELOPMENT.md](DEVELOPMENT.md)
for the supported local workflow and verification gates.

## Non-negotiables

1. **No shell.** Commands are typed argument vectors via `Command::new`.
2. **Validation at the boundary.** New values reaching argv get a validating
   domain constructor with tests.
3. **Honest results.** Partial failures are never reported as success.
4. **Runtime/permanent separation stays explicit** — in the domain, in the UI,
   and in every operation.
5. **The reducer stays pure.** UI logic is tested without a terminal.
6. **Parsers are fixture-tested.** New firewall-cmd output gets a fixture
   captured from a real daemon (use the dev container), not a hand-typed guess.

## Workflow

```sh
docker compose run --rm dev      # real firewalld sandbox
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
make test-real                  # container only; serialized real-daemon suite
make coverage-dbus              # container only; real-daemon D-Bus coverage
```

All applicable gates must pass. `cargo test` must never touch the host firewall.

### Backend evidence

Real-firewalld tests run only inside disposable privileged containers and are
serialized with `--test-threads=1`; never run an ignored firewalld test against
the host. The compatibility matrix exercises Fedora 44, Debian 13, and
AlmaLinux 9. Line coverage is measured once in the Fedora 44 coverage image so
instrumentation does not triple the matrix cost.

`make coverage-dbus` runs the D-Bus integration target and enforces at least
60% line coverage for `src/infrastructure/firewalld/dbus.rs`. On a cold Docker
cache, expose the host Cargo registry read-only with
`FWDECK_CARGO_REGISTRY="$HOME/.cargo/registry" make coverage-dbus`. Improve this
gate with tests for supported behavior; do not lower the threshold, exclude
adapter code, or add test-only production branches.

Pull requests target `develop`. Pushes to `develop` and `main` run the full CI
and CodeQL suites. Changes to release, packaging, dependency, or shell files
also run the release canary: it builds a real tar/RPM/DEB set, transfers the
artifacts between jobs, generates an SBOM, and exercises Cosign. Trusted
keyless signing and provenance run only after the change lands on a protected
repository branch.

The `make` targets wrap these (`make help` lists them). If Docker's DNS is flaky
(common on macOS), run `make warm` once — it fetches dependencies into a shared
cached volume — after which `make run` and the container build fully offline.

## Commits

Small, focused commits with imperative messages. Document any operation that
can interrupt connectivity in its `connectivity_warning()`.

## Commit messages

Releases and the changelog are automated with release-please, which reads
[Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add zone overview drift lines
fix: narrow restore target for permanent-only zones
perf: fetch ipset info concurrently
docs: explain offline mode
chore: bump dependencies
```

`feat` triggers a minor version bump, `fix`/`perf` a patch, and a
`BREAKING CHANGE:` footer (or `!` after the type) a major bump. Commits that
do not follow the convention will not appear in the changelog.
