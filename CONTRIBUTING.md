# Contributing to FWDeck

Thanks for considering a contribution. Ground rules:

## Before you start

Open an issue for anything larger than a bugfix — architecture discussions
happen before code. Read the architecture section in [AGENTS.md](AGENTS.md) first; the layer
boundaries are enforced deliberately.

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
cargo test --test real_firewalld -- --ignored   # container only
```

All four must pass. `cargo test` must never touch the host firewall.

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
