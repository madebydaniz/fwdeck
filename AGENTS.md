# FWDeck Project Overview

This document provides context about the FWDeck project for the different agents.

## Project Overview

FWDeck is a safety-first terminal UI (TUI) for managing Linux **firewalld**,
inspired by k9s and lazygit. It is a single Rust crate (edition 2024,
MSRV 1.88) producing one binary: `fwdeck`.

- **TUI:** ratatui + crossterm (`EventStream`), Dracula theme with fallbacks
- **Async runtime:** tokio (single engine task, bounded mpsc channels)
- **Backends:** `firewall-cmd` CLI (default), native D-Bus via zbus (optional
  `dbus` cargo feature), `firewall-offline-cmd` (offline mode)
- **Errors:** thiserror in the library, anyhow only in `main`
- **Serialization:** serde + serde_json (snapshots, audit trail)

## Architecture (hexagonal — respect the layer boundaries)

```
src/domain/          Pure types. No I/O, no tokio. Newtypes (ZoneName, PortSpec, …),
                     FirewallSnapshot, FirewallOperation (validate/describe/inverse),
                     restore diff engine. Validating serde Deserialize.
src/application/     ports.rs: the FirewallBackend trait (async fn via
                     `-> impl Future + Send`, engine generic over B — no dyn).
                     engine.rs: the single async task; UI talks to it via channels.
src/infrastructure/  Adapters: firewalld/ (command.rs = the ONLY place argv is
                     built; parse.rs = fixture-tested parsers; dbus.rs; errors.rs),
                     process.rs (CommandRunner), logs.rs, audit.rs, snapshot_store.rs.
src/ui/              TEA: action.rs → update.rs (pure reducer) → render.
                     keymap, palette, views, overlays, details, theme.
src/main.rs          Wiring + doctor/completions/manpage subcommands.
```

## Non-negotiable rules

- **No `unwrap`/`expect`/`panic!` in production paths** (clippy denies them;
  tests may `#[allow]`).
- **No shell interpolation, ever.** Commands are argv vectors through
  `CommandRunner`. All *firewalld mutation* argv is built in
  `src/infrastructure/firewalld/command.rs`. A few read-only/auxiliary probes
  build their own argv deliberately outside it — the systemd-run rollback
  watchdog (`infrastructure/rollback.rs`), `nft` counters (`counters.rs`), and the `ip`/
  `systemctl` startup probes — because they are not firewalld operations; they
  still go through `resolve_trusted` + a cleared env, never a shell.
- **Honest reporting:** a change that applied to runtime but failed for
  permanent is `PartiallyApplied`, never success. Don't silently drop the
  permanent half of an operation.
- **Runtime vs permanent must stay distinguishable** in every view and result.
- **Rich rules are verbatim strings** — never reconstruct them from parsed parts.
- **Parsers are verified against real firewalld output** captured in the dev
  container (`tests/fixtures/firewall_cmd/`) — never hand-typed. Don't invent
  firewalld CLI/D-Bus APIs; verify against the real daemon first.
- Every mutation goes through validation → confirmation modal → apply.
  Destructive/risky operations use the rollback (dead-man's switch) flow.
- **Shared value types the UI reads** (`LogEntry`, `LogAction`, `ChainCounter`)
  live in `src/domain/observation.rs` so the dependency arrow points inward.
  `ExportFormat` stays in `command.rs` on purpose — its `render()` generates
  `firewall-cmd`/Ansible scripts, which is command-building, not a value type.
- **Leaf I/O helpers** (`audit`, `counters`, `snapshot_store`, `export_write`)
  return `Result<_, String>`: their error is only ever shown to the operator as
  a toast, so a typed `thiserror` layer would add ceremony with no behavioral
  benefit. Use `thiserror` in the library where callers actually *match* on the
  variant (the firewalld/domain errors do).

## Development Workflow

Development runs against a **real firewalld** in a disposable Fedora container
(the host firewall is never touched; macOS hosts work fine):

```bash
docker compose run --rm dev        # Fedora + firewalld + Rust, repo mounted
cargo run                          # inside: the TUI with real seeded data
```

### Common Commands

- `cargo test` — full suite (fixtures + fake runner + reducer tests; never
  touches a real firewall).
- `cargo test --test real_firewalld -- --ignored --test-threads=1` —
  real-daemon integration tests, **container only**, must run serially.
- `cargo fmt --all -- --check` — formatting gate.
- `cargo clippy --all-targets -- -D warnings` — lint gate (pedantic warns on).
- `cargo clippy --all-targets --features dbus -- -D warnings` — the D-Bus
  backend must also stay clean.
- `cargo build --features dbus` — build with the native D-Bus backend.
- `./scripts/preview-site.sh` — assemble and open the website locally
  (site/ references assets/ which only exists in the deployed artifact).

All four gates (fmt, clippy both feature sets, tests, MSRV 1.88 check) are
enforced in CI along with cargo-deny and CodeQL.

## Releases

- **Conventional Commits are required** (`feat:`, `fix:`, `perf:`, …) —
  release-please turns them into release PRs and the changelog; merging
  publishes a GitHub Release, and `release-binaries` builds 4 Linux targets,
  generates checksums, and signs them with Cosign keyless (Sigstore).
- Never edit `CHANGELOG.md` version sections by hand; release-please owns them.

## Docs & website

- `README.md` — storefront: screenshot, feature list, links into the docs site.
- `site/` — landing page + `site/docs/` documentation (plain HTML, no build
  step), deployed by `.github/workflows/pages.yml` together with `assets/`.
- Screenshots live in `assets/` (one per view, kebab-case names).

## Other info

- Config: `~/.config/fwdeck/config.toml` (XDG); state (logs, audit JSONL,
  snapshots, exports): `~/.local/state/fwdeck/`.
- Unprivileged runs degrade to read-only; FWDeck never re-executes itself
  with sudo.
- firewalld semantics worth knowing: exit 252 = daemon not running,
  253 = not authorized; `--new-zone`/`--new-ipset`/`--new-service`/
  `--new-policy` are permanent-only (reload to activate); `--query-panic`
  exit 1 means "off", not an error.
