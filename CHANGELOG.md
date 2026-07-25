# Changelog

All notable changes to FWDeck are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [0.1.2](https://github.com/madebydaniz/fwdeck/compare/v0.1.1...v0.1.2) (2026-07-25)


### Bug Fixes

* **crate:** slim the published crate and enable crates.io publishing ([#11](https://github.com/madebydaniz/fwdeck/issues/11)) ([91741b1](https://github.com/madebydaniz/fwdeck/commit/91741b1d4099fc5fd9f5d9f25a9a5c965c2aced6))

## [0.1.1](https://github.com/madebydaniz/fwdeck/compare/v0.1.0...v0.1.1) (2026-07-25)


### Documentation

* align README/site — Workflows naming, undo key, dev notices, version badge ([#9](https://github.com/madebydaniz/fwdeck/issues/9)) ([e28f8b1](https://github.com/madebydaniz/fwdeck/commit/e28f8b1c03951838d2d5d27e2d736109949d2c56))

## 0.1.0 (2026-07-25)


### Features

* initial public release ([c969daf](https://github.com/madebydaniz/fwdeck/commit/c969dafab69dd7ee0c346bd7fd2e8ca8963f36db))

## [Unreleased]

### Added

- Full read/write TUI for firewalld via the `firewall-cmd` backend:
  zones, services, ports, forward ports, rich rules, interfaces, sources,
  IP sets, direct rules (read-only), and a live kernel log view.
- Typed mutation pipeline: validation → confirmation (resource, zone, target,
  connectivity warning) → execution → honest outcome reporting, including
  `PartiallyApplied` with per-step invocations and rollback hints.
- Command palette with fuzzy search and context-aware availability; live row
  filtering; details overlays; toast notifications.
- Dracula theme with 256-color and no-color fallbacks; graceful narrow-terminal
  layout.
- Read-only mode enforced in the application layer; polkit/permission
  detection with actionable error details.
- SSH session detection with extra confirmation warnings.
- Panic mode, runtime-to-permanent, LogDenied control, firewalld reload.
- `fwdeck doctor` — read-only environment diagnosis.
- XDG config file with CLI overrides; file logging via `tracing`.
- Shell completions (`fwdeck completions`) and man page (`fwdeck manpage`).
- Timed rollback dead-man's switch, staged operation plans (export to
  firewall-cmd script / JSON), and a session + `audit.jsonl` audit trail.
- Clipboard yank (`Y`) via OSC 52; selectable themes (dracula / high-contrast /
  mono).
- ICMP-block management (block/unblock ICMP types per zone); Ansible playbook
  export.
- Service catalog browsing (all firewalld services with ports) and custom
  service definitions (create/delete, add/remove ports).
- Policy objects: browse, create/delete, set target, ingress/egress zones,
  add/remove services (the modern replacement for direct rules).
- Precise SSH-interface guard: names the SSH interface when an operation targets
  the zone governing it.
- Optional native D-Bus backend (`--features dbus`, `fwdeck --backend dbus`) —
  a second FirewallBackend implementation proving the trait boundary.
- Configuration snapshots: save the current state to timestamped JSON, browse
  saved snapshots, and restore (diff a snapshot into a reviewable staged plan;
  deserialization re-validates every value).
- Zone Overview: Enter on a zone opens a composite per-zone view showing runtime
  vs permanent drift per attribute.
- Offline mode (`--offline`, `firewall-offline-cmd`) for managing the permanent
  config when the daemon is down.
- Multi-select (`space`) with bulk delete; guided rich-rule builder; clone (`c`)
  an entry into a prefilled add form. (Masquerade toggle moved to `m`.)

### Fixed (external production review)

- Desired-state targeting: Both-scoped edits narrow to the scope that needs
  them; staged plans re-narrow and skip already-satisfied operations at apply.
- Restore diffs runtime and permanent independently (no Both contamination).
- Transactional plan apply: sequential, fail-fast, single refresh, unexecuted
  operations re-staged — never silently dropped.
- Rollback: pending inverses are a stack, mutation sends can no longer be
  dropped by a full queue, and quitting inside the countdown fires the
  inverses before exit.
- Offline mode rejects runtime-targeted edits and forces the permanent target.
- Degraded sections (ipsets/policies/direct/services fetch failures) are
  reported in the snapshot and shown in the breadcrumb — unknown ≠ empty.
- Zones view: the drift (≠) column has a header again (headers were shifted).
- Child processes run from trusted absolute paths with a cleared environment;
  snapshots/audit live in 0700/0600 files, snapshots written atomically.
- Release binaries: pinned toolchain, dbus feature included; installer detects
  musl; real-firewalld container suite runs in CI (Fedora 44 / firewalld 2.4.4
  verified alongside 2.3.2).
- Rustdoc for the full public API; `#![warn(missing_docs)]` + clippy
  `-D warnings` now gate it.

### Fixed (senior review hardening)

- D-Bus backend rejects non-runtime targets instead of silently dropping the
  permanent half; snapshot errors propagate instead of defaulting fields;
  error mapping uses structured D-Bus error names; failed steps carry the
  failing method for the audit trail.
- Multi-select marks the exact row, not every row sharing a first cell.
- Snapshot restore narrows zones absent from runtime to permanent-only,
  avoiding INVALID_ZONE from staged plans.
- Offline mode reports reload/runtime-to-permanent as unsupported.
- Bulk delete supports forwarding and source rows.

### Performance

- CLI snapshot fetches per-ipset/policy/service info concurrently — refresh no
  longer scales serially with object count (~100 ms per firewall-cmd spawn).
- D-Bus snapshot parallelizes per-zone reads (~10x fewer sequential
  round-trips).
- Docker-based development environment with a real firewalld daemon;
  fixture-based parser tests captured from firewalld 2.3.2; real-daemon
  integration tests (opt-in, container-only).
