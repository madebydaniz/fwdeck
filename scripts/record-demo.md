# Recording the FWDeck demo cast

The README and landing page lead with a static screenshot, but FWDeck's most
compelling, most trust-building behavior — the dead-man's switch reverting a
change that would lock you out — is *motion*. A ~30 s [asciinema](https://asciinema.org)
cast of it is the single highest-leverage thing for adoption. Record it against
the dev container's real firewalld, which is fully isolated from your host.

## Setup

asciinema runs on the **host** and records the terminal; the TUI inside the
container renders into that same terminal, so nothing needs to be installed in
the image. `make record-demo` wraps it all (offline build from the host cargo
cache, plus `scripts/demo-config.toml` for a GIF-friendly 10 s rollback window):

```bash
brew install asciinema agg   # once, on the host
make record-demo             # play the scenario below, then quit the app
```

The target passes `--window-size 100x30`, so the cast records at exactly
100×30 regardless of your actual terminal size — no resizing needed.

## The scenario (the story the cast should tell)

1. **Zones** open on launch — note `public (active, default)`; that zone carries
   the SSH session.
2. Press `1` → **Services**, select `ssh`.
3. Press `d` (remove). The confirmation shows the exact `firewall-cmd`
   invocation **and** the precise warning:
   `⚠ zone \`public\` protects your SSH session (…) — you may cut your own connection`.
4. Press `y` to apply. The status bar starts a **countdown**:
   `auto-rollback in Ns … y keep · u undo now`.
5. Do nothing. Let the countdown expire → FWDeck **auto-reverts** and `ssh` is
   back. (Pressing `u` reverts immediately; `y` would have kept it.)

That arc — risky change → precise SSH warning → apply → countdown → automatic
recovery — is the whole product in half a minute.

## Publish

```bash
agg --theme dracula fwdeck-demo.cast assets/demo.gif
ls -lh assets/demo.gif   # keep it under ~2 MB so GitHub autoplays it
# too big? re-render faster: agg --theme dracula --speed 1.5 ...
```

Embed `assets/demo.gif` at the top of `README.md` (in the "Why did I build it?"
section) and the landing hero (`site/index.html`), above or replacing the static
`zones.png`.
