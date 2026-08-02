# Recording the FWDeck demo cast

The README and landing page lead with `assets/demo.gif`: FWDeck's most
compelling, most trust-building behavior — the dead-man's switch reverting a
change that would lock you out — is *motion*. This guide is how to re-record
that cast (for a new release or a better take) against the dev container's
real firewalld, which is fully isolated from your host.

## Setup

asciinema runs on the **host** and records the terminal; the TUI inside the
container renders into that same terminal, so nothing needs to be installed in
the image. `make record-demo` wraps it all (offline build from the host cargo
cache, plus `scripts/demo-config.toml` for a GIF-friendly 10 s rollback window):

```bash
brew install asciinema agg   # once, on the host
make record-demo             # play the scenario below, then quit the app
```

The cast records at your terminal's natural size (asciinema's `--window-size`
is deliberately not used — its intermediary terminal layer lags the TUI).
Aim for roughly 120–140 columns: in most terminals, bump the font size until
`stty size` reports about `34 130`.

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

`assets/demo.gif` is already embedded as the hero of `README.md` and the
landing page (`site/index.html`) — committing the regenerated file updates
both. If the first/last frames carry startup or exit noise, trim them:

```bash
gifsicle --colors=255 assets/demo.gif -o /tmp/demo-c255.gif
gifsicle -U /tmp/demo-c255.gif "#5--2" -O2 -o assets/demo.gif
```
