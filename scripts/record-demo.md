# Recording the FWDeck demo cast

The README and landing page lead with a static screenshot, but FWDeck's most
compelling, most trust-building behavior — the dead-man's switch reverting a
change that would lock you out — is *motion*. A ~30 s [asciinema](https://asciinema.org)
cast of it is the single highest-leverage thing for adoption. Record it against
the dev container's real firewalld, which is fully isolated from your host.

## Setup

```bash
docker compose run --rm dev bash     # real firewalld, seeded, isolated
# inside the container:
asciinema rec -c "cargo run" fwdeck-demo.cast
```

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
agg fwdeck-demo.cast assets/demo.gif   # render to a GIF (github.com/asciinema/agg)
```

Embed `assets/demo.gif` at the top of `README.md` (in the "Why did I build it?"
section) and the landing hero (`site/index.html`), above or replacing the static
`zones.png`.
