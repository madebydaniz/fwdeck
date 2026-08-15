# Changelog

All notable changes to FWDeck are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [0.5.0](https://github.com/madebydaniz/fwdeck/compare/v0.4.0...v0.5.0) (2026-08-15)


### Features

* **ux:** conditional quit confirm, demo GIF hero, placeholder sweep ([#36](https://github.com/madebydaniz/fwdeck/issues/36)) ([4855a12](https://github.com/madebydaniz/fwdeck/commit/4855a1235c3749759e442aebb064cd69c0f835e0))
* **ux:** confirm quit only when it would revert or discard work ([878b48b](https://github.com/madebydaniz/fwdeck/commit/878b48b381bf968df2393556d046efabc14f2566))


### Bug Fixes

* **ui:** hide the arming rollback placeholder countdown ([a1a7177](https://github.com/madebydaniz/fwdeck/commit/a1a7177e72337fd33db40d48a4e7c0003205a5d0))


### Documentation

* drop unpublished install paths and stale placeholder content ([5fdf225](https://github.com/madebydaniz/fwdeck/commit/5fdf225b693f51be664b69c062f42428eae6bac2))
* lead with the dead-man's-switch demo GIF and recording tooling ([bdbf501](https://github.com/madebydaniz/fwdeck/commit/bdbf501d000c8b81cc976ec0c60575e1f5b16aa8))

## [0.4.0](https://github.com/madebydaniz/fwdeck/compare/v0.3.0...v0.4.0) (2026-07-29)


### Features

* install-method-aware upgrade guidance ([18b8931](https://github.com/madebydaniz/fwdeck/commit/18b8931dbe417c9e0a033b03771add25ed722db7))
* **ui:** show version in the header and add an About overlay ([5ee514b](https://github.com/madebydaniz/fwdeck/commit/5ee514b1ad9c433fdfe056f26893298416666948))
* **ui:** version display, About overlay, and install-aware upgrade guidance ([#33](https://github.com/madebydaniz/fwdeck/issues/33)) ([be9fcb1](https://github.com/madebydaniz/fwdeck/commit/be9fcb1aea48bae48ba276289b7774ccaaa37ab4))

## [0.3.0](https://github.com/madebydaniz/fwdeck/compare/v0.2.1...v0.3.0) (2026-07-28)


### Features

* **logs:** propose a scoped allow rule from a denied flow ([c00b6a5](https://github.com/madebydaniz/fwdeck/commit/c00b6a5956f207b59c3b1a5fbf1f5d287ca2d4f4))
* **logs:** propose an allow rule from a denied flow + offline dev container ([#31](https://github.com/madebydaniz/fwdeck/issues/31)) ([f1509a8](https://github.com/madebydaniz/fwdeck/commit/f1509a84d4d6183e5fca8e5bfff8bd3d908bfab0))

## [0.2.1](https://github.com/madebydaniz/fwdeck/compare/v0.2.0...v0.2.1) (2026-07-26)


### Bug Fixes

* **security:** clamp rollback window, guard nft path, sanitize stderr, bias uid ([2a5f8a9](https://github.com/madebydaniz/fwdeck/commit/2a5f8a9f0a86a6f3690839c8937c8cb2529476d6))
* warn and arm rollback on re-zoning, and show the offline command preview ([a1c1f93](https://github.com/madebydaniz/fwdeck/commit/a1c1f93e76dd91c6ab02232f309e74c3f1d55323))

## [0.2.0](https://github.com/madebydaniz/fwdeck/compare/v0.1.2...v0.2.0) (2026-07-26)


### Features

* **ui:** make undo discoverable and read-only self-explanatory ([5de8f58](https://github.com/madebydaniz/fwdeck/commit/5de8f58811e1a1be534767a39b259249f1507a6f))


### Bug Fixes

* arm the dead-man's switch on staged plans, restores, and bulk deletes ([43fbdca](https://github.com/madebydaniz/fwdeck/commit/43fbdca8388cbc0429ed1d71ff2f4f805422e48e))
* **concurrency:** drain events during sends and start the countdown on apply ([39c3caf](https://github.com/madebydaniz/fwdeck/commit/39c3caf3392aa3f137af490fffd31081ff4ffe94))
* extend the rollback net to reloads and independent countdowns ([64fcdb0](https://github.com/madebydaniz/fwdeck/commit/64fcdb03c8d12b95de23377da5bd1e145963f95b))
* **parse:** isolate zone parsing so one bad zone degrades only itself ([55caa5b](https://github.com/madebydaniz/fwdeck/commit/55caa5b44fc59a4c8e7d1c40f99270cb9f945fba))
* remove shipped placeholders before release ([f4792de](https://github.com/madebydaniz/fwdeck/commit/f4792def01101bc472651fe4d79494d47f0098fb))
* **security:** tighten cosign identity, watchdog PATH guard, audit honesty ([c2c86a4](https://github.com/madebydaniz/fwdeck/commit/c2c86a45ad7e6bc5e6bb94b3b40ecb1c5423ff5c))
* surface swallowed parse errors and bound startup probes ([c5ce7cb](https://github.com/madebydaniz/fwdeck/commit/c5ce7cb5743e75a2f5c27d3818060f842001c515))


### Refactoring

* **arch:** move shared value types to domain, document boundaries ([918a0a7](https://github.com/madebydaniz/fwdeck/commit/918a0a7a7f45f214107e7443e160229172633a8b))


### Documentation

* restructure README and fix crate metadata for release ([723433e](https://github.com/madebydaniz/fwdeck/commit/723433eab9163c39d9ce9faa5560b04afd00caec))

## [0.1.2](https://github.com/madebydaniz/fwdeck/compare/v0.1.1...v0.1.2) (2026-07-25)


### Bug Fixes

* **crate:** slim the published crate and enable crates.io publishing ([#11](https://github.com/madebydaniz/fwdeck/issues/11)) ([91741b1](https://github.com/madebydaniz/fwdeck/commit/91741b1d4099fc5fd9f5d9f25a9a5c965c2aced6))

## [0.1.1](https://github.com/madebydaniz/fwdeck/compare/v0.1.0...v0.1.1) (2026-07-25)


### Documentation

* align README/site — Workflows naming, undo key, dev notices, version badge ([#9](https://github.com/madebydaniz/fwdeck/issues/9)) ([e28f8b1](https://github.com/madebydaniz/fwdeck/commit/e28f8b1c03951838d2d5d27e2d736109949d2c56))

## 0.1.0 (2026-07-25)


### Features

* initial public release ([c969daf](https://github.com/madebydaniz/fwdeck/commit/c969dafab69dd7ee0c346bd7fd2e8ca8963f36db))
