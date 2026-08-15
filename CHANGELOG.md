# Changelog

All notable changes to FWDeck are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [0.5.0](https://github.com/madebydaniz/fwdeck/compare/v0.4.0...v0.5.0) (2026-08-15)


### Features

* **observability:** Report refresh performance metrics ([2131e47](https://github.com/madebydaniz/fwdeck/commit/2131e473041ec18c8538271bf0e2e70cc1c128c4))
* **observability:** Report refresh performance metrics ([#39](https://github.com/madebydaniz/fwdeck/issues/39)) ([a58505c](https://github.com/madebydaniz/fwdeck/commit/a58505c90195abd743b1b061616dea6ada59ba30))
* **observability:** report refresh scheduling outcomes ([2da503f](https://github.com/madebydaniz/fwdeck/commit/2da503ff2597b32a2d3095410c242ef4e84e2d72))
* **plan:** identify plan completion events ([14e8fd8](https://github.com/madebydaniz/fwdeck/commit/14e8fd85432a5837627e33caae4e9e8980f5c99a))
* **policy:** Add capability-gated policy sets ([d263c21](https://github.com/madebydaniz/fwdeck/commit/d263c2179abcc9391f06fcc57afbd496d16f2706))
* **policy:** Add dependency-safe deletion ([7cb98f8](https://github.com/madebydaniz/fwdeck/commit/7cb98f8af62eb1243673773edf1e1f2f2c42263a))
* **policy:** Add direct-rule migration assistant ([f708744](https://github.com/madebydaniz/fwdeck/commit/f708744ec4dd9355927fdc7fff6d9d339a0fab17))
* **policy:** Add first-class policy workspace ([4814cfd](https://github.com/madebydaniz/fwdeck/commit/4814cfdead780c83af99efbc2ded32ff094a1373))
* **refresh:** add cancellable refresh scheduler ([#42](https://github.com/madebydaniz/fwdeck/issues/42)) ([63cf81c](https://github.com/madebydaniz/fwdeck/commit/63cf81c30e7fe620548da79c76073162fbf0212e))
* **refresh:** add pure scheduling policy ([1f7a219](https://github.com/madebydaniz/fwdeck/commit/1f7a2192f2a3b98a911e3b5d5ead8831b45cbfd7))
* **refresh:** define scheduler lifecycle metadata ([cd2d3de](https://github.com/madebydaniz/fwdeck/commit/cd2d3de90d061e7cb5494d89ff16c7a65329835f))
* **refresh:** preempt ordinary reads for mutations ([8d267a1](https://github.com/madebydaniz/fwdeck/commit/8d267a1710c70f1e5147beee188b8c80b44d9a2c))
* **state:** Add bounded enterprise retention ([df9ad52](https://github.com/madebydaniz/fwdeck/commit/df9ad52fcb1efc95c2e8a3a5f958b95f179e7db0))
* **ui:** add bounded engine outbox protocol ([9efd40c](https://github.com/madebydaniz/fwdeck/commit/9efd40cb1903069ed5eec67c75d3a51dcce29139))
* **ui:** Add typed row identities ([eec874f](https://github.com/madebydaniz/fwdeck/commit/eec874f4e31124c60222d4b0bf8ff40384f6d8b6))
* **ux:** conditional quit confirm, demo GIF hero, placeholder sweep ([#36](https://github.com/madebydaniz/fwdeck/issues/36)) ([4855a12](https://github.com/madebydaniz/fwdeck/commit/4855a1235c3749759e442aebb064cd69c0f835e0))
* **ux:** confirm quit only when it would revert or discard work ([878b48b](https://github.com/madebydaniz/fwdeck/commit/878b48b381bf968df2393556d046efabc14f2566))


### Bug Fixes

* **ci:** Create D-Bus coverage report directory ([f7b43f1](https://github.com/madebydaniz/fwdeck/commit/f7b43f1b0ccbfca9a12282939d0265cf87d1f311))
* **ci:** Refresh D-Bus job action pin ([f7cd7f2](https://github.com/madebydaniz/fwdeck/commit/f7cd7f271ca06f94b35a12e8b74578a65e82f285))
* **refresh:** guarantee bounded post-mutation reconciliation ([5ab4415](https://github.com/madebydaniz/fwdeck/commit/5ab4415035999c760b13ef5ab052a6554bf16356))
* **refresh:** preserve rollback priority during reconciliation ([d45c810](https://github.com/madebydaniz/fwdeck/commit/d45c81064023b2c46fd1f2496afd404653c9dd4f))
* **refresh:** reserve rollback capacity under saturation ([46306bb](https://github.com/madebydaniz/fwdeck/commit/46306bb02b989b8ff5e7af5b4ccef87de498bea8))
* **safety:** Arm rollback guards per operation ([842b1fe](https://github.com/madebydaniz/fwdeck/commit/842b1fe4b89d4a8d5f2ad4fb0721a51d18017b3f))
* **safety:** Harden operational mutation boundaries ([d6bd0c7](https://github.com/madebydaniz/fwdeck/commit/d6bd0c72c1e9aba73f3452cc3a9b2899dc2d49d7))
* **safety:** Reject stale mutation requests ([8457d99](https://github.com/madebydaniz/fwdeck/commit/8457d99d97e323557ee2d3cc2aed1e8f5369c672))
* **safety:** Release instance locks explicitly ([c83cdc1](https://github.com/madebydaniz/fwdeck/commit/c83cdc1338c34ed714c5c50bfaea2161bfa4525b))
* **state:** Preserve runtime and permanent object scopes ([49ca476](https://github.com/madebydaniz/fwdeck/commit/49ca476bfcbc3c34b93d66ca639ea0ec4a5c262f))
* **ui:** gate mutations on bounded outbox capacity ([88b7a7a](https://github.com/madebydaniz/fwdeck/commit/88b7a7a750d8b3bdecefd3dc588571ec9829cec6))
* **ui:** hide the arming rollback placeholder countdown ([a1a7177](https://github.com/madebydaniz/fwdeck/commit/a1a7177e72337fd33db40d48a4e7c0003205a5d0))
* **ui:** keep dialogs at seventy percent width ([1ba9d49](https://github.com/madebydaniz/fwdeck/commit/1ba9d49b1bb49a4e5b646217c0babb76ced4fc6d))
* **ui:** keep palette selection visible ([36ee245](https://github.com/madebydaniz/fwdeck/commit/36ee245f1f1e0ffbf5ca8cd8a6e21d73717ec19b))
* **ui:** keep rollback ticks live under backpressure ([ee20d75](https://github.com/madebydaniz/fwdeck/commit/ee20d75b46bd03dc460d7742279bd17560238ddb))
* **ui:** make dialogs responsive and readable ([87edce9](https://github.com/madebydaniz/fwdeck/commit/87edce9ce74c6a1a1e611c220f5722e4c7653581))
* **ui:** preserve manual batch lifecycle state ([2643c9c](https://github.com/madebydaniz/fwdeck/commit/2643c9ce87ede7084bb2e8d744b37a0b680b8b0e))
* **ui:** reconcile rollback reservation accounting ([a08e0eb](https://github.com/madebydaniz/fwdeck/commit/a08e0ebe18b57e0d4bb1c07d3b50b183490f561e))
* **ui:** serialize plan submission accounting ([aea51c0](https://github.com/madebydaniz/fwdeck/commit/aea51c0c4fc8dacc154b6dfd33bfaaac485598be))
* **ui:** track refresh lifecycles by identity ([073d038](https://github.com/madebydaniz/fwdeck/commit/073d0383d931d4d361056f64595393db47e0122d))
* **ui:** wrap remaining text dialogs ([3060a28](https://github.com/madebydaniz/fwdeck/commit/3060a28a3af40090007391ab1cdbe50034970026))


### Performance

* **refresh:** stage prioritized firewall details ([#44](https://github.com/madebydaniz/fwdeck/issues/44)) ([4eb614a](https://github.com/madebydaniz/fwdeck/commit/4eb614a210e72fcae6d32c6fe2f824e61ffcf139))


### Documentation

* **dbus:** Document coverage workflow ([c3f2676](https://github.com/madebydaniz/fwdeck/commit/c3f26763e5f1ea76817b633c64c9c53b2d880e71))
* drop unpublished install paths and stale placeholder content ([5fdf225](https://github.com/madebydaniz/fwdeck/commit/5fdf225b693f51be664b69c062f42428eae6bac2))
* lead with the dead-man's-switch demo GIF and recording tooling ([bdbf501](https://github.com/madebydaniz/fwdeck/commit/bdbf501d000c8b81cc976ec0c60575e1f5b16aa8))
* **refresh:** document bounded scheduler behavior ([0b21c0f](https://github.com/madebydaniz/fwdeck/commit/0b21c0f62da2c09dbe36b18fa3722abbbf342952))
* **site:** add the social-preview card and og meta tags ([ebcafb5](https://github.com/madebydaniz/fwdeck/commit/ebcafb53e5674b64eb166fd83b070f3c2ee19302))
* update policies and refresh behavior ([959b004](https://github.com/madebydaniz/fwdeck/commit/959b004122ace6b373eddaebf75abcca95430c6a))

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
