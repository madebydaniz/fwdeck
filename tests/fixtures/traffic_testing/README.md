# Traffic-testing fixtures

These documents are manually reviewed semantic evidence for the traffic-testing foundation.
They are intentionally checked in and must never be regenerated silently from a live daemon.

## Review contract

- `schema_version` is the loader contract. A schema change requires an explicit test and review.
- `fixture_version` identifies the reviewed dataset independently of the application version.
- `reviewed_on` records the latest manual semantic review.
- `sources` contains primary firewalld documentation used to review the expected meaning.
- Observation fixtures are deterministic inputs, not captured runtime output.
- Generated fuzz corpora and local experiment output do not belong in this directory.

## Documents

- `capability_thresholds.json` - reviewed upstream release thresholds.
- `rich_rules/` - raw supported, unsupported, and malformed rich-rule seeds.
- `observation/zone-observation.json` - runtime/permanent priority and degraded-evidence cases.
- `observation/service-evidence.json` - complete service fields and include failures.
- `observation/semantic-classification.json` - rich-rule and operation-effect classifications.

Changes require exact structural tests in `tests/traffic_testing_foundation.rs` and manual source review.
