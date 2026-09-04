//! Live rule-hit counters from the nftables backend.
//!
//! Reads `nft -j list ruleset` (libnftables JSON — structured and stable,
//! unlike the text `firewall-cmd` output) and aggregates the per-rule `counter`
//! statements by nft chain. firewalld only attaches counters to *some* rules
//! (logging, rich rules, and when counters are enabled), so an empty result is
//! normal, not an error. Counters come straight from the kernel, so they are
//! only visible with the nftables backend and sufficient privilege.
//!
//! The chain name (`filter_IN_public`, `filter_FWD_public`, …) already carries
//! the hook and zone, so counts are keyed on it verbatim — no fragile chain
//! name re-parsing that would drift across firewalld versions.

use std::collections::BTreeMap;

use crate::domain::ChainCounter;
use crate::infrastructure::process::{
    CommandRequest, CommandRunner, DEFAULT_TIMEOUT, TokioRunner, resolve_trusted,
};

/// Runs `nft -j list ruleset` and returns per-chain counters, busiest first.
///
/// # Errors
/// Returns an error string when `nft` is missing, not permitted, or emits
/// output that is not valid libnftables JSON.
pub async fn read() -> Result<Vec<ChainCounter>, String> {
    // Resolve `nft` from trusted dirs with a cleared environment — this may run
    // as root, so a poisoned PATH must not choose the binary.
    let nft = resolve_trusted("nft");
    if !nft.is_absolute() {
        return Err("nft not found in a trusted directory".to_owned());
    }
    read_with(&TokioRunner).await
}

async fn read_with<R: CommandRunner>(runner: &R) -> Result<Vec<ChainCounter>, String> {
    let output = runner
        .run(CommandRequest {
            program: "nft",
            args: vec!["-j".to_owned(), "list".to_owned(), "ruleset".to_owned()],
            timeout: DEFAULT_TIMEOUT,
        })
        .await
        .map_err(|error| format!("nft unavailable: {error}"))?;
    if output.exit_code != Some(0) {
        let stderr = output.stderr.trim();
        return Err(if stderr.is_empty() {
            "nft failed (need root and the nftables backend)".to_owned()
        } else {
            format!("nft failed: {stderr}")
        });
    }
    parse(&output.stdout)
}

/// Parses libnftables JSON and aggregates `counter` statements by chain, for
/// rules in the `firewalld` table. Pure — the fixture-testable core of [`read`].
pub fn parse(json: &str) -> Result<Vec<ChainCounter>, String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|err| format!("invalid nft JSON: {err}"))?;
    let items = value
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "unexpected nft JSON: no `nftables` array".to_owned())?;

    let mut totals: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for item in items {
        let Some(rule) = item.get("rule") else {
            continue;
        };
        // firewalld's own table only — skip anything another tool installed.
        if rule.get("table").and_then(serde_json::Value::as_str) != Some("firewalld") {
            continue;
        }
        let Some(chain) = rule.get("chain").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(exprs) = rule.get("expr").and_then(serde_json::Value::as_array) else {
            continue;
        };
        for expr in exprs {
            if let Some(counter) = expr.get("counter") {
                let packets = counter
                    .get("packets")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                let bytes = counter
                    .get("bytes")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                let entry = totals.entry(chain.to_owned()).or_default();
                entry.0 = entry.0.saturating_add(packets);
                entry.1 = entry.1.saturating_add(bytes);
            }
        }
    }

    let mut counters: Vec<ChainCounter> = totals
        .into_iter()
        .map(|(chain, (packets, bytes))| ChainCounter {
            chain,
            packets,
            bytes,
        })
        .collect();
    // Busiest chains first.
    counters.sort_by(|a, b| {
        b.packets
            .cmp(&a.packets)
            .then_with(|| a.chain.cmp(&b.chain))
    });
    Ok(counters)
}

#[cfg(test)]
#[allow(unknown_lints, clippy::unused_async_trait_impl, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::infrastructure::process::{CommandOutput, ProcessError};
    use std::sync::Mutex;

    struct FakeRunner {
        response: Mutex<Option<Result<CommandOutput, ProcessError>>>,
        seen: Mutex<Vec<CommandRequest>>,
    }

    impl FakeRunner {
        fn new(response: Result<CommandOutput, ProcessError>) -> Self {
            Self {
                response: Mutex::new(Some(response)),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl CommandRunner for FakeRunner {
        async fn run(&self, request: CommandRequest) -> Result<CommandOutput, ProcessError> {
            self.seen.lock().unwrap().push(request);
            self.response.lock().unwrap().take().unwrap()
        }
    }

    // Mirrors the libnftables JSON schema (`nft -j list ruleset`). The real
    // fixture is captured in the dev container by the real_firewalld suite;
    // this sample pins the parser's shape.
    const SAMPLE: &str = r#"{
      "nftables": [
        { "metainfo": { "version": "1.0.9", "release_name": "Old Doc Yak", "json_schema_version": 1 } },
        { "table": { "family": "inet", "name": "firewalld", "handle": 1 } },
        { "chain": { "family": "inet", "table": "firewalld", "name": "filter_IN_public", "handle": 10 } },
        { "rule": { "family": "inet", "table": "firewalld", "chain": "filter_IN_public", "handle": 11,
            "expr": [ { "counter": { "packets": 40, "bytes": 3200 } }, { "accept": null } ] } },
        { "rule": { "family": "inet", "table": "firewalld", "chain": "filter_IN_public", "handle": 12,
            "expr": [ { "counter": { "packets": 2, "bytes": 120 } }, { "drop": null } ] } },
        { "rule": { "family": "inet", "table": "firewalld", "chain": "filter_FWD_public", "handle": 13,
            "expr": [ { "counter": { "packets": 500, "bytes": 60000 } }, { "accept": null } ] } },
        { "rule": { "family": "inet", "table": "other", "chain": "x", "handle": 1,
            "expr": [ { "counter": { "packets": 999, "bytes": 999 } } ] } }
      ]
    }"#;

    #[tokio::test]
    async fn counter_read_uses_the_bounded_process_runner() {
        let runner = FakeRunner::new(Ok(CommandOutput {
            exit_code: Some(0),
            stdout: SAMPLE.to_owned(),
            stderr: String::new(),
            duration: std::time::Duration::ZERO,
        }));

        let counters = read_with(&runner).await.unwrap();

        assert!(!counters.is_empty());
        assert_eq!(
            runner.seen.lock().unwrap().as_slice(),
            [CommandRequest {
                program: "nft",
                args: vec!["-j".to_owned(), "list".to_owned(), "ruleset".to_owned()],
                timeout: DEFAULT_TIMEOUT,
            }]
        );
    }

    #[tokio::test]
    async fn counter_timeout_is_reported_without_parsing() {
        let runner = FakeRunner::new(Err(ProcessError::Timeout(DEFAULT_TIMEOUT)));
        let error = read_with(&runner).await.unwrap_err();
        assert!(error.contains("timed out"));
    }

    #[test]
    fn aggregates_counters_per_firewalld_chain_busiest_first() {
        let counters = parse(SAMPLE).unwrap();
        assert_eq!(
            counters.len(),
            2,
            "two firewalld chains, `other` table ignored"
        );
        // FWD is busiest.
        assert_eq!(counters[0].chain, "filter_FWD_public");
        assert_eq!(counters[0].packets, 500);
        // IN aggregates its two rules (40 + 2, 3200 + 120).
        assert_eq!(counters[1].chain, "filter_IN_public");
        assert_eq!(counters[1].packets, 42);
        assert_eq!(counters[1].bytes, 3320);
    }

    #[test]
    fn no_counters_is_empty_not_an_error() {
        let empty = r#"{ "nftables": [ { "metainfo": { "version": "1.0.9" } } ] }"#;
        assert!(parse(empty).unwrap().is_empty());
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(parse("not json").is_err());
        assert!(parse(r#"{ "wat": [] }"#).is_err());
    }
}
