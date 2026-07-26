//! Read-only observations the UI displays: parsed kernel-log lines and nft
//! per-chain hit counters. Pure value types (no I/O) — the parsing that
//! produces them lives in the infrastructure adapters (`logs`, `counters`).

/// Netfilter verdict extracted from a kernel log line's rule-name prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogAction {
    /// Packet was accepted (`ACCEPT` / `ALLOW` in the prefix).
    Accept,
    /// Packet was silently dropped (`DROP` / `DENIED`).
    Drop,
    /// Packet was rejected with an error response (`REJECT`).
    Reject,
    /// Line matched the netfilter format but named no known verdict.
    Unknown,
}

impl LogAction {
    /// Short display label (`"ACCEPT"`, `"DROP"`, `"REJECT"`, `"?"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "ACCEPT",
            Self::Drop => "DROP",
            Self::Reject => "REJECT",
            Self::Unknown => "?",
        }
    }

    /// Whether the packet was blocked (`Drop` or `Reject`).
    #[must_use]
    pub const fn is_denied(self) -> bool {
        matches!(self, Self::Drop | Self::Reject)
    }
}

/// One parsed netfilter log line, ready for the Logs view. Fields keep the
/// kernel's string form; missing fields are empty strings, not errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// `HH:MM:SS` slice of the source timestamp (full token if not ISO-shaped).
    pub time: String,
    /// Verdict inferred from the rule-name prefix.
    pub action: LogAction,
    /// Source address (`SRC=`).
    pub src: String,
    /// Destination address (`DST=`).
    pub dst: String,
    /// Destination port (`DPT=`), empty for portless protocols like ICMP.
    pub dport: String,
    /// Protocol (`PROTO=`), e.g. `TCP`/`UDP`.
    pub proto: String,
    /// Ingress interface (`IN=`).
    pub iface: String,
}

/// Aggregated hit counter for one nft chain in the `firewalld` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainCounter {
    /// The nft chain name (e.g. `filter_IN_public`).
    pub chain: String,
    /// Total packets matched by countered rules in this chain.
    pub packets: u64,
    /// Total bytes matched by countered rules in this chain.
    pub bytes: u64,
}
