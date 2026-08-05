//! Read-only observations the UI displays: refresh health, parsed kernel-log
//! lines, and nft per-chain hit counters. Pure value types (no I/O) — adapters
//! produce them and the application transports them inward-to-outward.

use std::time::Duration;

/// Logical part of one firewall snapshot refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RefreshSection {
    /// Daemon state, version, panic mode, and log-denied state.
    Status,
    /// Default zone, active bindings, and runtime/permanent zone data.
    Zones,
    /// Runtime and permanent IP sets.
    IpSets,
    /// Available and referenced service definitions.
    Services,
    /// Runtime and permanent policies.
    Policies,
    /// Deprecated direct-interface rules.
    DirectRules,
}

impl RefreshSection {
    /// Stable operator-facing label used by Doctor and diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Zones => "zones",
            Self::IpSets => "ipsets",
            Self::Services => "services",
            Self::Policies => "policies",
            Self::DirectRules => "direct rules",
        }
    }
}

/// Adapter-reported work for one logical refresh section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshSectionObservation {
    /// Section that was fetched.
    pub section: RefreshSection,
    /// Aggregate wall time spent fetching this section.
    pub elapsed: Duration,
    /// Number of external processes issued for this section.
    pub process_count: u64,
}

/// Operational telemetry for one completed or failed snapshot read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshObservation {
    /// End-to-end wall time observed at the backend boundary.
    pub elapsed: Duration,
    /// Total external process count, when the adapter can report it.
    pub process_count: Option<u64>,
    /// Per-section observations in stable section order.
    pub sections: Vec<RefreshSectionObservation>,
}

impl RefreshObservation {
    /// Creates an adapter-specific observation with stable section ordering.
    #[must_use]
    pub fn new(
        elapsed: Duration,
        process_count: u64,
        mut sections: Vec<RefreshSectionObservation>,
    ) -> Self {
        sections.sort_by_key(|section| section.section);
        Self {
            elapsed,
            process_count: Some(process_count),
            sections,
        }
    }

    /// Creates a portable total-only observation for adapters without process
    /// or logical-section instrumentation.
    #[must_use]
    pub const fn total_only(elapsed: Duration) -> Self {
        Self {
            elapsed,
            process_count: None,
            sections: Vec::new(),
        }
    }
}

/// Netfilter verdict extracted from a kernel log line's rule-name prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{RefreshObservation, RefreshSection, RefreshSectionObservation};

    #[test]
    fn refresh_observation_sorts_sections_and_preserves_totals() {
        let observation = RefreshObservation::new(
            Duration::from_millis(42),
            7,
            vec![
                RefreshSectionObservation {
                    section: RefreshSection::Services,
                    elapsed: Duration::from_millis(9),
                    process_count: 3,
                },
                RefreshSectionObservation {
                    section: RefreshSection::Status,
                    elapsed: Duration::from_millis(4),
                    process_count: 4,
                },
            ],
        );

        assert_eq!(observation.elapsed, Duration::from_millis(42));
        assert_eq!(observation.process_count, Some(7));
        assert_eq!(
            observation
                .sections
                .iter()
                .map(|section| section.section)
                .collect::<Vec<_>>(),
            vec![RefreshSection::Status, RefreshSection::Services]
        );
    }
}
