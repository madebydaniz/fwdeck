//! One immutable view of the complete firewall state. The UI only ever reads
//! from a snapshot; refreshes replace the whole thing atomically.

use std::collections::BTreeMap;

use super::ids::{IpSetName, PolicyName, ServiceName, ZoneName};
use super::policy::PolicyDetails;
use super::port::PortSpec;
use super::zone::{ActiveZone, ZoneDetails};

/// Which configuration a query or mutation applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum ConfigurationTarget {
    /// The live in-kernel configuration; lost on reload or daemon restart.
    Runtime,
    /// The on-disk configuration; takes effect after a reload.
    Permanent,
    /// Both at once — the default for mutations, so changes apply now *and*
    /// survive a reload.
    #[default]
    RuntimeAndPermanent,
}

impl ConfigurationTarget {
    /// Human-readable label for modal and toast text.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Permanent => "permanent",
            Self::RuntimeAndPermanent => "runtime + permanent",
        }
    }
}

/// firewalld's `LogDenied` setting.
// Non-default variants are constructed by the CLI parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum LogDenied {
    /// Denied packets are not logged.
    #[default]
    Off,
    /// Log every denied packet.
    All,
    /// Log denied unicast packets only.
    Unicast,
    /// Log denied broadcast packets only.
    Broadcast,
    /// Log denied multicast packets only.
    Multicast,
}

impl LogDenied {
    /// The spelling `firewall-cmd --set-log-denied` accepts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::All => "all",
            Self::Unicast => "unicast",
            Self::Broadcast => "broadcast",
            Self::Multicast => "multicast",
        }
    }
}

impl std::str::FromStr for LogDenied {
    type Err = super::ids::ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "off" => Ok(Self::Off),
            "all" => Ok(Self::All),
            "unicast" => Ok(Self::Unicast),
            "broadcast" => Ok(Self::Broadcast),
            "multicast" => Ok(Self::Multicast),
            _ => Err(super::ids::ValidationError::InvalidLogDenied(s.to_owned())),
        }
    }
}

/// Which netfilter backend firewalld drives.
// `Iptables` is constructed by the CLI parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum NetfilterBackend {
    /// The nftables backend (modern default).
    Nftables,
    /// The legacy iptables backend.
    Iptables,
    /// The backend could not be determined.
    #[default]
    Unknown,
}

impl NetfilterBackend {
    /// Lowercase name for display.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nftables => "nftables",
            Self::Iptables => "iptables",
            Self::Unknown => "unknown",
        }
    }
}

/// Daemon-level state and settings.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FirewallStatus {
    /// Whether the firewalld daemon is up and answering.
    pub daemon_running: bool,
    /// Daemon version, when it could be queried.
    pub version: Option<String>,
    /// Netfilter backend in use.
    pub backend: NetfilterBackend,
    /// Current `LogDenied` setting.
    pub log_denied: LogDenied,
    /// Whether panic mode (drop every packet) is active.
    pub panic_mode: bool,
}

/// Static definition of a firewalld service (from `--info-service`),
/// cached per process — definitions only change when service files change.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ServiceDefinition {
    /// Ports the service opens.
    pub ports: Vec<PortSpec>,
    /// Raw IP protocols (e.g. `igmp`) beyond port-based rules.
    pub protocols: Vec<String>,
}

/// Runtime info of one ipset (from `--info-ipset`).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct IpSetInfo {
    /// The ipset type, e.g. `hash:ip`.
    pub kind: String,
    /// Current entries, verbatim as firewalld prints them.
    pub entries: Vec<String>,
}

/// The complete firewall state at one point in time.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FirewallSnapshot {
    /// Daemon-level status.
    pub status: FirewallStatus,
    /// The zone traffic without an explicit binding falls into.
    pub default_zone: ZoneName,
    /// Zones with at least one interface or source bound, with those bindings.
    pub active: BTreeMap<ZoneName, ActiveZone>,
    /// Per-zone runtime configuration.
    pub runtime: BTreeMap<ZoneName, ZoneDetails>,
    /// Per-zone permanent configuration.
    pub permanent: BTreeMap<ZoneName, ZoneDetails>,
    /// Known ipsets and their entries.
    pub ipsets: BTreeMap<IpSetName, IpSetInfo>,
    /// Definitions for services referenced by any zone (ports/protocols).
    pub service_definitions: BTreeMap<ServiceName, ServiceDefinition>,
    /// Every service firewalld knows about (`--get-services`), for browsing.
    pub available_services: Vec<ServiceName>,
    /// Policy objects (`--get-policies` + `--info-policy`).
    pub policies: BTreeMap<PolicyName, PolicyDetails>,
    /// Raw `--direct --get-all-rules` lines (direct rules are deprecated;
    /// shown read-only with a warning).
    pub direct_rules: Vec<String>,
    /// Sections that could not be fetched this refresh (name plus reason).
    /// An empty ipset list with `"ipsets"` in here means "unknown", not
    /// "none" — the UI must show the difference.
    #[serde(default)]
    pub degraded: Vec<String>,
}

impl FirewallSnapshot {
    /// Sorted union of service names referenced by any zone in any config.
    #[must_use]
    pub fn referenced_services(&self) -> Vec<ServiceName> {
        let mut names: Vec<ServiceName> = self
            .runtime
            .values()
            .chain(self.permanent.values())
            .flat_map(|zone| zone.services.iter().cloned())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// Sorted union of runtime and permanent zone names.
    #[must_use]
    pub fn zone_names(&self) -> Vec<&ZoneName> {
        let mut names: Vec<&ZoneName> = self.runtime.keys().collect();
        names.extend(
            self.permanent
                .keys()
                .filter(|name| !self.runtime.contains_key(*name)),
        );
        names.sort();
        names
    }

    /// Whether the zone has any runtime interface or source binding.
    #[must_use]
    pub fn is_active(&self, zone: &ZoneName) -> bool {
        self.active.contains_key(zone)
    }

    // Drives the per-zone drift indicator.
    /// Whether the zone's runtime and permanent configs are identical.
    #[must_use]
    pub fn is_zone_synced(&self, zone: &ZoneName) -> bool {
        self.runtime.get(zone) == self.permanent.get(zone)
    }

    /// Whether the entire runtime config matches permanent (no drift).
    #[must_use]
    pub fn all_synced(&self) -> bool {
        self.runtime == self.permanent
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::domain::mock;

    #[test]
    fn snapshot_serializes_to_json() {
        let snapshot = mock::sample().unwrap();
        let json = serde_json::to_string(&snapshot).unwrap();
        // Newtypes serialize transparently; ports as "8080/tcp".
        assert!(json.contains("\"default_zone\":\"public\""));
        assert!(json.contains("8080/tcp"));
        assert!(json.contains("\"mypolicy\""));
    }
}
