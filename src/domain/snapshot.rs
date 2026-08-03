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

/// Runtime and permanent views of the same firewalld resource family.
///
/// Deserialization accepts the legacy single-value representation and copies
/// it into both scopes. This keeps schema-v1 snapshots readable while schema
/// v2 persists the two configurations independently.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Scoped<T> {
    /// The live in-kernel state.
    pub runtime: T,
    /// The on-disk state activated by reload.
    pub permanent: T,
}

impl<T: Default> Default for Scoped<T> {
    fn default() -> Self {
        Self {
            runtime: T::default(),
            permanent: T::default(),
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum ScopedRepr<T> {
    Scoped { runtime: T, permanent: T },
    Legacy(T),
}

impl<'de, T> serde::Deserialize<'de> for Scoped<T>
where
    T: Clone + serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match <ScopedRepr<T> as serde::Deserialize>::deserialize(deserializer)? {
            ScopedRepr::Scoped { runtime, permanent } => Ok(Self { runtime, permanent }),
            ScopedRepr::Legacy(value) => Ok(Self {
                runtime: value.clone(),
                permanent: value,
            }),
        }
    }
}

/// Snapshot section whose contents could not be observed completely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotSection {
    /// Runtime or permanent zone configuration.
    Zones,
    /// IP set definitions and entries.
    IpSets,
    /// Policy definitions.
    Policies,
    /// Deprecated direct rules.
    DirectRules,
    /// The service catalog.
    Services,
    /// Details of referenced service definitions.
    ServiceDefinitions,
    /// Compatibility notice for a snapshot written by an older schema.
    LegacySnapshot,
}

impl SnapshotSection {
    /// Stable operator-facing section label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Zones => "zones",
            Self::IpSets => "ipsets",
            Self::Policies => "policies",
            Self::DirectRules => "direct rules",
            Self::Services => "services",
            Self::ServiceDefinitions => "service definitions",
            Self::LegacySnapshot => "legacy snapshot",
        }
    }
}

/// A structured observation failure. Keeping section, scope, and object
/// separate lets validation disable only mutations whose preconditions are
/// unknown instead of treating the whole snapshot as unusable.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DegradedSection {
    /// Resource family affected by the failed observation.
    pub section: SnapshotSection,
    /// Affected configuration scope, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<ConfigurationTarget>,
    /// Specific object that failed to load, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// Original failure detail, suitable for an operator.
    pub reason: String,
}

impl DegradedSection {
    /// Creates a section-level degradation record.
    #[must_use]
    pub fn new(
        section: SnapshotSection,
        target: Option<ConfigurationTarget>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            section,
            target,
            object: None,
            reason: reason.into(),
        }
    }

    /// Adds the affected object identity to this record.
    #[must_use]
    pub fn with_object(mut self, object: impl Into<String>) -> Self {
        self.object = Some(object.into());
        self
    }

    /// Converts a pre-v2 free-form degradation message.
    #[must_use]
    pub fn from_legacy(reason: String) -> Self {
        let lower = reason.to_ascii_lowercase();
        let section = if lower.contains("ipset") {
            SnapshotSection::IpSets
        } else if lower.contains("polic") {
            SnapshotSection::Policies
        } else if lower.contains("direct rule") {
            SnapshotSection::DirectRules
        } else if lower.contains("service definition") {
            SnapshotSection::ServiceDefinitions
        } else if lower.contains("service") {
            SnapshotSection::Services
        } else {
            SnapshotSection::Zones
        };
        let target = if lower.starts_with("runtime ") {
            Some(ConfigurationTarget::Runtime)
        } else if lower.starts_with("permanent ") {
            Some(ConfigurationTarget::Permanent)
        } else {
            None
        };
        Self::new(section, target, reason)
    }
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum DegradedSectionRepr {
    Typed {
        section: SnapshotSection,
        #[serde(default)]
        target: Option<ConfigurationTarget>,
        #[serde(default)]
        object: Option<String>,
        reason: String,
    },
    Legacy(String),
}

impl<'de> serde::Deserialize<'de> for DegradedSection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match <DegradedSectionRepr as serde::Deserialize>::deserialize(deserializer)? {
            DegradedSectionRepr::Typed {
                section,
                target,
                object,
                reason,
            } => Ok(Self {
                section,
                target,
                object,
                reason,
            }),
            DegradedSectionRepr::Legacy(reason) => Ok(Self::from_legacy(reason)),
        }
    }
}

impl std::fmt::Display for DegradedSection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.section.label())?;
        if let Some(target) = self.target {
            write!(formatter, " [{}]", target.label())?;
        }
        if let Some(object) = &self.object {
            write!(formatter, " `{object}`")?;
        }
        write!(formatter, ": {}", self.reason)
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

/// Static definition of a firewalld service (from `--info-service`).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ServiceDefinition {
    /// Ports the service opens.
    pub ports: Vec<PortSpec>,
    /// Raw IP protocols (e.g. `igmp`) beyond port-based rules.
    pub protocols: Vec<String>,
}

/// One scope's info for an ipset (from `--info-ipset`).
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
    /// Known ipsets and their entries, separated by configuration scope.
    pub ipsets: Scoped<BTreeMap<IpSetName, IpSetInfo>>,
    /// Definitions for services referenced by any zone (ports/protocols).
    pub service_definitions: BTreeMap<ServiceName, ServiceDefinition>,
    /// Every service firewalld knows about (`--get-services`), for browsing.
    pub available_services: Vec<ServiceName>,
    /// Policy objects (`--get-policies` + `--info-policy`) by scope.
    pub policies: Scoped<BTreeMap<PolicyName, PolicyDetails>>,
    /// Raw `--direct --get-all-rules` lines (direct rules are deprecated;
    /// shown read-only with a warning).
    pub direct_rules: Vec<String>,
    /// Sections that could not be fetched this refresh (name plus reason).
    /// An empty ipset list with `"ipsets"` in here means "unknown", not
    /// "none" — the UI must show the difference.
    #[serde(default)]
    pub degraded: Vec<DegradedSection>,
}

impl FirewallSnapshot {
    /// Whether a resource family was observed completely for the requested
    /// target. A scope-less record affects both configurations. Legacy
    /// snapshots cannot safely prove ipset or policy preconditions because
    /// their old representation collapsed the two scopes.
    #[must_use]
    pub fn section_is_complete(
        &self,
        section: SnapshotSection,
        target: ConfigurationTarget,
    ) -> bool {
        !self.degraded.iter().any(|record| {
            let legacy_scope_loss = record.section == SnapshotSection::LegacySnapshot
                && matches!(section, SnapshotSection::IpSets | SnapshotSection::Policies);
            (record.section == section && targets_overlap(record.target, target))
                || legacy_scope_loss
        })
    }

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
        self.section_is_complete(
            SnapshotSection::Zones,
            ConfigurationTarget::RuntimeAndPermanent,
        ) && self.section_is_complete(
            SnapshotSection::IpSets,
            ConfigurationTarget::RuntimeAndPermanent,
        ) && self.section_is_complete(
            SnapshotSection::Policies,
            ConfigurationTarget::RuntimeAndPermanent,
        ) && self.runtime == self.permanent
            && self.ipsets.runtime == self.ipsets.permanent
            && self.policies.runtime == self.policies.permanent
    }
}

fn targets_overlap(observed: Option<ConfigurationTarget>, requested: ConfigurationTarget) -> bool {
    match observed {
        None | Some(ConfigurationTarget::RuntimeAndPermanent) => true,
        Some(ConfigurationTarget::Runtime) => requested != ConfigurationTarget::Permanent,
        Some(ConfigurationTarget::Permanent) => requested != ConfigurationTarget::Runtime,
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

    #[test]
    fn legacy_scoped_values_deserialize_into_both_targets() {
        let snapshot = mock::sample().unwrap();
        let mut json = serde_json::to_value(&snapshot).unwrap();
        let ipsets = json["ipsets"]["runtime"].take();
        json["ipsets"] = ipsets;
        let decoded: super::FirewallSnapshot = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.ipsets.runtime, decoded.ipsets.permanent);
        assert!(
            decoded
                .ipsets
                .runtime
                .contains_key(&crate::domain::IpSetName::parse("blocklist").unwrap())
        );
    }

    #[test]
    fn legacy_degraded_strings_become_typed_records() {
        let snapshot = mock::sample().unwrap();
        let mut json = serde_json::to_value(&snapshot).unwrap();
        json["degraded"] = serde_json::json!(["ipsets: access denied"]);
        let decoded: super::FirewallSnapshot = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.degraded[0].section, super::SnapshotSection::IpSets);
        assert_eq!(decoded.degraded[0].reason, "ipsets: access denied");
        assert!(
            !decoded.all_synced(),
            "unknown state cannot be called synced"
        );
    }
}
