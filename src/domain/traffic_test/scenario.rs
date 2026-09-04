use std::collections::BTreeSet;
use std::fmt;
use std::num::NonZeroU64;

use super::TrafficExpectation;
use crate::domain::{IcmpType, InterfaceName, IpProtocol, PortSelector, SourceAddress, ZoneName};

/// Maximum scenarios accepted in one suite or aggregate report.
pub const MAX_SCENARIOS_PER_SUITE: usize = 1000;
/// Maximum UTF-8 bytes retained for a suite or scenario name.
pub const MAX_TRAFFIC_NAME_BYTES: usize = 128;
/// Maximum UTF-8 bytes retained for one operator note.
pub const MAX_TRAFFIC_NOTE_BYTES: usize = 1024;
const MAX_TRAFFIC_ID_BYTES: usize = 128;

macro_rules! traffic_id {
    ($(#[$meta:meta])* $name:ident, $kind:literal) => {
        $(#[$meta])*
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            serde::Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Parses a stable, filesystem-independent identifier.
            pub fn parse(raw: &str) -> Result<Self, TrafficValidationError> {
                validate_id(raw, $kind)?;
                Ok(Self(raw.to_owned()))
            }

            /// Returns the validated identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                Self::parse(&raw).map_err(serde::de::Error::custom)
            }
        }
    };
}

traffic_id!(
    /// Stable identity of one traffic expectation.
    TrafficScenarioId,
    "scenario ID"
);
traffic_id!(
    /// Stable identity of one traffic suite.
    TrafficSuiteId,
    "suite ID"
);

/// Monotonic persisted revision used for optimistic concurrency and stale-result checks.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct TrafficSuiteRevision(NonZeroU64);

impl TrafficSuiteRevision {
    /// Creates a non-zero suite revision.
    pub fn new(value: u64) -> Result<Self, TrafficValidationError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(TrafficValidationError::ZeroSuiteRevision)
    }

    /// Returns the numeric revision.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Packet direction requested by a scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficDirection {
    /// Traffic entering the local host.
    ToHost,
    /// Traffic originating from the local host.
    FromHost,
    /// Traffic routed through the host.
    Forwarded,
}

/// Scenario destination independent of the evaluated configuration target.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficDestination {
    /// The local host without binding the scenario to one local address.
    LocalHost,
    /// One explicit IP address or CIDR.
    Address(SourceAddress),
}

/// Transport selector for one scenario.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TrafficTransport {
    /// TCP traffic.
    Tcp,
    /// UDP traffic.
    Udp,
    /// One ICMP message type.
    Icmp {
        /// Firewalld ICMP type name.
        icmp_type: IcmpType,
    },
    /// One raw IP protocol such as GRE or ESP.
    RawProtocol {
        /// Firewalld protocol name.
        protocol: IpProtocol,
    },
}

impl TrafficTransport {
    const fn label(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp { .. } => "icmp",
            Self::RawProtocol { .. } => "raw_protocol",
        }
    }

    const fn uses_ports(&self) -> bool {
        matches!(self, Self::Tcp | Self::Udp)
    }
}

/// Connection-tracking state declared by a scenario.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficConnectionState {
    /// A new flow with no established conntrack entry.
    #[default]
    New,
    /// Reserved for a future source-backed conntrack model.
    Established,
    /// Reserved for a future source-backed conntrack model.
    Related,
}

/// Operational importance of one expectation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficSeverity {
    /// A violated result may participate in a later mutation safety gate.
    Critical,
    /// A violated result is informational unless explicitly promoted.
    Advisory,
}

/// One persisted traffic expectation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrafficScenario {
    /// Stable identity within the suite.
    pub id: TrafficScenarioId,
    /// Operator-facing name.
    pub name: String,
    /// Whether normal suite runs include this scenario.
    pub enabled: bool,
    /// Direction of travel.
    pub direction: TrafficDirection,
    /// Source IP address or CIDR.
    pub source: SourceAddress,
    /// Optional ingress interface hint.
    pub ingress_interface: Option<InterfaceName>,
    /// Optional explicit ingress zone hint.
    pub ingress_zone: Option<ZoneName>,
    /// Local or explicit destination.
    pub destination: TrafficDestination,
    /// Optional egress interface hint for later directions.
    pub egress_interface: Option<InterfaceName>,
    /// Optional egress zone hint for later directions.
    pub egress_zone: Option<ZoneName>,
    /// Transport or raw protocol.
    pub transport: TrafficTransport,
    /// Required for TCP and UDP, forbidden for portless transports.
    pub destination_port: Option<PortSelector>,
    /// Optional TCP or UDP source port.
    pub source_port: Option<PortSelector>,
    /// Declared conntrack state.
    #[serde(default)]
    pub connection_state: TrafficConnectionState,
    /// Operator-declared expected decision.
    pub expectation: TrafficExpectation,
    /// Operational importance.
    pub severity: TrafficSeverity,
    /// Whether a later phase should include this scenario in mutation gates.
    pub required_safety_gate: bool,
    /// Optional operator context, never command output or credentials.
    pub note: Option<String>,
}

impl TrafficScenario {
    /// Validates persistence and semantic shape without claiming evaluator support.
    pub fn validate(&self) -> Result<(), TrafficValidationError> {
        validate_text("scenario", &self.name, MAX_TRAFFIC_NAME_BYTES)?;
        if let Some(note) = &self.note {
            validate_text("scenario note", note, MAX_TRAFFIC_NOTE_BYTES)?;
        }
        if self.ingress_interface.is_some() && self.ingress_zone.is_some() {
            return Err(TrafficValidationError::ConflictingIngressHints);
        }
        if self.egress_interface.is_some() && self.egress_zone.is_some() {
            return Err(TrafficValidationError::ConflictingEgressHints);
        }

        let source_family = self
            .source
            .family()
            .ok_or(TrafficValidationError::SourceMustBeIpAddress)?;
        if let TrafficDestination::Address(destination) = &self.destination {
            let destination_family = destination
                .family()
                .ok_or(TrafficValidationError::DestinationMustBeIpAddress)?;
            if source_family != destination_family {
                return Err(TrafficValidationError::AddressFamilyMismatch);
            }
        }

        if self.transport.uses_ports() {
            if self.destination_port.is_none() {
                return Err(TrafficValidationError::DestinationPortRequired);
            }
        } else if self.destination_port.is_some() || self.source_port.is_some() {
            return Err(TrafficValidationError::PortsNotAllowed {
                transport: self.transport.label(),
            });
        }

        Ok(())
    }
}

/// One version-independent set of traffic expectations.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrafficSuite {
    /// Stable suite identity.
    pub id: TrafficSuiteId,
    /// Operator-facing name.
    pub name: String,
    /// Persisted optimistic-concurrency revision.
    pub revision: TrafficSuiteRevision,
    /// Ordered scenarios. Order is retained for predictable operator review.
    pub scenarios: Vec<TrafficScenario>,
}

impl TrafficSuite {
    /// Validates suite limits and every contained scenario.
    pub fn validate(&self) -> Result<(), TrafficValidationError> {
        validate_text("suite", &self.name, MAX_TRAFFIC_NAME_BYTES)?;
        if self.scenarios.len() > MAX_SCENARIOS_PER_SUITE {
            return Err(TrafficValidationError::TooManyScenarios {
                count: self.scenarios.len(),
                max: MAX_SCENARIOS_PER_SUITE,
            });
        }

        let mut ids = BTreeSet::new();
        for scenario in &self.scenarios {
            scenario.validate()?;
            if !ids.insert(scenario.id.clone()) {
                return Err(TrafficValidationError::DuplicateScenarioId(
                    scenario.id.clone(),
                ));
            }
        }
        Ok(())
    }
}

/// Invalid traffic-suite input rejected before evaluation or persistence.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrafficValidationError {
    /// A stable identifier is empty or whitespace-only.
    #[error("{kind} cannot be empty")]
    EmptyId {
        /// Identifier family.
        kind: &'static str,
    },
    /// A stable identifier is too long.
    #[error("{kind} is {actual} bytes; maximum is {max}")]
    IdTooLong {
        /// Identifier family.
        kind: &'static str,
        /// Actual UTF-8 byte length.
        actual: usize,
        /// Maximum byte length.
        max: usize,
    },
    /// A stable identifier contains an unsupported character.
    #[error("{kind} contains invalid character `{character}`")]
    InvalidIdCharacter {
        /// Identifier family.
        kind: &'static str,
        /// Rejected character.
        character: char,
    },
    /// A suite or scenario name is empty.
    #[error("{kind} name cannot be empty")]
    EmptyName {
        /// Object family.
        kind: &'static str,
    },
    /// User-visible text exceeds its UTF-8 byte limit.
    #[error("{kind} is {actual} bytes; maximum is {max}")]
    TextTooLong {
        /// Field family.
        kind: &'static str,
        /// Actual UTF-8 byte length.
        actual: usize,
        /// Maximum byte length.
        max: usize,
    },
    /// User-visible text contains a control character.
    #[error("{kind} contains a control character")]
    TextContainsControl {
        /// Field family.
        kind: &'static str,
    },
    /// Revision zero cannot identify persisted state.
    #[error("suite revision must be non-zero")]
    ZeroSuiteRevision,
    /// More scenarios were supplied than bounded execution permits.
    #[error("suite contains {count} scenarios; maximum is {max}")]
    TooManyScenarios {
        /// Actual count.
        count: usize,
        /// Maximum count.
        max: usize,
    },
    /// Two scenarios share one stable identity.
    #[error("duplicate scenario ID `{0}`")]
    DuplicateScenarioId(TrafficScenarioId),
    /// The source must be an IP address or CIDR, not a MAC or IP set.
    #[error("scenario source must be an IP address or CIDR")]
    SourceMustBeIpAddress,
    /// An explicit destination must be an IP address or CIDR.
    #[error("scenario destination must be an IP address or CIDR")]
    DestinationMustBeIpAddress,
    /// Source and destination IP families differ.
    #[error("source and destination address families differ")]
    AddressFamilyMismatch,
    /// Interface and explicit zone cannot both select ingress.
    #[error("ingress interface and ingress zone hints are mutually exclusive")]
    ConflictingIngressHints,
    /// Interface and explicit zone cannot both select egress.
    #[error("egress interface and egress zone hints are mutually exclusive")]
    ConflictingEgressHints,
    /// Port-based transports require a destination port.
    #[error("TCP and UDP scenarios require a destination port")]
    DestinationPortRequired,
    /// ICMP and raw-protocol scenarios cannot carry ports.
    #[error("{transport} scenarios cannot contain source or destination ports")]
    PortsNotAllowed {
        /// Stable transport label.
        transport: &'static str,
    },
}

fn validate_id(raw: &str, kind: &'static str) -> Result<(), TrafficValidationError> {
    if raw.trim().is_empty() {
        return Err(TrafficValidationError::EmptyId { kind });
    }
    if raw.len() > MAX_TRAFFIC_ID_BYTES {
        return Err(TrafficValidationError::IdTooLong {
            kind,
            actual: raw.len(),
            max: MAX_TRAFFIC_ID_BYTES,
        });
    }
    if let Some(character) = raw.chars().find(|character| {
        !character.is_ascii_alphanumeric() && !matches!(character, '-' | '_' | '.')
    }) {
        return Err(TrafficValidationError::InvalidIdCharacter { kind, character });
    }
    Ok(())
}

fn validate_text(kind: &'static str, raw: &str, max: usize) -> Result<(), TrafficValidationError> {
    if raw.trim().is_empty() {
        return Err(TrafficValidationError::EmptyName { kind });
    }
    if raw.len() > max {
        return Err(TrafficValidationError::TextTooLong {
            kind,
            actual: raw.len(),
            max,
        });
    }
    if raw.chars().any(char::is_control) {
        return Err(TrafficValidationError::TextContainsControl { kind });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::domain::{
        IcmpType, InterfaceName, IpProtocol, PortSelector, SourceAddress, ZoneName,
    };

    fn scenario() -> TrafficScenario {
        TrafficScenario {
            id: TrafficScenarioId::parse("keep-ssh").unwrap(),
            name: "Keep SSH access".to_owned(),
            enabled: true,
            direction: TrafficDirection::ToHost,
            source: SourceAddress::parse("192.0.2.0/24").unwrap(),
            ingress_interface: Some(InterfaceName::parse("eth0").unwrap()),
            ingress_zone: None,
            destination: TrafficDestination::LocalHost,
            egress_interface: None,
            egress_zone: None,
            transport: TrafficTransport::Tcp,
            destination_port: Some("22".parse::<PortSelector>().unwrap()),
            source_port: None,
            connection_state: TrafficConnectionState::New,
            expectation: crate::domain::TrafficExpectation::Allow,
            severity: TrafficSeverity::Critical,
            required_safety_gate: true,
            note: Some("Remote administration path".to_owned()),
        }
    }

    fn suite(scenarios: Vec<TrafficScenario>) -> TrafficSuite {
        TrafficSuite {
            id: TrafficSuiteId::parse("default").unwrap(),
            name: "Default host checks".to_owned(),
            revision: TrafficSuiteRevision::new(1).unwrap(),
            scenarios,
        }
    }

    #[test]
    fn ids_and_revision_are_stable_validated_values() {
        assert_eq!(
            TrafficScenarioId::parse("keep-ssh").unwrap().as_str(),
            "keep-ssh"
        );
        assert_eq!(
            TrafficSuiteId::parse("prod.host_v1").unwrap().as_str(),
            "prod.host_v1"
        );
        assert!(TrafficScenarioId::parse("").is_err());
        assert!(TrafficSuiteId::parse("contains whitespace").is_err());
        assert!(TrafficSuiteRevision::new(0).is_err());
        assert_eq!(TrafficSuiteRevision::new(4).unwrap().get(), 4);
    }

    #[test]
    fn valid_host_ingress_scenario_and_suite_pass_validation() {
        let scenario = scenario();
        assert_eq!(scenario.validate(), Ok(()));
        assert_eq!(suite(vec![scenario]).validate(), Ok(()));
    }

    #[test]
    fn suite_rejects_name_limits_count_and_duplicate_ids() {
        let mut invalid_name = scenario();
        invalid_name.name = " ".to_owned();
        assert_eq!(
            invalid_name.validate(),
            Err(TrafficValidationError::EmptyName { kind: "scenario" })
        );

        let mut oversized_name = scenario();
        oversized_name.name = "é".repeat(MAX_TRAFFIC_NAME_BYTES / 2 + 1);
        assert!(matches!(
            oversized_name.validate(),
            Err(TrafficValidationError::TextTooLong {
                kind: "scenario",
                actual,
                max: MAX_TRAFFIC_NAME_BYTES,
            }) if actual == MAX_TRAFFIC_NAME_BYTES + 2
        ));

        let mut oversized_note = scenario();
        oversized_note.note = Some("x".repeat(MAX_TRAFFIC_NOTE_BYTES + 1));
        assert!(matches!(
            oversized_note.validate(),
            Err(TrafficValidationError::TextTooLong {
                kind: "scenario note",
                ..
            })
        ));

        let original = scenario();
        assert_eq!(
            suite(vec![original.clone(), original]).validate(),
            Err(TrafficValidationError::DuplicateScenarioId(
                TrafficScenarioId::parse("keep-ssh").unwrap()
            ))
        );

        let mut too_many = Vec::with_capacity(MAX_SCENARIOS_PER_SUITE + 1);
        for index in 0..=MAX_SCENARIOS_PER_SUITE {
            let mut item = scenario();
            item.id = TrafficScenarioId::parse(&format!("scenario-{index}")).unwrap();
            too_many.push(item);
        }
        assert!(matches!(
            suite(too_many).validate(),
            Err(TrafficValidationError::TooManyScenarios { .. })
        ));
    }

    #[test]
    fn transport_and_port_shapes_are_checked() {
        let mut missing_destination_port = scenario();
        missing_destination_port.destination_port = None;
        assert_eq!(
            missing_destination_port.validate(),
            Err(TrafficValidationError::DestinationPortRequired)
        );

        let mut icmp_with_port = scenario();
        icmp_with_port.transport = TrafficTransport::Icmp {
            icmp_type: IcmpType::parse("echo-request").unwrap(),
        };
        assert_eq!(
            icmp_with_port.validate(),
            Err(TrafficValidationError::PortsNotAllowed { transport: "icmp" })
        );

        let mut raw_with_port = scenario();
        raw_with_port.transport = TrafficTransport::RawProtocol {
            protocol: IpProtocol::parse("gre").unwrap(),
        };
        assert_eq!(
            raw_with_port.validate(),
            Err(TrafficValidationError::PortsNotAllowed {
                transport: "raw_protocol"
            })
        );
    }

    #[test]
    fn address_family_and_zone_interface_hints_cannot_conflict() {
        let mut mixed_family = scenario();
        mixed_family.destination =
            TrafficDestination::Address(SourceAddress::parse("2001:db8::10").unwrap());
        assert_eq!(
            mixed_family.validate(),
            Err(TrafficValidationError::AddressFamilyMismatch)
        );

        let mut ingress_conflict = scenario();
        ingress_conflict.ingress_zone = Some(ZoneName::parse("public").unwrap());
        assert_eq!(
            ingress_conflict.validate(),
            Err(TrafficValidationError::ConflictingIngressHints)
        );

        let mut egress_conflict = scenario();
        egress_conflict.egress_interface = Some(InterfaceName::parse("eth1").unwrap());
        egress_conflict.egress_zone = Some(ZoneName::parse("external").unwrap());
        assert_eq!(
            egress_conflict.validate(),
            Err(TrafficValidationError::ConflictingEgressHints)
        );
    }

    #[test]
    fn schema_preserves_future_directions_and_states_without_normalizing_them() {
        let mut from_host = scenario();
        from_host.direction = TrafficDirection::FromHost;
        assert_eq!(from_host.validate(), Ok(()));

        let mut established = scenario();
        established.connection_state = TrafficConnectionState::Established;
        assert_eq!(established.validate(), Ok(()));

        let encoded = toml::to_string(&suite(vec![from_host, established])).unwrap();
        let decoded: TrafficSuite = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded.scenarios[0].direction, TrafficDirection::FromHost);
        assert_eq!(
            decoded.scenarios[1].connection_state,
            TrafficConnectionState::Established
        );
    }
}
