//! Zone-level configuration details.

use super::address::SourceAddress;
use super::ids::{IcmpType, InterfaceName, IpProtocol, ServiceName, ZoneName};
use super::port::{ForwardPort, PortSpec};
use super::rich_rule::RichRule;

/// The zone target, i.e. what happens to packets not matched by any rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum ZoneTarget {
    /// firewalld's built-in default behavior (reject-like, with ICMP allowances).
    #[default]
    Default,
    /// Accept unmatched packets.
    Accept,
    /// Silently drop unmatched packets.
    Drop,
    /// Reject unmatched packets with an ICMP error.
    Reject,
}

impl ZoneTarget {
    /// The exact spelling firewalld uses in `--list-all` output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Accept => "ACCEPT",
            Self::Drop => "DROP",
            Self::Reject => "%%REJECT%%",
        }
    }
}

impl std::str::FromStr for ZoneTarget {
    type Err = super::ids::ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "default" => Ok(Self::Default),
            "ACCEPT" => Ok(Self::Accept),
            "DROP" => Ok(Self::Drop),
            "%%REJECT%%" | "REJECT" => Ok(Self::Reject),
            _ => Err(super::ids::ValidationError::InvalidZoneTarget(s.to_owned())),
        }
    }
}

/// Runtime binding info from `--get-active-zones`.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ActiveZone {
    /// Interfaces currently bound to the zone.
    pub interfaces: Vec<InterfaceName>,
    /// Source addresses currently bound to the zone.
    pub sources: Vec<SourceAddress>,
}

/// Full configuration of one zone for one configuration target
/// (one instance for runtime, one for permanent).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ZoneDetails {
    /// Zone name.
    pub name: ZoneName,
    /// Fate of packets no rule matches.
    pub target: ZoneTarget,
    /// Bound network interfaces.
    pub interfaces: Vec<InterfaceName>,
    /// Bound source addresses.
    pub sources: Vec<SourceAddress>,
    /// Enabled services.
    pub services: Vec<ServiceName>,
    /// Directly opened ports.
    pub ports: Vec<PortSpec>,
    /// Port-forwarding rules.
    pub forward_ports: Vec<ForwardPort>,
    /// Rich rules, stored verbatim.
    pub rich_rules: Vec<RichRule>,
    /// Blocked ICMP types.
    pub icmp_blocks: Vec<IcmpType>,
    /// Whether IP masquerading (source NAT) is enabled.
    pub masquerade: bool,
    /// Source-port matches (`--add-source-port`), same `port/proto` shape as ports.
    pub source_ports: Vec<PortSpec>,
    /// Allowed IP protocols (`--add-protocol`), e.g. `gre`, `esp`, `igmp`.
    pub protocols: Vec<IpProtocol>,
    /// Whether intra-zone forwarding between bound interfaces/sources is on
    /// (firewalld 0.9+ `--add-forward`).
    pub forward: bool,
    /// Whether the icmp-block set is inverted: block everything *except* the
    /// listed types (`--add-icmp-block-inversion`).
    pub icmp_block_inversion: bool,
}

impl ZoneDetails {
    /// A zone with the given name and nothing configured; the starting point
    /// for parsers and tests.
    #[must_use]
    pub fn empty(name: ZoneName) -> Self {
        Self {
            name,
            target: ZoneTarget::Default,
            interfaces: Vec::new(),
            sources: Vec::new(),
            services: Vec::new(),
            ports: Vec::new(),
            forward_ports: Vec::new(),
            rich_rules: Vec::new(),
            icmp_blocks: Vec::new(),
            masquerade: false,
            source_ports: Vec::new(),
            protocols: Vec::new(),
            forward: false,
            icmp_block_inversion: false,
        }
    }
}
