//! Policy objects: firewalld\'s modern replacement for direct rules. A policy
//! controls traffic between ingress and egress zones (`ANY`/`HOST` are valid
//! pseudo-zones).

use super::ids::{PolicyName, ServiceName};
use super::port::PortSpec;

/// The action for packets not matched by any policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum PolicyTarget {
    /// Fall through to the next policy or the zone rules (firewalld's default).
    #[default]
    Continue,
    /// Accept unmatched packets.
    Accept,
    /// Reject unmatched packets with an ICMP error.
    Reject,
    /// Silently drop unmatched packets.
    Drop,
}

impl PolicyTarget {
    /// The uppercase spelling firewalld uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Continue => "CONTINUE",
            Self::Accept => "ACCEPT",
            Self::Reject => "REJECT",
            Self::Drop => "DROP",
        }
    }

    /// Parses firewalld's spelling; accepts both `REJECT` and `%%REJECT%%`.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "CONTINUE" => Some(Self::Continue),
            "ACCEPT" => Some(Self::Accept),
            "REJECT" | "%%REJECT%%" => Some(Self::Reject),
            "DROP" => Some(Self::Drop),
            _ => None,
        }
    }
}

/// Full configuration of one policy object.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PolicyDetails {
    /// Policy name.
    pub name: PolicyName,
    /// Action for packets no policy rule matches.
    pub target: PolicyTarget,
    /// Ingress zone names; plain strings because the `ANY`/`HOST`
    /// pseudo-zones are not valid [`super::ids::ZoneName`]s.
    pub ingress_zones: Vec<String>,
    /// Egress zone names; may include `ANY`/`HOST`, like `ingress_zones`.
    pub egress_zones: Vec<String>,
    /// Allowed services.
    pub services: Vec<ServiceName>,
    /// Allowed ports.
    pub ports: Vec<PortSpec>,
}

impl PolicyDetails {
    /// A policy with the given name and no rules.
    #[must_use]
    pub fn empty(name: PolicyName) -> Self {
        Self {
            name,
            target: PolicyTarget::Continue,
            ingress_zones: Vec::new(),
            egress_zones: Vec::new(),
            services: Vec::new(),
            ports: Vec::new(),
        }
    }
}
