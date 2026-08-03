//! Policy objects: firewalld\'s modern replacement for direct rules. A policy
//! controls traffic between ingress and egress zones (`ANY`/`HOST` are valid
//! pseudo-zones).

use super::ids::{IcmpType, IpProtocol, PolicyName, ServiceName};
use super::port::{ForwardPort, PortSpec};
use super::rich_rule::RichRule;

const fn default_priority() -> i32 {
    -1
}

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
    /// Whether firewalld currently considers this policy active.
    #[serde(default)]
    pub active: bool,
    /// Whether the policy is administratively disabled.
    #[serde(default)]
    pub disabled: bool,
    /// Policy evaluation priority; lower values run first.
    #[serde(default = "default_priority")]
    pub priority: i32,
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
    /// Raw IP protocols allowed by the policy.
    #[serde(default)]
    pub protocols: Vec<IpProtocol>,
    /// Whether IPv4 masquerading is enabled.
    #[serde(default)]
    pub masquerade: bool,
    /// Destination port-forwarding rules.
    #[serde(default)]
    pub forward_ports: Vec<ForwardPort>,
    /// Source ports allowed by the policy.
    #[serde(default)]
    pub source_ports: Vec<PortSpec>,
    /// ICMP types blocked by the policy.
    #[serde(default)]
    pub icmp_blocks: Vec<IcmpType>,
    /// Verbatim rich rules attached to the policy.
    #[serde(default)]
    pub rich_rules: Vec<RichRule>,
}

impl PolicyDetails {
    /// A policy with the given name and no rules.
    #[must_use]
    pub fn empty(name: PolicyName) -> Self {
        Self {
            name,
            active: false,
            disabled: false,
            priority: default_priority(),
            target: PolicyTarget::Continue,
            ingress_zones: Vec::new(),
            egress_zones: Vec::new(),
            services: Vec::new(),
            ports: Vec::new(),
            protocols: Vec::new(),
            masquerade: false,
            forward_ports: Vec::new(),
            source_ports: Vec::new(),
            icmp_blocks: Vec::new(),
            rich_rules: Vec::new(),
        }
    }

    /// Whether two snapshots describe the same policy configuration.
    /// `active` is deliberately excluded because it is runtime observation,
    /// not desired configuration.
    #[must_use]
    pub fn configuration_eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.disabled == other.disabled
            && self.priority == other.priority
            && self.target == other.target
            && self.ingress_zones == other.ingress_zones
            && self.egress_zones == other.egress_zones
            && self.services == other.services
            && self.ports == other.ports
            && self.protocols == other.protocols
            && self.masquerade == other.masquerade
            && self.forward_ports == other.forward_ports
            && self.source_ports == other.source_ports
            && self.icmp_blocks == other.icmp_blocks
            && self.rich_rules == other.rich_rules
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn active_status_does_not_create_configuration_drift() {
        let mut runtime = PolicyDetails::empty(PolicyName::parse("example").unwrap());
        let permanent = runtime.clone();
        runtime.active = true;

        assert_ne!(runtime, permanent);
        assert!(runtime.configuration_eq(&permanent));
    }
}
