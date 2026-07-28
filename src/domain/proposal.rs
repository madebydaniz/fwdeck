//! Turning an observed *denied* netfilter flow into a least-privilege allow
//! suggestion. Pure: the log line is already parsed by the infrastructure
//! adapter; here we only decide the single scoped rule an admin *could* stage
//! to permit that one flow. Nothing is applied — the caller routes the proposed
//! [`FirewallOperation`] through the normal confirm/stage/apply path.

use std::fmt;
use std::net::IpAddr;

use super::address::AddressFamily;
use super::ids::ZoneName;
use super::observation::LogEntry;
use super::operation::FirewallOperation;
use super::port::{PortNumber, Protocol};
use super::rich_rule::RichRule;
use super::snapshot::ConfigurationTarget;

/// A single blocked inbound flow distilled from a denied log line — enough to
/// propose one scoped allow rule (this source, this port, this protocol).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniedFlow {
    /// The blocked source address.
    pub src: IpAddr,
    /// Address family of `src` (decides the `/32` vs `/128` host scope).
    pub family: AddressFamily,
    /// Destination port that was refused.
    pub dport: PortNumber,
    /// Transport protocol.
    pub proto: Protocol,
    /// Ingress interface (`IN=`), when the log line carried one.
    pub iface: Option<String>,
}

/// Why a log line cannot become an allow suggestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalError {
    /// The verdict was not a denial — there is nothing to allow.
    NotDenied,
    /// The source field did not parse as an IP address.
    BadSource,
    /// The destination port was missing or not a valid port.
    NoPort,
    /// The protocol is not one a port rule can scope to (e.g. ICMP).
    UnsupportedProtocol,
}

impl fmt::Display for ProposalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::NotDenied => "select a denied (DROP/REJECT) row to propose an allow rule",
            Self::BadSource => "no usable source address on this log line",
            Self::NoPort => "no destination port on this log line (portless protocol?)",
            Self::UnsupportedProtocol => "no port-scoped rule for this protocol (e.g. ICMP)",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for ProposalError {}

impl DeniedFlow {
    /// Parses the raw log-string fields of an already-denied flow. The kernel
    /// logs `PROTO` uppercase (`TCP`) while firewalld wants it lowercase, and
    /// `DPT` is empty for portless protocols — both are normalized here.
    ///
    /// # Errors
    /// Returns [`ProposalError`] when the source isn't an IP, the port is
    /// missing/invalid, or the protocol can't carry a port rule (e.g. ICMP).
    pub fn parse(src: &str, dport: &str, proto: &str, iface: &str) -> Result<Self, ProposalError> {
        let src: IpAddr = src.trim().parse().map_err(|_| ProposalError::BadSource)?;
        let family = if src.is_ipv4() {
            AddressFamily::Ipv4
        } else {
            AddressFamily::Ipv6
        };
        let proto: Protocol = proto
            .trim()
            .to_ascii_lowercase()
            .parse()
            .map_err(|_| ProposalError::UnsupportedProtocol)?;
        let dport: PortNumber = dport.trim().parse().map_err(|_| ProposalError::NoPort)?;
        let iface = {
            let iface = iface.trim();
            (!iface.is_empty()).then(|| iface.to_owned())
        };
        Ok(Self {
            src,
            family,
            dport,
            proto,
            iface,
        })
    }

    /// Builds a source-scoped allow rule for this flow in `zone`: the tightest
    /// shape firewalld offers — this one host, to this one port/protocol, in
    /// this one zone. Widening (a zone-wide port open or a whole service) is
    /// always a separate, explicit choice, never proposed here.
    ///
    /// Returns `None` only if the assembled rule fails [`RichRule::parse`] — a
    /// guard that should not trip for well-formed input.
    #[must_use]
    pub fn propose_allow(
        &self,
        zone: ZoneName,
        target: ConfigurationTarget,
    ) -> Option<FirewallOperation> {
        let prefix = if self.family == AddressFamily::Ipv4 {
            32
        } else {
            128
        };
        let raw = format!(
            r#"rule family="{}" source address="{}/{prefix}" port port="{}" protocol="{}" accept"#,
            self.family.as_str(),
            self.src,
            self.dport,
            self.proto.as_str(),
        );
        let rule = RichRule::parse(&raw).ok()?;
        Some(FirewallOperation::AddRichRule { zone, rule, target })
    }
}

impl TryFrom<&LogEntry> for DeniedFlow {
    type Error = ProposalError;

    fn try_from(entry: &LogEntry) -> Result<Self, Self::Error> {
        if !entry.action.is_denied() {
            return Err(ProposalError::NotDenied);
        }
        Self::parse(&entry.src, &entry.dport, &entry.proto, &entry.iface)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::domain::observation::{LogAction, LogEntry};

    fn public() -> ZoneName {
        ZoneName::parse("public").unwrap()
    }

    #[test]
    fn tcp_flow_yields_source_scoped_accept() {
        let flow = DeniedFlow::parse("203.0.113.7", "5432", "TCP", "eth0").unwrap();
        assert_eq!(flow.family, AddressFamily::Ipv4);
        assert_eq!(flow.iface.as_deref(), Some("eth0"));
        let op = flow
            .propose_allow(public(), ConfigurationTarget::RuntimeAndPermanent)
            .unwrap();
        let FirewallOperation::AddRichRule { zone, rule, .. } = op else {
            panic!("expected AddRichRule");
        };
        assert_eq!(zone.as_str(), "public");
        let s = rule.as_str();
        assert!(s.contains(r#"family="ipv4""#), "{s}");
        assert!(s.contains(r#"source address="203.0.113.7/32""#), "{s}");
        assert!(s.contains(r#"port port="5432""#), "{s}");
        assert!(s.contains(r#"protocol="tcp""#), "{s}");
        assert!(s.ends_with("accept"), "{s}");
    }

    #[test]
    fn ipv6_flow_uses_128_and_ipv6_family() {
        let flow = DeniedFlow::parse("2001:db8::1", "22", "tcp", "").unwrap();
        assert_eq!(flow.family, AddressFamily::Ipv6);
        assert_eq!(flow.iface, None);
        let op = flow
            .propose_allow(public(), ConfigurationTarget::Runtime)
            .unwrap();
        let FirewallOperation::AddRichRule { rule, .. } = op else {
            panic!("expected AddRichRule");
        };
        assert!(rule.as_str().contains(r#"family="ipv6""#));
        assert!(
            rule.as_str()
                .contains(r#"source address="2001:db8::1/128""#)
        );
    }

    #[test]
    fn portless_unsupported_and_bad_source_are_rejected() {
        assert_eq!(
            DeniedFlow::parse("10.0.0.5", "", "ICMP", "eth0"),
            Err(ProposalError::UnsupportedProtocol)
        );
        assert_eq!(
            DeniedFlow::parse("10.0.0.5", "", "tcp", "eth0"),
            Err(ProposalError::NoPort)
        );
        assert_eq!(
            DeniedFlow::parse("not-an-ip", "80", "tcp", "eth0"),
            Err(ProposalError::BadSource)
        );
    }

    #[test]
    fn accept_entry_is_not_denied_but_reject_converts() {
        let base = LogEntry {
            time: "00:00:00".to_owned(),
            action: LogAction::Accept,
            src: "192.0.2.9".to_owned(),
            dst: "192.0.2.1".to_owned(),
            dport: "443".to_owned(),
            proto: "TCP".to_owned(),
            iface: "ens3".to_owned(),
        };
        assert_eq!(DeniedFlow::try_from(&base), Err(ProposalError::NotDenied));
        let denied = LogEntry {
            action: LogAction::Reject,
            ..base
        };
        let flow = DeniedFlow::try_from(&denied).unwrap();
        assert_eq!(flow.dport.get(), 443);
        assert_eq!(flow.iface.as_deref(), Some("ens3"));
    }
}
