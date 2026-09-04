//! Ports, protocols, and port-forwarding specifications.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use super::ids::ValidationError;

/// Transport protocols firewalld accepts in port rules.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// SCTP.
    Sctp,
    /// DCCP.
    Dccp,
}

impl Protocol {
    /// The lowercase spelling used in `firewall-cmd` arguments.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Sctp => "sctp",
            Self::Dccp => "dccp",
        }
    }
}

impl FromStr for Protocol {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "sctp" => Ok(Self::Sctp),
            "dccp" => Ok(Self::Dccp),
            _ => Err(ValidationError::InvalidProtocol(s.to_owned())),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A non-zero TCP/UDP/SCTP/DCCP port number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
pub struct PortNumber(u16);

impl PortNumber {
    /// Validates that `value` is non-zero.
    pub fn new(value: u16) -> Result<Self, ValidationError> {
        if value == 0 {
            return Err(ValidationError::InvalidPort("0".to_owned()));
        }
        Ok(Self(value))
    }

    /// The raw port number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl FromStr for PortNumber {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value: u16 = s
            .parse()
            .map_err(|_| ValidationError::InvalidPort(s.to_owned()))?;
        Self::new(value)
    }
}

impl fmt::Display for PortNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// An inclusive port range with `start <= end` enforced at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
pub struct PortRange {
    start: PortNumber,
    end: PortNumber,
}

impl PortRange {
    /// Validates that `start <= end`.
    pub fn new(start: PortNumber, end: PortNumber) -> Result<Self, ValidationError> {
        if start.get() > end.get() {
            return Err(ValidationError::InvalidRange(format!("{start}-{end}")));
        }
        Ok(Self { start, end })
    }

    /// Inclusive lower bound.
    #[must_use]
    pub const fn start(self) -> PortNumber {
        self.start
    }

    /// Inclusive upper bound.
    #[must_use]
    pub const fn end(self) -> PortNumber {
        self.end
    }
}

/// A single port or an inclusive range, the port half of a port spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PortSelector {
    /// One port.
    Single(PortNumber),
    /// An inclusive port range.
    Range(PortRange),
}

impl serde::Serialize for PortSelector {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for PortSelector {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for PortSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(port) => write!(f, "{port}"),
            Self::Range(range) => write!(f, "{}-{}", range.start(), range.end()),
        }
    }
}

impl FromStr for PortSelector {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('-') {
            Some((start, end)) => {
                let range = PortRange::new(start.parse()?, end.parse()?)?;
                Ok(Self::Range(range))
            }
            None => Ok(Self::Single(s.parse()?)),
        }
    }
}

/// A port (or range) plus protocol, in the same `8080/tcp` syntax firewall-cmd uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PortSpec {
    /// Port or range.
    pub port: PortSelector,
    /// Transport protocol.
    pub protocol: Protocol,
}

impl serde::Serialize for PortSpec {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for PortSpec {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for PortSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.port, self.protocol)
    }
}

impl FromStr for PortSpec {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (port, protocol) = s
            .split_once('/')
            .ok_or_else(|| ValidationError::InvalidPortSpec(s.to_owned()))?;
        Ok(Self {
            port: port.parse()?,
            protocol: protocol.parse()?,
        })
    }
}

/// An `--add-forward-port` style rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ForwardPort {
    /// Matched destination port(s).
    pub port: PortSelector,
    /// Transport protocol.
    pub protocol: Protocol,
    /// Rewritten destination port(s), if any.
    pub to_port: Option<PortSelector>,
    /// Rewritten destination address, if any.
    pub to_addr: Option<IpAddr>,
}

impl serde::Serialize for ForwardPort {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.spec_string())
    }
}

impl<'de> serde::Deserialize<'de> for ForwardPort {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

impl ForwardPort {
    /// Builds a forward from its four raw parts (empty `to_port`/`to_addr`
    /// mean "not set"). The single constructor for every row/tuple source —
    /// UI table rows and D-Bus tuples both funnel through here.
    #[must_use]
    pub fn from_parts(port: &str, protocol: &str, to_port: &str, to_addr: &str) -> Option<Self> {
        use std::fmt::Write as _;
        let mut spec = format!("port={port}:proto={protocol}");
        if !to_port.is_empty() {
            let _ = write!(spec, ":toport={to_port}");
        }
        if !to_addr.is_empty() {
            let _ = write!(spec, ":toaddr={to_addr}");
        }
        spec.parse().ok()
    }

    /// The exact firewall-cmd forward-port syntax; also what `FromStr` accepts.
    #[must_use]
    pub fn spec_string(&self) -> String {
        use std::fmt::Write as _;
        let mut spec = format!("port={}:proto={}", self.port, self.protocol);
        if let Some(to_port) = self.to_port {
            let _ = write!(spec, ":toport={to_port}");
        }
        if let Some(to_addr) = self.to_addr {
            let _ = write!(spec, ":toaddr={to_addr}");
        }
        spec
    }
}

impl FromStr for ForwardPort {
    type Err = ValidationError;

    /// `port=8080:proto=tcp[:toport=80][:toaddr=10.0.0.5]` — `toaddr` is split
    /// off first because IPv6 addresses contain `:`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || ValidationError::InvalidForwardPort(s.to_owned());
        let (rest, to_addr) = match s.split_once(":toaddr=") {
            Some((head, tail)) => (head, Some(tail)),
            None => (s, None),
        };
        let (rest, to_port) = match rest.split_once(":toport=") {
            Some((head, tail)) => (head, Some(tail)),
            None => (rest, None),
        };
        let (rest, protocol) = match rest.split_once(":proto=") {
            Some((head, tail)) => (head, Some(tail)),
            None => (rest, None),
        };
        let port = rest.strip_prefix("port=").ok_or_else(bad)?;
        Ok(Self {
            port: port.parse()?,
            protocol: protocol.ok_or_else(bad)?.parse()?,
            to_port: to_port
                .filter(|value| !value.is_empty())
                .map(str::parse)
                .transpose()?,
            to_addr: to_addr
                .filter(|value| !value.is_empty())
                .map(IpAddr::from_str)
                .transpose()
                .map_err(|_| bad())?,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_port_spec() {
        let spec: PortSpec = "8080/tcp".parse().unwrap();
        assert_eq!(spec.to_string(), "8080/tcp");
        assert_eq!(spec.protocol, Protocol::Tcp);
    }

    #[test]
    fn parses_port_range_spec() {
        let spec: PortSpec = "5000-5010/udp".parse().unwrap();
        assert_eq!(spec.to_string(), "5000-5010/udp");
    }

    #[test]
    fn port_selector_uses_one_validated_string_representation() {
        let selector: PortSelector = "8000-8080".parse().unwrap();
        let encoded = serde_json::to_string(&selector).unwrap();
        assert_eq!(encoded, "\"8000-8080\"");
        assert_eq!(
            serde_json::from_str::<PortSelector>(&encoded).unwrap(),
            selector
        );
        assert!(serde_json::from_str::<PortSelector>("\"0\"").is_err());
    }

    #[test]
    fn rejects_port_zero() {
        assert!(matches!(
            "0/tcp".parse::<PortSpec>(),
            Err(ValidationError::InvalidPort(_))
        ));
    }

    #[test]
    fn rejects_inverted_range() {
        assert!(matches!(
            "10-5/tcp".parse::<PortSpec>(),
            Err(ValidationError::InvalidRange(_))
        ));
    }

    #[test]
    fn rejects_missing_protocol() {
        assert!(matches!(
            "80".parse::<PortSpec>(),
            Err(ValidationError::InvalidPortSpec(_))
        ));
    }

    #[test]
    fn forward_port_round_trips_through_spec_string() {
        for spec in [
            "port=8080:proto=tcp:toport=80:toaddr=10.0.0.5",
            "port=443:proto=tcp:toport=8443:toaddr=2001:db8::1",
            "port=53:proto=udp",
        ] {
            let parsed: ForwardPort = spec.parse().unwrap();
            assert_eq!(parsed.spec_string(), spec);
        }
    }

    #[test]
    fn forward_port_rejects_garbage() {
        assert!("proto=tcp".parse::<ForwardPort>().is_err());
        assert!("port=eighty:proto=tcp".parse::<ForwardPort>().is_err());
        assert!(
            "port=80:proto=tcp:toaddr=nope"
                .parse::<ForwardPort>()
                .is_err()
        );
    }

    #[test]
    fn rejects_unknown_protocol() {
        assert!(matches!(
            "80/icmp".parse::<PortSpec>(),
            Err(ValidationError::InvalidProtocol(_))
        ));
    }
}
