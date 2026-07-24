//! Source addresses as accepted by firewalld zone bindings.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use super::ids::{IpSetName, ValidationError};

/// IP protocol family of a source address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AddressFamily {
    /// IPv4.
    Ipv4,
    /// IPv6.
    Ipv6,
}

impl AddressFamily {
    /// The lowercase spelling firewalld uses (`"ipv4"` / `"ipv6"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

/// A zone source binding: IP/CIDR, MAC address, or `ipset:<name>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourceAddress {
    /// An IP address, optionally with a CIDR prefix length.
    Ip {
        /// The address itself.
        addr: IpAddr,
        /// CIDR prefix length; `None` means a plain host address.
        prefix: Option<u8>,
    },
    /// A MAC address in `aa:bb:cc:dd:ee:ff` form.
    Mac(String),
    /// A reference to a firewalld ipset.
    IpSet(IpSetName),
}

impl SourceAddress {
    /// Parses an IP/CIDR, MAC, or `ipset:<name>` string. Prefix lengths are
    /// checked against the family (max 32 for IPv4, 128 for IPv6).
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        if let Some(name) = raw.strip_prefix("ipset:") {
            return Ok(Self::IpSet(IpSetName::parse(name)?));
        }
        if is_mac(raw) {
            return Ok(Self::Mac(raw.to_owned()));
        }
        let (ip_part, prefix) = match raw.split_once('/') {
            Some((ip, p)) => {
                let prefix: u8 = p
                    .parse()
                    .map_err(|_| ValidationError::InvalidSource(raw.to_owned()))?;
                (ip, Some(prefix))
            }
            None => (raw, None),
        };
        let addr = IpAddr::from_str(ip_part)
            .map_err(|_| ValidationError::InvalidSource(raw.to_owned()))?;
        let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
        if prefix.is_some_and(|p| p > max_prefix) {
            return Err(ValidationError::InvalidSource(raw.to_owned()));
        }
        Ok(Self::Ip { addr, prefix })
    }

    /// The IP family, or `None` for MAC and ipset sources.
    #[must_use]
    pub fn family(&self) -> Option<AddressFamily> {
        match self {
            Self::Ip { addr, .. } => Some(if addr.is_ipv4() {
                AddressFamily::Ipv4
            } else {
                AddressFamily::Ipv6
            }),
            Self::Mac(_) | Self::IpSet(_) => None,
        }
    }
}

/// One ipset entry, stored verbatim. firewalld validates it against the set's
/// declared type — `hash:ip` (`203.0.113.9`), `hash:net` (`10.0.0.0/8`),
/// `hash:ip,port` (`1.2.3.4,tcp:80`), `hash:net,iface` (`10.0.0.0/8,eth0`),
/// `hash:mac` (`aa:bb:cc:dd:ee:ff`), … — so fwdeck does not re-implement that
/// grammar. It only enforces that the entry is a single safe token (non-empty,
/// no whitespace, no control characters, bounded length), which keeps it sound
/// in an argument vector and in the audit trail. Unlike [`SourceAddress`] this
/// admits the compound entry forms.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
pub struct IpSetEntry(String);

impl IpSetEntry {
    /// Validates an ipset entry as a single safe token; firewalld remains the
    /// authority on the type-specific grammar.
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let trimmed = raw.trim();
        if trimmed.is_empty()
            || trimmed.len() > 255
            || trimmed.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(ValidationError::InvalidIpSetEntry(raw.to_owned()));
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// The validated entry as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> serde::Deserialize<'de> for IpSetEntry {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for IpSetEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Six colon-separated pairs of hex digits (`aa:bb:cc:dd:ee:ff`).
fn is_mac(raw: &str) -> bool {
    let parts: Vec<&str> = raw.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

impl serde::Serialize for SourceAddress {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for SourceAddress {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for SourceAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip {
                addr,
                prefix: Some(p),
            } => write!(f, "{addr}/{p}"),
            Self::Ip { addr, prefix: None } => write!(f, "{addr}"),
            Self::Mac(mac) => f.write_str(mac),
            Self::IpSet(name) => write!(f, "ipset:{name}"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_cidr() {
        let src = SourceAddress::parse("192.168.1.0/24").unwrap();
        assert_eq!(src.to_string(), "192.168.1.0/24");
        assert_eq!(src.family(), Some(AddressFamily::Ipv4));
    }

    #[test]
    fn parses_ipv6() {
        let src = SourceAddress::parse("2001:db8::/32").unwrap();
        assert_eq!(src.family(), Some(AddressFamily::Ipv6));
    }

    #[test]
    fn parses_mac() {
        let src = SourceAddress::parse("00:11:22:33:44:55").unwrap();
        assert!(matches!(src, SourceAddress::Mac(_)));
        assert_eq!(src.family(), None);
    }

    #[test]
    fn parses_ipset_reference() {
        let src = SourceAddress::parse("ipset:blocklist").unwrap();
        assert_eq!(src.to_string(), "ipset:blocklist");
    }

    #[test]
    fn rejects_garbage_and_oversized_prefixes() {
        assert!(SourceAddress::parse("not-an-address").is_err());
        assert!(SourceAddress::parse("192.168.1.0/33").is_err());
        assert!(SourceAddress::parse("2001:db8::/129").is_err());
    }

    #[test]
    fn ipset_entry_accepts_simple_and_compound_forms() {
        for entry in [
            "203.0.113.9",             // hash:ip
            "10.0.0.0/8",              // hash:net
            "1.2.3.4,tcp:80",          // hash:ip,port
            "10.0.0.0/8,eth0",         // hash:net,iface
            "aa:bb:cc:dd:ee:ff",       // hash:mac
            "192.168.0.0/16,udp:5353", // hash:net,port
        ] {
            assert!(IpSetEntry::parse(entry).is_ok(), "should accept `{entry}`");
            assert_eq!(IpSetEntry::parse(entry).unwrap().as_str(), entry);
        }
    }

    #[test]
    fn ipset_entry_rejects_unsafe_tokens() {
        assert!(IpSetEntry::parse("").is_err());
        assert!(IpSetEntry::parse("   ").is_err());
        assert!(
            IpSetEntry::parse("1.2.3.4 tcp:80").is_err(),
            "no whitespace"
        );
        assert!(
            IpSetEntry::parse("1.2.3.4\ntcp:80").is_err(),
            "no internal newline"
        );
        assert!(
            IpSetEntry::parse(&"a".repeat(256)).is_err(),
            "bounded length"
        );
        // Surrounding whitespace is trimmed, not rejected.
        assert_eq!(
            IpSetEntry::parse("  1.2.3.4  ").unwrap().as_str(),
            "1.2.3.4"
        );
    }
}
