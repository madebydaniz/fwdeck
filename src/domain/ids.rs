//! Validated identifier newtypes. Every value that ends up in a `firewall-cmd`
//! argument vector must pass through one of these constructors first.

use std::fmt;

/// Validation failure for any user- or backend-supplied value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    /// The value is empty.
    #[error("{kind} must not be empty")]
    Empty {
        /// Human-readable identifier kind, e.g. `"zone name"`.
        kind: &'static str,
    },
    /// The value exceeds the identifier kind's length limit.
    #[error("{kind} `{value}` exceeds {max} characters")]
    TooLong {
        /// Human-readable identifier kind.
        kind: &'static str,
        /// The rejected input.
        value: String,
        /// Maximum length for this kind.
        max: usize,
    },
    /// The value contains a character outside the kind's allowed set.
    #[error("{kind} `{value}` contains invalid character `{ch}`")]
    InvalidChar {
        /// Human-readable identifier kind.
        kind: &'static str,
        /// The rejected input.
        value: String,
        /// The first offending character.
        ch: char,
    },
    /// Not a number in `1..=65535`.
    #[error("invalid port `{0}`: expected a number between 1 and 65535")]
    InvalidPort(String),
    /// Port range start exceeds end.
    #[error("invalid port range `{0}`: start must not exceed end")]
    InvalidRange(String),
    /// Unknown transport protocol keyword.
    #[error("invalid protocol `{0}`: expected tcp, udp, sctp or dccp")]
    InvalidProtocol(String),
    /// Malformed `<port>[-<port>]/<protocol>` spec.
    #[error("invalid port spec `{0}`: expected <port>[-<port>]/<protocol>")]
    InvalidPortSpec(String),
    /// Not an IP, CIDR, MAC, or `ipset:<name>` reference.
    #[error("invalid source `{0}`: expected an IP address, CIDR, MAC or ipset:<name>")]
    InvalidSource(String),
    /// Rich rule text does not start with `rule`.
    #[error("rich rule must start with `rule`")]
    InvalidRichRule,
    /// Unknown zone target keyword.
    #[error("invalid zone target `{0}`: expected default, ACCEPT, DROP or %%REJECT%%")]
    InvalidZoneTarget(String),
    /// Unknown `LogDenied` keyword.
    #[error("invalid LogDenied value `{0}`")]
    InvalidLogDenied(String),
    /// Malformed `port=<p>:proto=<proto>[:toport=<p>][:toaddr=<ip>]` spec.
    #[error(
        "invalid forward port `{0}`: expected port=<p>:proto=<proto>[:toport=<p>][:toaddr=<ip>]"
    )]
    InvalidForwardPort(String),
    /// An ipset entry with whitespace, control characters, or empty/oversized.
    #[error("invalid ipset entry `{0}`: expected a single token with no spaces")]
    InvalidIpSetEntry(String),
}

/// Shared identifier check: non-empty, at most `max` bytes, ASCII
/// alphanumeric plus the characters in `extra`.
fn validate(
    raw: &str,
    kind: &'static str,
    max: usize,
    extra: &[char],
) -> Result<(), ValidationError> {
    if raw.is_empty() {
        return Err(ValidationError::Empty { kind });
    }
    if raw.len() > max {
        return Err(ValidationError::TooLong {
            kind,
            value: raw.to_owned(),
            max,
        });
    }
    if let Some(ch) = raw
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && !extra.contains(c))
    {
        return Err(ValidationError::InvalidChar {
            kind,
            value: raw.to_owned(),
            ch,
        });
    }
    Ok(())
}

macro_rules! identifier {
    ($(#[$meta:meta])* $name:ident, $kind:literal, $max:expr, $extra:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Validates `raw` against this identifier's length and character
            /// rules; safe for `firewall-cmd` argument vectors afterwards.
            pub fn parse(raw: &str) -> Result<Self, ValidationError> {
                validate(raw, $kind, $max, $extra)?;
                Ok(Self(raw.to_owned()))
            }

            // Feeds `firewall-cmd` argv construction; not every
            // identifier type has a caller yet.
            /// The validated name as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(d)?;
                Self::parse(&raw).map_err(serde::de::Error::custom)
            }
        }
    };
}

identifier!(
    /// A firewalld zone name (firewalld caps zone names at 17 characters).
    ZoneName,
    "zone name",
    17,
    &['_', '-']
);

identifier!(
    /// A firewalld service name, e.g. `dhcpv6-client`.
    ServiceName,
    "service name",
    64,
    &['_', '-', '.']
);
identifier!(
    /// A network interface name, e.g. `eth0`, `br-lan`, `eth0.100`.
    InterfaceName,
    "interface name",
    15,
    &['_', '-', '.', '@', ':']
);
identifier!(
    /// A firewalld ipset name.
    IpSetName,
    "ipset name",
    64,
    &['_', '-', '.']
);
identifier!(
    /// A firewalld ICMP type name, e.g. `echo-request`.
    IcmpType,
    "icmp type",
    32,
    &['_', '-']
);

identifier!(
    /// A firewalld policy name. Shipped policy-set members exceed the zone
    /// name limit (for example `gateway-lan-to-world`).
    PolicyName,
    "policy name",
    64,
    &['_', '-']
);

/// Maximum length firewalld accepts when creating a user policy. Shipped
/// policies may be longer, so observation uses [`PolicyName::parse`] while
/// creation paths use [`PolicyName::parse_user_created`].
pub const USER_POLICY_NAME_MAX: usize = 17;

impl PolicyName {
    /// Parses a policy name that will be passed to `--new-policy`.
    pub fn parse_user_created(raw: &str) -> Result<Self, ValidationError> {
        let policy = Self::parse(raw)?;
        if policy.as_str().len() > USER_POLICY_NAME_MAX {
            return Err(ValidationError::TooLong {
                kind: "policy name",
                value: raw.to_owned(),
                max: USER_POLICY_NAME_MAX,
            });
        }
        Ok(policy)
    }

    /// Whether this observed name is valid for a new user-created policy.
    #[must_use]
    pub fn is_user_creatable(&self) -> bool {
        self.as_str().len() <= USER_POLICY_NAME_MAX
    }
}
identifier!(
    /// A predefined firewalld policy-set name used by `--policy-set`.
    PolicySetName,
    "policy-set name",
    17,
    &['_', '-']
);
identifier!(
    /// An IP protocol for `--add-protocol`, e.g. `gre`, `esp`, `ah`, `igmp`,
    /// `ipv6-icmp`, or a numeric protocol value. firewalld validates it against
    /// `/etc/protocols`; this only enforces a safe argv token.
    IpProtocol,
    "ip protocol",
    16,
    &['-']
);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_names() {
        assert_eq!(ZoneName::parse("public").unwrap().as_str(), "public");
        assert_eq!(
            ServiceName::parse("dhcpv6-client").unwrap().as_str(),
            "dhcpv6-client"
        );
        assert_eq!(
            InterfaceName::parse("eth0.100").unwrap().as_str(),
            "eth0.100"
        );
        assert_eq!(
            PolicyName::parse("gateway-lan-to-world").unwrap().as_str(),
            "gateway-lan-to-world"
        );
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            ZoneName::parse(""),
            Err(ValidationError::Empty { .. })
        ));
    }

    #[test]
    fn rejects_too_long_zone_name() {
        assert!(matches!(
            ZoneName::parse("a-very-long-zone-name"),
            Err(ValidationError::TooLong { max: 17, .. })
        ));
    }

    #[test]
    fn user_policy_creation_keeps_firewalld_seventeen_character_limit() {
        assert!(PolicyName::parse_user_created("direct-web-input").is_ok());
        assert!(PolicyName::parse_user_created("gateway-lan-to-world").is_err());
        assert!(
            PolicyName::parse("gateway-lan-to-world").is_ok(),
            "shipped policies still need to be observable"
        );
    }

    #[test]
    fn rejects_shell_metacharacters() {
        for bad in ["pub;lic", "zone$(id)", "a b", "x'y", "x\"y", "a|b"] {
            assert!(
                matches!(
                    ZoneName::parse(bad),
                    Err(ValidationError::InvalidChar { .. })
                ),
                "expected `{bad}` to be rejected"
            );
        }
    }
}
