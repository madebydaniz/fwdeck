//! Parsers for `firewall-cmd` output. Tolerant of unknown attributes (forward
//! compatibility across firewalld versions) but strict about the values they
//! do consume: everything goes through the domain's validating constructors.
//!
//! Formats are pinned by real fixtures in `tests/fixtures/firewall_cmd/`.

use std::collections::BTreeMap;
use std::str::FromStr;

use crate::application::ports::FirewallError;
use crate::domain::{
    ActiveZone, ForwardPort, IcmpType, InterfaceName, IpProtocol, IpSetInfo, IpSetName,
    NetfilterBackend, PolicyDetails, PolicyName, PolicyTarget, RichRule, ServiceDefinition,
    ServiceName, SourceAddress, ValidationError, ZoneDetails, ZoneName,
};

/// A parser rejection with a message naming the offending line/value.
/// Converts into [`FirewallError::Parse`] at the backend boundary.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ParseError(String);

impl ParseError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl From<ParseError> for FirewallError {
    fn from(err: ParseError) -> Self {
        Self::Parse(err.to_string())
    }
}

/// `--get-default-zone`: a single zone name.
pub fn parse_default_zone(raw: &str) -> Result<ZoneName, ParseError> {
    let name = raw.trim();
    ZoneName::parse(name)
        .map_err(|err| ParseError::new(format!("invalid default zone `{name}`: {err}")))
}

/// `--get-active-zones`:
/// ```text
/// public (default)
///   interfaces: eth0
/// home
///   sources: 192.168.1.0/24
/// ```
pub fn parse_active_zones(raw: &str) -> Result<BTreeMap<ZoneName, ActiveZone>, ParseError> {
    let mut zones: BTreeMap<ZoneName, ActiveZone> = BTreeMap::new();
    let mut current: Option<ZoneName> = None;

    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            let zone = current.as_ref().ok_or_else(|| {
                ParseError::new(format!("active-zones attribute without a zone: `{line}`"))
            })?;
            let (key, value) = split_attribute(line)?;
            let Some(entry) = zones.get_mut(zone) else {
                continue;
            };
            match key {
                "interfaces" => {
                    entry.interfaces = parse_items(value, InterfaceName::parse, "interface")?;
                }
                "sources" => {
                    entry.sources = parse_items(value, SourceAddress::parse, "source")?;
                }
                _ => {}
            }
        } else {
            let zone = parse_zone_header(line)?;
            zones.insert(zone.clone(), ActiveZone::default());
            current = Some(zone);
        }
    }
    Ok(zones)
}

/// `--list-all-zones` (runtime or `--permanent`): blank-line-separated blocks,
/// two-space-indented `key: value` attributes, tab-indented entries for the
/// multi-value sections (forward-ports, rich rules).
#[must_use]
pub fn parse_list_all_zones(raw: &str) -> (BTreeMap<ZoneName, ZoneDetails>, Vec<String>) {
    let mut zones: BTreeMap<ZoneName, ZoneDetails> = BTreeMap::new();
    let mut degraded: Vec<String> = Vec::new();

    // Group the output into per-zone blocks (a new block begins at each
    // non-indented header line) and parse each one independently: a single
    // malformed zone then degrades only itself instead of blanking the whole
    // snapshot.
    let mut block: Vec<&str> = Vec::new();
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with([' ', '\t']) && !block.is_empty() {
            flush_zone_block(&block, &mut zones, &mut degraded);
            block.clear();
        }
        block.push(line);
    }
    flush_zone_block(&block, &mut zones, &mut degraded);
    (zones, degraded)
}

/// Parses one zone block, recording a degraded entry (keyed by the zone header)
/// instead of failing the whole listing when a single zone is malformed.
fn flush_zone_block(
    block: &[&str],
    zones: &mut BTreeMap<ZoneName, ZoneDetails>,
    degraded: &mut Vec<String>,
) {
    if block.is_empty() {
        return;
    }
    match parse_zone_block(block) {
        Ok((zone, details)) => {
            zones.insert(zone, details);
        }
        Err(err) => {
            let name = block.first().map_or("<unknown>", |header| header.trim());
            degraded.push(format!("zone `{name}` unparseable: {err}"));
        }
    }
}

fn parse_zone_block(block: &[&str]) -> Result<(ZoneName, ZoneDetails), ParseError> {
    #[derive(Clone, Copy, PartialEq)]
    enum Section {
        None,
        ForwardPorts,
        RichRules,
    }

    let (header, rest) = block
        .split_first()
        .ok_or_else(|| ParseError::new("empty zone block"))?;
    if header.starts_with([' ', '\t']) {
        return Err(ParseError::new(format!(
            "zone attribute before any zone header: `{header}`"
        )));
    }
    let zone = parse_zone_header(header)?;
    let mut details = ZoneDetails::empty(zone.clone());
    let mut section = Section::None;

    for line in rest {
        if line.trim().is_empty() {
            section = Section::None;
            continue;
        }
        if line.starts_with('\t') {
            let entry = line.trim();
            match section {
                Section::ForwardPorts => details.forward_ports.push(parse_forward_port(entry)?),
                Section::RichRules => details.rich_rules.push(
                    RichRule::parse(entry)
                        .map_err(|err| ParseError::new(format!("invalid rich rule: {err}")))?,
                ),
                Section::None => {
                    return Err(ParseError::new(format!(
                        "entry line outside a known section: `{entry}`"
                    )));
                }
            }
            continue;
        }

        let (key, value) = split_attribute(line)?;
        section = Section::None;
        match key {
            "target" => {
                details.target = value
                    .parse()
                    .map_err(|err: ValidationError| ParseError::new(err.to_string()))?;
            }
            "interfaces" => {
                details.interfaces = parse_items(value, InterfaceName::parse, "interface")?;
            }
            "sources" => {
                details.sources = parse_items(value, SourceAddress::parse, "source")?;
            }
            "services" => {
                details.services = parse_items(value, ServiceName::parse, "service")?;
            }
            "ports" => {
                details.ports = parse_items(value, str::parse, "port")?;
            }
            "icmp-blocks" => {
                details.icmp_blocks = parse_items(value, IcmpType::parse, "icmp type")?;
            }
            "masquerade" => details.masquerade = value == "yes",
            "forward" => details.forward = value == "yes",
            "icmp-block-inversion" => details.icmp_block_inversion = value == "yes",
            "source-ports" => {
                details.source_ports = parse_items(value, str::parse, "source port")?;
            }
            "protocols" => {
                details.protocols = parse_items(value, IpProtocol::parse, "protocol")?;
            }
            "forward-ports" => {
                section = Section::ForwardPorts;
                for token in value.split_whitespace() {
                    details.forward_ports.push(parse_forward_port(token)?);
                }
            }
            "rich rules" => {
                section = Section::RichRules;
                if !value.is_empty() {
                    details.rich_rules.push(
                        RichRule::parse(value)
                            .map_err(|err| ParseError::new(format!("invalid rich rule: {err}")))?,
                    );
                }
            }
            // ingress-priority / egress-priority are intentionally ignored
            // (policy-only ordering that has no zone view yet).
            _ => {}
        }
    }
    Ok((zone, details))
}

/// `FirewallBackend=` from `/etc/firewalld/firewalld.conf`.
#[must_use]
pub fn parse_conf_backend(conf: &str) -> NetfilterBackend {
    conf.lines()
        .filter_map(|line| line.trim().strip_prefix("FirewallBackend="))
        .next_back()
        .map_or(NetfilterBackend::Unknown, |value| match value.trim() {
            "nftables" => NetfilterBackend::Nftables,
            "iptables" => NetfilterBackend::Iptables,
            _ => NetfilterBackend::Unknown,
        })
}

/// Strips `(default, active)`-style suffixes from a zone header line.
fn parse_zone_header(line: &str) -> Result<ZoneName, ParseError> {
    let name = line.split_once(" (").map_or(line, |(name, _)| name).trim();
    ZoneName::parse(name)
        .map_err(|err| ParseError::new(format!("invalid zone header `{line}`: {err}")))
}

/// Splits an indented `key: value` attribute line, trimming both sides.
fn split_attribute(line: &str) -> Result<(&str, &str), ParseError> {
    line.trim_start()
        .split_once(':')
        .map(|(key, value)| (key.trim(), value.trim()))
        .ok_or_else(|| ParseError::new(format!("expected `key: value`, got `{line}`")))
}

/// Parses a whitespace-separated list with `parse`, failing on the first
/// invalid item (`what` names the item kind in the error).
fn parse_items<T, E: std::fmt::Display>(
    value: &str,
    parse: impl Fn(&str) -> Result<T, E>,
    what: &str,
) -> Result<Vec<T>, ParseError> {
    value
        .split_whitespace()
        .map(|item| {
            parse(item).map_err(|err| ParseError::new(format!("invalid {what} `{item}`: {err}")))
        })
        .collect()
}

/// Delegates to the domain's `ForwardPort` parser (same syntax both ways).
fn parse_forward_port(entry: &str) -> Result<ForwardPort, ParseError> {
    ForwardPort::from_str(entry).map_err(|err| ParseError::new(err.to_string()))
}

/// `--get-policies`: whitespace-separated policy names.
pub fn parse_policy_names(raw: &str) -> Result<Vec<PolicyName>, ParseError> {
    parse_items(raw, PolicyName::parse, "policy name")
}

/// `--info-policy=<name>` block. The first line is the policy name (with an
/// optional `(active)` marker); the rest are `key: value` attributes.
pub fn parse_policy_info(raw: &str) -> Result<PolicyDetails, ParseError> {
    #[derive(Clone, Copy, PartialEq)]
    enum Section {
        None,
        ForwardPorts,
        RichRules,
    }

    let mut lines = raw.lines();
    let header = lines
        .next()
        .ok_or_else(|| ParseError::new("empty policy info"))?;
    let name = header.split_whitespace().next().unwrap_or("").trim();
    let name = PolicyName::parse(name)
        .map_err(|err| ParseError::new(format!("invalid policy `{name}`: {err}")))?;
    let mut details = PolicyDetails::empty(name);
    details.active = header.split_whitespace().any(|token| token == "(active)");
    let mut section = Section::None;
    for line in lines {
        if line.starts_with('\t') {
            let entry = line.trim();
            match section {
                Section::ForwardPorts => details.forward_ports.push(parse_forward_port(entry)?),
                Section::RichRules => details.rich_rules.push(
                    RichRule::parse(entry)
                        .map_err(|err| ParseError::new(format!("invalid rich rule: {err}")))?,
                ),
                Section::None => {
                    return Err(ParseError::new(format!(
                        "entry line outside a known policy section: `{entry}`"
                    )));
                }
            }
            continue;
        }
        let Some((key, value)) = line.trim_start().split_once(':') else {
            continue;
        };
        let value = value.trim();
        section = Section::None;
        match key.trim() {
            "disable" => details.disabled = value == "yes",
            "priority" => {
                details.priority = value.parse().map_err(|err| {
                    ParseError::new(format!("invalid policy priority `{value}`: {err}"))
                })?;
            }
            "target" => {
                if let Some(target) = PolicyTarget::parse(value) {
                    details.target = target;
                }
            }
            "ingress-zones" => {
                details.ingress_zones = value.split_whitespace().map(str::to_owned).collect();
            }
            "egress-zones" => {
                details.egress_zones = value.split_whitespace().map(str::to_owned).collect();
            }
            "services" => {
                details.services = parse_items(value, ServiceName::parse, "service")?;
            }
            "ports" => {
                details.ports = parse_items(value, str::parse, "port")?;
            }
            "protocols" => {
                details.protocols = parse_items(value, IpProtocol::parse, "protocol")?;
            }
            "masquerade" => details.masquerade = value == "yes",
            "forward-ports" => {
                section = Section::ForwardPorts;
                for token in value.split_whitespace() {
                    details.forward_ports.push(parse_forward_port(token)?);
                }
            }
            "source-ports" => {
                details.source_ports = parse_items(value, str::parse, "source port")?;
            }
            "icmp-blocks" => {
                details.icmp_blocks = parse_items(value, IcmpType::parse, "icmp type")?;
            }
            "rich rules" => {
                section = Section::RichRules;
                if !value.is_empty() {
                    details.rich_rules.push(
                        RichRule::parse(value)
                            .map_err(|err| ParseError::new(format!("invalid rich rule: {err}")))?,
                    );
                }
            }
            _ => {}
        }
    }
    Ok(details)
}

/// `--get-services`: whitespace-separated service names.
pub fn parse_service_names(raw: &str) -> Result<Vec<ServiceName>, ParseError> {
    parse_items(raw, ServiceName::parse, "service name")
}

/// `--get-ipsets`: whitespace-separated names.
pub fn parse_ipset_names(raw: &str) -> Result<Vec<IpSetName>, ParseError> {
    parse_items(raw, IpSetName::parse, "ipset name")
}

/// `--info-ipset=<name>` block: `type:` and space-separated `entries:`.
#[must_use]
pub fn parse_ipset_info(raw: &str) -> IpSetInfo {
    let mut info = IpSetInfo::default();
    for line in raw.lines() {
        if let Some((key, value)) = line.trim_start().split_once(':') {
            match key.trim() {
                "type" => value.trim().clone_into(&mut info.kind),
                "entries" => {
                    info.entries = value.split_whitespace().map(str::to_owned).collect();
                }
                _ => {}
            }
        }
    }
    info
}

/// `--info-service=<name>` block: `ports:` and `protocols:` lines. Unknown
/// or malformed port entries are skipped — definitions are display-only.
#[must_use]
pub fn parse_service_info(raw: &str) -> ServiceDefinition {
    let mut definition = ServiceDefinition::default();
    for line in raw.lines() {
        if let Some((key, value)) = line.trim_start().split_once(':') {
            match key.trim() {
                "ports" => {
                    definition.ports = value
                        .split_whitespace()
                        .filter_map(|spec| spec.parse().ok())
                        .collect();
                }
                "protocols" => {
                    definition.protocols = value.split_whitespace().map(str::to_owned).collect();
                }
                _ => {}
            }
        }
    }
    definition
}

/// `--direct --get-all-rules`: raw lines, kept verbatim (deprecated feature,
/// display-only).
#[must_use]
pub fn parse_direct_rules(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::domain::Protocol;

    #[test]
    fn forward_port_with_ipv6_target() {
        let fwd = parse_forward_port("port=443:proto=tcp:toport=8443:toaddr=2001:db8::1").unwrap();
        assert_eq!(fwd.protocol, Protocol::Tcp);
        assert_eq!(fwd.to_addr.unwrap().to_string(), "2001:db8::1");
        assert_eq!(fwd.to_port.unwrap().to_string(), "8443");
    }

    #[test]
    fn forward_port_with_empty_optionals() {
        let fwd = parse_forward_port("port=8080:proto=tcp:toport=:toaddr=").unwrap();
        assert!(fwd.to_port.is_none());
        assert!(fwd.to_addr.is_none());
    }

    #[test]
    fn forward_port_rejects_garbage() {
        assert!(parse_forward_port("port=eighty:proto=tcp").is_err());
        assert!(parse_forward_port("proto=tcp").is_err());
    }

    #[test]
    fn parses_source_ports_protocols_forward_and_inversion() {
        let raw = "myzone\n  \
            target: DROP\n  \
            icmp-block-inversion: yes\n  \
            protocols: gre esp\n  \
            forward: yes\n  \
            source-ports: 68/udp 546/udp\n";
        let (zones, _) = parse_list_all_zones(raw);
        let z = &zones[&ZoneName::parse("myzone").unwrap()];
        assert!(z.forward);
        assert!(z.icmp_block_inversion);
        assert_eq!(z.protocols.len(), 2);
        assert_eq!(z.protocols[0].as_str(), "gre");
        assert_eq!(z.source_ports.len(), 2);
        assert_eq!(z.source_ports[0].to_string(), "68/udp");
    }

    #[test]
    fn empty_outputs_yield_empty_collections() {
        assert!(parse_active_zones("").unwrap().is_empty());
        assert!(parse_list_all_zones("").0.is_empty());
        assert!(parse_list_all_zones("\n\n").0.is_empty());
    }

    #[test]
    fn conf_backend_ignores_comments() {
        let conf =
            "# FirewallBackend\n# FirewallBackend=iptables is old\nFirewallBackend=nftables\n";
        assert_eq!(parse_conf_backend(conf), NetfilterBackend::Nftables);
        assert_eq!(parse_conf_backend("# nothing"), NetfilterBackend::Unknown);
    }

    #[test]
    fn attribute_before_zone_header_degrades_only_that_block() {
        let (zones, degraded) = parse_list_all_zones("  target: default\n");
        assert!(zones.is_empty(), "no valid zone parsed");
        assert_eq!(
            degraded.len(),
            1,
            "the malformed block is recorded as degraded, not fatal"
        );
    }

    #[test]
    fn one_bad_zone_degrades_only_itself() {
        // A good zone, then a zone with an invalid target, then another good one.
        let raw = "good1\n  target: default\n  services: ssh\n\nbadzone\n  target: \
                   not-a-valid-target\n\ngood2\n  target: ACCEPT\n";
        let (zones, degraded) = parse_list_all_zones(raw);
        assert!(zones.contains_key(&ZoneName::parse("good1").unwrap()));
        assert!(zones.contains_key(&ZoneName::parse("good2").unwrap()));
        assert!(!zones.contains_key(&ZoneName::parse("badzone").unwrap()));
        assert_eq!(degraded.len(), 1);
        assert!(degraded[0].contains("badzone"));
    }
}
