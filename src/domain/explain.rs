//! "Explain this traffic": a step-by-step account of how firewalld would
//! treat one ingress packet, evaluated against the RUNTIME snapshot.
//!
//! This is an **approximation of firewalld's zone dispatch**, not an nftables
//! simulator: rich rules are matched textually against their raw text, the
//! ingress interface is unknown (so interface-bound zones are only reported as
//! candidates), and rule priorities are ignored. It exists to answer "why is
//! this blocked/allowed" at the zone level, honestly labeled as best-effort.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;

use super::address::{AddressFamily, SourceAddress};
use super::ids::{IpSetName, ServiceName, ZoneName};
use super::port::{PortSelector, PortSpec};
use super::rich_rule::RichRule;
use super::service::ServiceDefinition;
use super::snapshot::{FirewallSnapshot, IpSetInfo};
use super::zone::{ZoneDetails, ZoneTarget};

/// Explains how firewalld would treat ingress traffic from `source` to
/// `port`, as ordered `(step, detail)` lines for a details overlay. An empty
/// step key renders as a plain continuation line.
///
/// Evaluation order (an approximation of firewalld's actual dispatch):
/// zone selection by source binding (exact IP, CIDR containment, or ipset
/// membership; source beats interface), then within the selected zone's
/// runtime config: rich rules (textual match), services, explicit ports, and
/// finally the zone target. Every consulted stage produces a line, matched
/// or not; the first decisive match ends the evaluation with a verdict.
#[must_use]
pub fn explain(snapshot: &FirewallSnapshot, source: &str, port: PortSpec) -> Vec<(String, String)> {
    let mut lines = vec![(
        String::new(),
        "approximation of firewalld's zone dispatch — not an nft simulation".to_owned(),
    )];
    let Ok(ip) = IpAddr::from_str(source) else {
        lines.push((
            "error".to_owned(),
            format!("`{source}` is not a plain IP address"),
        ));
        return lines;
    };

    // Stage 1: zone selection. A matching source binding wins outright;
    // otherwise interface-bound zones are candidates we cannot decide between
    // (the ingress interface is unknown), so we continue with the default zone.
    let by_source = snapshot.runtime.iter().find_map(|(name, details)| {
        details
            .sources
            .iter()
            .find(|binding| source_matches(binding, ip, &snapshot.ipsets.runtime))
            .map(|binding| (name, details, binding))
    });
    let details = if let Some((name, details, binding)) = by_source {
        lines.push((
            "zone".to_owned(),
            format!("`{name}` — source binding {binding} matches {ip} (source beats interface)"),
        ));
        details
    } else {
        lines.push(("zone".to_owned(), format!("no source binding matches {ip}")));
        for (name, zone) in &snapshot.runtime {
            if !zone.interfaces.is_empty() {
                let interfaces = zone
                    .interfaces
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                lines.push((
                    String::new(),
                    format!(
                        "candidate `{name}` if traffic arrives on {interfaces} \
                         (ingress interface unknown)"
                    ),
                ));
            }
        }
        let default = &snapshot.default_zone;
        lines.push((
            String::new(),
            format!("continuing with the default zone `{default}`"),
        ));
        let Some(details) = snapshot.runtime.get(default) else {
            lines.push((
                "error".to_owned(),
                format!("default zone `{default}` has no runtime details in this snapshot"),
            ));
            return lines;
        };
        details
    };

    evaluate_zone(snapshot, details, ip, port, &mut lines);
    lines
}

/// Stages 2–5 within the selected zone's runtime config: rich rules,
/// services, explicit ports, zone target. Appends one line per stage plus a
/// final verdict.
fn evaluate_zone(
    snapshot: &FirewallSnapshot,
    details: &ZoneDetails,
    ip: IpAddr,
    port: PortSpec,
    lines: &mut Vec<(String, String)>,
) {
    let zone = &details.name;

    // Stage 2: rich rules, matched against their raw text — a textual
    // approximation, priorities and non-source conditions are ignored.
    let rich_match = details
        .rich_rules
        .iter()
        .find(|rule| rich_rule_matches(rule, ip, port, &snapshot.service_definitions));
    if let Some(rule) = rich_match {
        lines.push(("rich rules".to_owned(), format!("textual match: {rule}")));
        let action = rule.action().unwrap_or("unknown action");
        lines.push((
            "verdict".to_owned(),
            format!("{action} — by the rich rule above (textual approximation)"),
        ));
        return;
    }
    lines.push((
        "rich rules".to_owned(),
        format!("no match among {}", details.rich_rules.len()),
    ));

    // Stage 3: services whose cached definition opens the port.
    let service_match = details
        .services
        .iter()
        .find(|name| service_opens(snapshot.service_definitions.get(*name), port));
    if let Some(name) = service_match {
        lines.push((
            "services".to_owned(),
            format!("service `{name}` opens {port}"),
        ));
        lines.push((
            "verdict".to_owned(),
            format!("allowed by service `{name}` in zone `{zone}`"),
        ));
        return;
    }
    lines.push((
        "services".to_owned(),
        format!("no match among {}", details.services.len()),
    ));

    // Stage 4: explicitly opened ports (single ports and ranges).
    if let Some(spec) = details.ports.iter().find(|spec| port_covers(**spec, port)) {
        lines.push((
            "ports".to_owned(),
            format!("open port {spec} covers {port}"),
        ));
        lines.push((
            "verdict".to_owned(),
            format!("allowed by open port {spec} in zone `{zone}`"),
        ));
        return;
    }
    lines.push((
        "ports".to_owned(),
        format!("no match among {}", details.ports.len()),
    ));

    // Stage 5: nothing matched — the zone target decides.
    let (label, meaning) = match details.target {
        ZoneTarget::Accept => ("ACCEPT", "allowed — the zone accepts unmatched traffic"),
        ZoneTarget::Drop => ("DROP", "silently dropped — no reply is sent"),
        ZoneTarget::Reject => ("%%REJECT%%", "rejected with an ICMP error"),
        ZoneTarget::Default => (
            "default",
            "rejected with an ICMP error (firewalld's built-in default is reject-like)",
        ),
    };
    lines.push((
        "target".to_owned(),
        format!("no rule matched — zone target `{label}` decides"),
    ));
    lines.push(("verdict".to_owned(), meaning.to_owned()));
}

/// The runtime zone whose source bindings (IP/CIDR/ipset) cover `ip`, if any.
/// This is firewalld's highest-precedence zone dispatch — used by the SSH
/// guard to know which zone actually protects the operator's session.
#[must_use]
pub fn zone_for_source_ip(snapshot: &FirewallSnapshot, ip: IpAddr) -> Option<ZoneName> {
    snapshot
        .runtime
        .iter()
        .find(|(_, details)| {
            details
                .sources
                .iter()
                .any(|binding| source_matches(binding, ip, &snapshot.ipsets.runtime))
        })
        .map(|(zone, _)| zone.clone())
}

/// Whether a zone source binding covers `ip`: exact IP, CIDR containment, or
/// membership in a named ipset. MAC bindings never match an IP query.
fn source_matches(
    binding: &SourceAddress,
    ip: IpAddr,
    ipsets: &BTreeMap<IpSetName, IpSetInfo>,
) -> bool {
    match binding {
        SourceAddress::Ip { addr, prefix: None } => *addr == ip,
        SourceAddress::Ip {
            addr,
            prefix: Some(prefix),
        } => cidr_contains(*addr, *prefix, ip),
        SourceAddress::IpSet(name) => ipsets
            .get(name)
            .is_some_and(|set| set.entries.iter().any(|entry| entry_matches(entry, ip))),
        SourceAddress::Mac(_) => false,
    }
}

/// Whether one raw address string (an ipset entry or a rich-rule source)
/// covers `ip`, by exact address or CIDR containment.
fn entry_matches(entry: &str, ip: IpAddr) -> bool {
    match SourceAddress::parse(entry) {
        Ok(SourceAddress::Ip { addr, prefix: None }) => addr == ip,
        Ok(SourceAddress::Ip {
            addr,
            prefix: Some(prefix),
        }) => cidr_contains(addr, prefix, ip),
        _ => false,
    }
}

/// CIDR containment: is `candidate` inside `network/prefix`? Families must
/// match; the comparison is plain bit math on the address octets.
fn cidr_contains(network: IpAddr, prefix: u8, candidate: IpAddr) -> bool {
    match (network, candidate) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => masked_eq(&net.octets(), &ip.octets(), prefix),
        (IpAddr::V6(net), IpAddr::V6(ip)) => masked_eq(&net.octets(), &ip.octets(), prefix),
        _ => false,
    }
}

/// Whether the first `prefix` bits of two equal-length octet slices agree.
fn masked_eq(net: &[u8], ip: &[u8], prefix: u8) -> bool {
    let mut remaining = prefix;
    for (n, i) in net.iter().zip(ip) {
        if remaining == 0 {
            return true;
        }
        if remaining >= 8 {
            if n != i {
                return false;
            }
            remaining -= 8;
        } else {
            let mask = 0xff_u8 << (8 - remaining);
            return (n & mask) == (i & mask);
        }
    }
    true
}

/// Best-effort textual rich-rule match: the raw text must carry a
/// `source address="…"` covering `ip` (family-compatible), and either no
/// port/service condition, a `port port="…" protocol="…"` covering the query,
/// or a `service name="…"` whose cached definition opens the queried port.
fn rich_rule_matches(
    rule: &RichRule,
    ip: IpAddr,
    port: PortSpec,
    definitions: &BTreeMap<ServiceName, ServiceDefinition>,
) -> bool {
    let family = if ip.is_ipv4() {
        AddressFamily::Ipv4
    } else {
        AddressFamily::Ipv6
    };
    if rule.family().is_some_and(|f| f != family.as_str()) {
        return false;
    }
    let raw = rule.as_str();
    let Some(source) = attr(raw, "source address") else {
        return false;
    };
    if !entry_matches(source, ip) {
        return false;
    }
    if let Some(rule_port) = attr(raw, "port port") {
        return attr(raw, "protocol") == Some(port.protocol.as_str())
            && rule_port
                .parse::<PortSelector>()
                .is_ok_and(|selector| selector_covers(selector, port.port));
    }
    if let Some(service) = attr(raw, "service name") {
        return ServiceName::parse(service)
            .is_ok_and(|name| service_opens(definitions.get(&name), port));
    }
    true // source-wide rule with no port/service condition
}

/// Extracts the value of a `key="value"` attribute from raw rich-rule text.
fn attr<'a>(raw: &'a str, key: &str) -> Option<&'a str> {
    let pattern = format!("{key}=\"");
    let start = raw.find(&pattern)? + pattern.len();
    raw.get(start..)?.split('"').next()
}

/// Whether a cached service definition opens the queried port.
fn service_opens(definition: Option<&ServiceDefinition>, port: PortSpec) -> bool {
    definition.is_some_and(|def| def.ports.iter().any(|spec| port_covers(*spec, port)))
}

/// Whether `rule` covers `query`: same protocol, and the queried port(s) fall
/// entirely inside the rule's port or range.
fn port_covers(rule: PortSpec, query: PortSpec) -> bool {
    rule.protocol == query.protocol && selector_covers(rule.port, query.port)
}

/// Whether the queried selector lies entirely inside the rule's selector.
fn selector_covers(rule: PortSelector, query: PortSelector) -> bool {
    let (rule_start, rule_end) = bounds(rule);
    let (query_start, query_end) = bounds(query);
    rule_start <= query_start && query_end <= rule_end
}

/// Inclusive `(start, end)` bounds of a port selector.
fn bounds(selector: PortSelector) -> (u16, u16) {
    match selector {
        PortSelector::Single(port) => (port.get(), port.get()),
        PortSelector::Range(range) => (range.start().get(), range.end().get()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::domain::mock;

    fn run(source: &str, port: &str) -> Vec<(String, String)> {
        let snapshot = mock::sample().unwrap();
        explain(&snapshot, source, port.parse().unwrap())
    }

    fn value_of<'a>(lines: &'a [(String, String)], key: &str) -> &'a str {
        &lines.iter().find(|(k, _)| k == key).unwrap().1
    }

    #[test]
    fn source_cidr_selects_the_home_zone() {
        let lines = run("192.168.1.7", "443/tcp");
        let zone = value_of(&lines, "zone");
        assert!(zone.contains("`home`"), "zone line: {zone}");
        assert!(zone.contains("192.168.1.0/24"));
        // home opens neither 443/tcp nor a matching service → target decides.
        assert!(value_of(&lines, "verdict").contains("rejected"));
    }

    #[test]
    fn service_allows_port_in_the_default_zone() {
        // 10.1.2.3 matches no source binding → default zone `public`,
        // where the https service (443/tcp) is enabled.
        let lines = run("10.1.2.3", "443/tcp");
        assert!(value_of(&lines, "zone").contains("no source binding"));
        assert!(value_of(&lines, "services").contains("`https`"));
        assert!(value_of(&lines, "verdict").contains("allowed by service `https`"));
    }

    #[test]
    fn explicit_port_allows_traffic() {
        let lines = run("10.1.2.3", "8080/tcp");
        assert!(value_of(&lines, "ports").contains("8080/tcp"));
        assert!(value_of(&lines, "verdict").contains("allowed by open port"));
    }

    #[test]
    fn port_range_containment_allows_traffic() {
        // public opens 5000-5010/udp; 5005/udp falls inside.
        let lines = run("10.1.2.3", "5005/udp");
        assert!(value_of(&lines, "verdict").contains("5000-5010/udp"));
    }

    #[test]
    fn unmatched_port_falls_through_to_the_zone_target() {
        let lines = run("10.1.2.3", "12345/tcp");
        assert!(value_of(&lines, "rich rules").contains("no match"));
        assert!(value_of(&lines, "services").contains("no match"));
        assert!(value_of(&lines, "ports").contains("no match"));
        assert!(value_of(&lines, "target").contains("`default`"));
        assert!(value_of(&lines, "verdict").contains("reject"));
    }

    #[test]
    fn rich_rule_matches_first_and_decides() {
        // public carries `source address="203.0.113.0/24" … reject`.
        let lines = run("203.0.113.7", "443/tcp");
        assert!(value_of(&lines, "rich rules").contains("203.0.113.0/24"));
        assert!(value_of(&lines, "verdict").starts_with("reject"));
    }

    #[test]
    fn cidr_containment_v4_boundaries() {
        let net: IpAddr = "192.168.1.0".parse().unwrap();
        assert!(cidr_contains(net, 24, "192.168.1.1".parse().unwrap()));
        assert!(cidr_contains(net, 24, "192.168.1.255".parse().unwrap()));
        assert!(!cidr_contains(net, 24, "192.168.2.0".parse().unwrap()));
        // Non-octet-aligned prefix: /25 splits the last octet.
        assert!(cidr_contains(net, 25, "192.168.1.127".parse().unwrap()));
        assert!(!cidr_contains(net, 25, "192.168.1.128".parse().unwrap()));
    }

    #[test]
    fn cidr_containment_v6() {
        let net: IpAddr = "2001:db8::".parse().unwrap();
        assert!(cidr_contains(net, 32, "2001:db8::1".parse().unwrap()));
        assert!(cidr_contains(net, 32, "2001:db8:ffff::1".parse().unwrap()));
        assert!(!cidr_contains(net, 32, "2001:db9::1".parse().unwrap()));
        // Families never mix.
        assert!(!cidr_contains(net, 32, "192.168.1.1".parse().unwrap()));
    }
}
