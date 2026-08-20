//! Fixture-driven parser tests. Fixture structure was captured from a real
//! firewalld (Fedora 42, firewalld 2.3.2) inside the dev container. Selected
//! priority values are deliberately varied to pin signed parsing and drift.

#![allow(clippy::unwrap_used)]
#![allow(clippy::panic, clippy::expect_used)]

use fwdeck::domain::{NetfilterBackend, ZoneName, ZoneTarget};
use fwdeck::infrastructure::firewalld::parse;

const LIST_ALL_RUNTIME: &str = include_str!("fixtures/firewall_cmd/list_all_zones_runtime.txt");
const LIST_ALL_PERMANENT: &str = include_str!("fixtures/firewall_cmd/list_all_zones_permanent.txt");
const ACTIVE_ZONES: &str = include_str!("fixtures/firewall_cmd/active_zones.txt");
const DEFAULT_ZONE: &str = include_str!("fixtures/firewall_cmd/default_zone.txt");
const MALFORMED: &str = include_str!("fixtures/firewall_cmd/malformed.txt");
const CONF_BACKEND: &str = include_str!("fixtures/firewall_cmd/firewalld_conf_backend.txt");

fn zone(name: &str) -> ZoneName {
    ZoneName::parse(name).unwrap()
}

#[test]
fn parses_all_eleven_fedora_zones() {
    let zones = parse::parse_list_all_zones(LIST_ALL_RUNTIME).0;
    assert_eq!(zones.len(), 11);
    for name in [
        "public",
        "home",
        "block",
        "drop",
        "trusted",
        "FedoraWorkstation",
    ] {
        assert!(zones.contains_key(&zone(name)), "missing zone `{name}`");
    }
}

#[test]
fn icmp_blocks_parse_from_list_all() {
    // The seeded public zone gets an echo-request block via the entrypoint;
    // but the committed fixture predates it — assert the parser handles the
    // attribute when present using an inline block.
    let block = "public\n  target: default\n  icmp-blocks: echo-request timestamp-reply\n";
    let zones = parse::parse_list_all_zones(block).0;
    let icmp = &zones[&zone("public")].icmp_blocks;
    assert_eq!(icmp.len(), 2);
    assert_eq!(icmp[0].as_str(), "echo-request");
}

#[test]
fn public_zone_details_are_fully_typed() {
    let zones = parse::parse_list_all_zones(LIST_ALL_RUNTIME).0;
    let public = &zones[&zone("public")];

    assert_eq!(public.target, ZoneTarget::Default);
    assert_eq!(public.interfaces.len(), 1);
    assert_eq!(public.interfaces[0].as_str(), "eth0");
    let services: Vec<&str> = public
        .services
        .iter()
        .map(fwdeck::domain::ServiceName::as_str)
        .collect();
    assert!(services.contains(&"http"));
    assert!(services.contains(&"https"));
    assert!(services.contains(&"ssh"));
    assert_eq!(public.ports.len(), 1);
    assert_eq!(public.ports[0].to_string(), "8080/tcp");
    assert_eq!(public.ingress_priority.get(), -120);
    assert_eq!(public.egress_priority.get(), 240);
    assert!(!public.masquerade);
}

#[test]
fn runtime_and_permanent_zone_priorities_remain_distinct() {
    let runtime = parse::parse_list_all_zones(LIST_ALL_RUNTIME).0;
    let permanent = parse::parse_list_all_zones(LIST_ALL_PERMANENT).0;
    let public = zone("public");

    assert_eq!(runtime[&public].ingress_priority.get(), -120);
    assert_eq!(runtime[&public].egress_priority.get(), 240);
    assert_eq!(permanent[&public].ingress_priority.get(), -100);
    assert_eq!(permanent[&public].egress_priority.get(), 200);
    assert_ne!(runtime[&public], permanent[&public]);
}

#[test]
fn malformed_priority_degrades_only_its_zone() {
    let raw = "broken\n  target: default\n  ingress-priority: not-a-number\n  egress-priority: 0\n\ntrusted\n  target: ACCEPT\n  ingress-priority: -32768\n  egress-priority: 32767\n";
    let (zones, degraded) = parse::parse_list_all_zones(raw);

    assert!(!zones.contains_key(&zone("broken")));
    assert_eq!(zones[&zone("trusted")].ingress_priority.get(), -32_768);
    assert_eq!(zones[&zone("trusted")].egress_priority.get(), 32_767);
    assert_eq!(degraded.len(), 1);
    assert!(degraded[0].contains("broken"));
    assert!(degraded[0].contains("not-a-number"));
}

#[test]
fn tab_indented_forward_ports_and_rich_rules_attach_to_their_zone() {
    let zones = parse::parse_list_all_zones(LIST_ALL_RUNTIME).0;
    let public = &zones[&zone("public")];

    assert_eq!(public.forward_ports.len(), 1);
    let fwd = &public.forward_ports[0];
    assert_eq!(fwd.port.to_string(), "8080");
    assert_eq!(fwd.to_port.unwrap().to_string(), "80");
    assert_eq!(fwd.to_addr.unwrap().to_string(), "10.0.0.5");

    assert_eq!(public.rich_rules.len(), 1);
    // Round-trip safety: the raw rule text survives verbatim.
    assert_eq!(
        public.rich_rules[0].as_str(),
        r#"rule family="ipv4" source address="203.0.113.0/24" reject"#
    );

    // Entries must not leak into neighboring zones.
    assert!(zones[&zone("trusted")].forward_ports.is_empty());
    assert!(zones[&zone("trusted")].rich_rules.is_empty());
}

#[test]
fn zone_targets_and_port_ranges_parse() {
    let zones = parse::parse_list_all_zones(LIST_ALL_RUNTIME).0;
    assert_eq!(zones[&zone("block")].target, ZoneTarget::Reject);
    assert_eq!(zones[&zone("drop")].target, ZoneTarget::Drop);
    assert_eq!(zones[&zone("trusted")].target, ZoneTarget::Accept);

    let workstation = &zones[&zone("FedoraWorkstation")];
    let ports: Vec<String> = workstation.ports.iter().map(ToString::to_string).collect();
    assert!(ports.contains(&"1025-65535/udp".to_owned()));
    assert!(ports.contains(&"1025-65535/tcp".to_owned()));
}

#[test]
fn runtime_permanent_drift_is_visible_after_parsing() {
    let runtime = parse::parse_list_all_zones(LIST_ALL_RUNTIME).0;
    let permanent = parse::parse_list_all_zones(LIST_ALL_PERMANENT).0;

    let name = zone("public");
    let runtime_services: Vec<&str> = runtime[&name]
        .services
        .iter()
        .map(fwdeck::domain::ServiceName::as_str)
        .collect();
    let permanent_services: Vec<&str> = permanent[&name]
        .services
        .iter()
        .map(fwdeck::domain::ServiceName::as_str)
        .collect();

    // Seeded by the container entrypoint: http/8080 are runtime-only.
    assert!(runtime_services.contains(&"http"));
    assert!(!permanent_services.contains(&"http"));
    assert!(permanent_services.contains(&"https"));
    assert!(permanent[&name].ports.is_empty());
}

#[test]
fn active_zones_strip_header_markers() {
    let active = parse::parse_active_zones(ACTIVE_ZONES).unwrap();
    assert_eq!(active.len(), 2);
    // `public (default)` header must resolve to plain `public`.
    let public = &active[&zone("public")];
    assert_eq!(public.interfaces[0].as_str(), "eth0");
    let home = &active[&zone("home")];
    assert_eq!(home.sources[0].to_string(), "192.168.1.0/24");
}

#[test]
fn default_zone_fixture_parses() {
    assert_eq!(
        parse::parse_default_zone(DEFAULT_ZONE).unwrap(),
        zone("public")
    );
}

#[test]
fn malformed_port_yields_descriptive_error() {
    let (_zones, degraded) = parse::parse_list_all_zones(MALFORMED);
    assert!(
        !degraded.is_empty(),
        "a malformed zone must be recorded as degraded"
    );
    let message = degraded.join(" ");
    assert!(message.contains("notaport"), "unhelpful error: {message}");
}

#[test]
fn conf_backend_fixture_detects_nftables() {
    assert_eq!(
        parse::parse_conf_backend(CONF_BACKEND),
        NetfilterBackend::Nftables
    );
}

const GET_IPSETS: &str = include_str!("fixtures/firewall_cmd/get_ipsets.txt");
const INFO_IPSET: &str = include_str!("fixtures/firewall_cmd/info_ipset.txt");
const DIRECT_RULES: &str = include_str!("fixtures/firewall_cmd/direct_rules.txt");

#[test]
fn ipset_fixtures_parse() {
    let names = parse::parse_ipset_names(GET_IPSETS).unwrap();
    assert_eq!(names.len(), 1);
    assert_eq!(names[0].as_str(), "blocklist");
    let info = parse::parse_ipset_info(INFO_IPSET);
    assert_eq!(info.kind, "hash:ip");
    assert_eq!(info.entries, vec!["203.0.113.9".to_owned()]);
}

#[test]
fn direct_rules_fixture_parses_verbatim() {
    let rules = parse::parse_direct_rules(DIRECT_RULES);
    assert_eq!(rules.len(), 1);
    assert!(rules[0].starts_with("ipv4 filter INPUT 9"));
    assert!(parse::parse_direct_rules("").is_empty());
}

#[test]
fn policy_info_parses() {
    let raw = include_str!("fixtures/firewall_cmd/info_policy.txt");
    let policy = parse::parse_policy_info(raw).unwrap();
    assert_eq!(policy.name.as_str(), "fwdeck-fixture");
    assert!(policy.active);
    assert!(!policy.disabled);
    assert_eq!(policy.priority, -1);
    assert_eq!(policy.target, fwdeck::domain::PolicyTarget::Drop);
    assert_eq!(policy.ingress_zones, vec!["public".to_owned()]);
    assert_eq!(policy.egress_zones, vec!["ANY".to_owned()]);
    assert_eq!(policy.services.len(), 1);
    assert_eq!(policy.ports[0].to_string(), "8080/tcp");
    assert!(policy.protocols.is_empty());
    assert!(!policy.masquerade);
    assert!(policy.forward_ports.is_empty());
    assert!(policy.source_ports.is_empty());
    assert!(policy.icmp_blocks.is_empty());
    assert!(policy.rich_rules.is_empty());
}
