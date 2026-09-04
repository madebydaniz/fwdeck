#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;
use crate::domain::{IcmpType, Scoped, TrafficScenarioId, TrafficSeverity};

fn scenario(source: &str, transport: TrafficTransport) -> TrafficScenario {
    TrafficScenario {
        id: TrafficScenarioId::parse("private-helper").unwrap(),
        name: "Private helper scenario".to_owned(),
        enabled: true,
        direction: crate::domain::TrafficDirection::ToHost,
        source: SourceAddress::parse(source).unwrap(),
        ingress_interface: None,
        ingress_zone: None,
        destination: crate::domain::TrafficDestination::LocalHost,
        egress_interface: None,
        egress_zone: None,
        transport,
        destination_port: None,
        source_port: None,
        connection_state: TrafficConnectionState::New,
        expectation: TrafficExpectation::Allow,
        severity: TrafficSeverity::Critical,
        required_safety_gate: true,
        note: None,
    }
}

#[test]
fn protocol_helpers_cover_every_supported_transport_family() {
    let udp = scenario("192.0.2.1", TrafficTransport::Udp);
    assert_eq!(scenario_protocol(&udp), Some("udp"));
    let icmp4 = scenario(
        "192.0.2.1",
        TrafficTransport::Icmp {
            icmp_type: IcmpType::parse("echo-request").unwrap(),
        },
    );
    assert_eq!(scenario_protocol(&icmp4), Some("icmp"));
    assert!(transport_protocol(&icmp4.transport).is_none());
    let icmp6 = scenario(
        "2001:db8::1",
        TrafficTransport::Icmp {
            icmp_type: IcmpType::parse("echo-request").unwrap(),
        },
    );
    assert_eq!(scenario_protocol(&icmp6), Some("ipv6-icmp"));
    let raw = TrafficTransport::RawProtocol {
        protocol: crate::domain::IpProtocol::parse("gre").unwrap(),
    };
    assert!(transport_protocol(&raw).is_none());
}

#[test]
fn cidr_helpers_cover_ipv6_partial_masks_and_cross_family_rejection() {
    let network = IpAddr::V6("2001:db8::".parse::<Ipv6Addr>().unwrap());
    let inside = IpAddr::V6("2001:db8:0:1::1".parse::<Ipv6Addr>().unwrap());
    let outside = IpAddr::V6("2001:db9::1".parse::<Ipv6Addr>().unwrap());
    assert!(cidr_contains(network, 47, inside));
    assert!(!cidr_contains(network, 47, outside));
    assert!(!cidr_contains(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
        24,
        inside
    ));
    assert!(
        source_binding_specificity(
            &SourceAddress::parse("aa:bb:cc:dd:ee:ff").unwrap(),
            &SourceAddress::parse("192.0.2.1").unwrap()
        )
        .is_none()
    );
}

#[test]
fn selected_zone_missing_from_index_returns_typed_unknown() {
    let observed = crate::domain::FirewallSnapshot {
        status: crate::domain::FirewallStatus {
            daemon_running: true,
            version: Some("2.4.0".to_owned()),
            backend: crate::domain::NetfilterBackend::Nftables,
            log_denied: crate::domain::LogDenied::Off,
            panic_mode: false,
        },
        default_zone: ZoneName::parse("public").unwrap(),
        active: BTreeMap::default(),
        runtime: BTreeMap::default(),
        permanent: BTreeMap::default(),
        ipsets: Scoped::default(),
        service_definitions: BTreeMap::default(),
        available_services: Vec::new(),
        policies: Scoped::default(),
        direct_rules: Vec::new(),
        degraded: Vec::new(),
    };
    let index =
        TrafficEvaluationIndex::new(std::sync::Arc::new(observed), EvaluationTarget::Runtime);
    let result = evaluate_selected_zone(
        &index,
        &scenario("192.0.2.1", TrafficTransport::Tcp),
        ZoneName::parse("absent").unwrap(),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        result.unknown_reason(),
        Some(UnknownReason::IncompleteSnapshot)
    );
}
