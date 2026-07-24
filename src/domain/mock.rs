//! Static sample firewall data backing the reducer, render, and engine tests.
//! Test-only — gated out of the release binary.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use super::address::SourceAddress;
use super::ids::{InterfaceName, IpSetName, ServiceName, ValidationError, ZoneName};
use super::port::{ForwardPort, Protocol};
use super::rich_rule::RichRule;
use super::snapshot::{
    FirewallSnapshot, FirewallStatus, IpSetInfo, LogDenied, NetfilterBackend, ServiceDefinition,
};
use super::zone::{ActiveZone, ZoneDetails, ZoneTarget};

fn services(names: &[&str]) -> Result<Vec<ServiceName>, ValidationError> {
    names.iter().map(|n| ServiceName::parse(n)).collect()
}

/// A hand-written snapshot with realistic drift between runtime and
/// permanent, plus ipsets, policies, and direct rules, so every UI surface
/// has something to render.
#[allow(clippy::too_many_lines)] // flat data builder
pub fn sample() -> Result<FirewallSnapshot, ValidationError> {
    let mut runtime: BTreeMap<ZoneName, ZoneDetails> = BTreeMap::new();
    let mut active: BTreeMap<ZoneName, ActiveZone> = BTreeMap::new();

    let public = ZoneName::parse("public")?;
    let mut zone = ZoneDetails::empty(public.clone());
    zone.interfaces = vec![InterfaceName::parse("eth0")?];
    zone.services = services(&["ssh", "http", "https", "dhcpv6-client"])?;
    zone.ports = vec!["8080/tcp".parse()?, "5000-5010/udp".parse()?];
    zone.source_ports = vec!["68/udp".parse()?];
    zone.protocols = vec![crate::domain::IpProtocol::parse("gre")?];
    zone.forward = true;
    zone.forward_ports = vec![ForwardPort {
        port: "8080".parse()?,
        protocol: Protocol::Tcp,
        to_port: Some("80".parse()?),
        to_addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))),
    }];
    zone.rich_rules = vec![
        RichRule::parse(r#"rule family="ipv4" source address="203.0.113.0/24" reject"#)?,
        RichRule::parse(
            r#"rule family="ipv4" source address="198.51.100.7" port port="22" protocol="tcp" accept"#,
        )?,
    ];
    runtime.insert(public.clone(), zone);
    active.insert(
        public.clone(),
        ActiveZone {
            interfaces: vec![InterfaceName::parse("eth0")?],
            sources: Vec::new(),
        },
    );

    let home = ZoneName::parse("home")?;
    let mut zone = ZoneDetails::empty(home.clone());
    zone.services = services(&["ssh", "mdns", "samba-client", "dhcpv6-client"])?;
    zone.sources = vec![SourceAddress::parse("192.168.1.0/24")?];
    runtime.insert(home.clone(), zone);
    active.insert(
        home,
        ActiveZone {
            interfaces: Vec::new(),
            sources: vec![SourceAddress::parse("192.168.1.0/24")?],
        },
    );

    let dmz = ZoneName::parse("dmz")?;
    let mut zone = ZoneDetails::empty(dmz.clone());
    zone.interfaces = vec![InterfaceName::parse("eth1")?];
    zone.services = services(&["ssh"])?;
    zone.icmp_blocks = vec![crate::domain::IcmpType::parse("echo-request")?];
    runtime.insert(dmz.clone(), zone);
    active.insert(
        dmz,
        ActiveZone {
            interfaces: vec![InterfaceName::parse("eth1")?],
            sources: Vec::new(),
        },
    );

    let external = ZoneName::parse("external")?;
    let mut zone = ZoneDetails::empty(external.clone());
    zone.services = services(&["ssh"])?;
    zone.masquerade = true;
    runtime.insert(external, zone);

    let work = ZoneName::parse("work")?;
    let mut zone = ZoneDetails::empty(work.clone());
    zone.services = services(&["ssh", "dhcpv6-client"])?;
    runtime.insert(work, zone);

    let internal = ZoneName::parse("internal")?;
    let mut zone = ZoneDetails::empty(internal.clone());
    zone.services = services(&["ssh", "mdns", "samba-client", "dhcpv6-client"])?;
    runtime.insert(internal, zone);

    let trusted = ZoneName::parse("trusted")?;
    let mut zone = ZoneDetails::empty(trusted.clone());
    zone.target = ZoneTarget::Accept;
    runtime.insert(trusted, zone);

    let block = ZoneName::parse("block")?;
    let mut zone = ZoneDetails::empty(block.clone());
    zone.target = ZoneTarget::Reject;
    runtime.insert(block, zone);

    let drop_zone = ZoneName::parse("drop")?;
    let mut zone = ZoneDetails::empty(drop_zone.clone());
    zone.target = ZoneTarget::Drop;
    runtime.insert(drop_zone, zone);

    // Permanent config drifts from runtime in `public`: http and 8080/tcp are
    // runtime-only, so the "different" indicator has something to show.
    let mut permanent = runtime.clone();
    if let Some(zone) = permanent.get_mut(&public) {
        zone.services.retain(|s| s.as_str() != "http");
        zone.ports.retain(|p| p.to_string() != "8080/tcp");
    }

    let mut service_definitions = BTreeMap::new();
    for (name, ports) in [
        ("ssh", "22/tcp"),
        ("http", "80/tcp"),
        ("https", "443/tcp"),
        ("dhcpv6-client", "546/udp"),
        ("mdns", "5353/udp"),
    ] {
        service_definitions.insert(
            ServiceName::parse(name)?,
            ServiceDefinition {
                ports: vec![ports.parse()?],
                protocols: Vec::new(),
            },
        );
    }

    let mut ipsets = BTreeMap::new();
    ipsets.insert(
        IpSetName::parse("blocklist")?,
        IpSetInfo {
            kind: "hash:ip".to_owned(),
            entries: vec!["203.0.113.9".to_owned()],
        },
    );

    Ok(FirewallSnapshot {
        status: FirewallStatus {
            daemon_running: true,
            version: Some("2.3.1".to_owned()),
            backend: NetfilterBackend::Nftables,
            log_denied: LogDenied::Off,
            panic_mode: false,
        },
        default_zone: public,
        active,
        runtime,
        permanent,
        ipsets,
        service_definitions,
        available_services: vec![
            ServiceName::parse("ssh")?,
            ServiceName::parse("http")?,
            ServiceName::parse("https")?,
            ServiceName::parse("dns")?,
            ServiceName::parse("mysql")?,
        ],
        policies: {
            let mut policies = BTreeMap::new();
            let name = crate::domain::PolicyName::parse("mypolicy")?;
            policies.insert(
                name.clone(),
                crate::domain::PolicyDetails {
                    name,
                    target: crate::domain::PolicyTarget::Drop,
                    ingress_zones: vec!["public".to_owned()],
                    egress_zones: vec!["ANY".to_owned()],
                    services: services(&["http"])?,
                    ports: Vec::new(),
                },
            );
            policies
        },
        degraded: Vec::new(),
        direct_rules: vec!["ipv4 filter INPUT 9 -p tcp --dport 12345 -j ACCEPT".to_owned()],
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn sample_snapshot_is_valid_and_drifted() {
        let snap = sample().unwrap();
        assert_eq!(snap.default_zone.as_str(), "public");
        assert!(snap.is_active(&snap.default_zone.clone()));
        assert!(!snap.all_synced());
        assert!(snap.zone_names().len() >= 9);
    }
}
