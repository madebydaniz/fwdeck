//! View catalog: identity, columns, widths, and row extraction from a snapshot.
//! Row extraction is pure — the render layer only formats what comes out of here.

use ratatui::layout::Constraint;
use strum::{EnumIter, FromRepr};

use crate::domain::{ConfigurationTarget, FirewallSnapshot, ZoneName};

/// Number of views; sizes the per-view state array in `UiState`.
pub const VIEW_COUNT: usize = 10;

/// The main table's views, in sidebar/digit-key order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, FromRepr)]
#[repr(usize)]
pub enum ViewId {
    /// All zones with sync/active/default markers.
    Zones,
    /// Services enabled in the effective zone.
    Services,
    /// Ports opened in the effective zone.
    Ports,
    /// Port-forwarding rules of the effective zone.
    Forwarding,
    /// Rich rules of the effective zone.
    RichRules,
    /// Interface-to-zone bindings.
    Interfaces,
    /// Source-to-zone bindings.
    Sources,
    /// Defined ipsets with entry counts.
    IpSets,
    /// Direct rules (deprecated in firewalld).
    Direct,
    /// Kernel/netfilter log entries, newest first.
    Logs,
}

impl ViewId {
    /// Index into per-view arrays (equals the discriminant).
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    /// The view bound to a digit key (0–9), if any.
    #[must_use]
    pub fn from_digit(digit: usize) -> Option<Self> {
        Self::from_repr(digit)
    }

    /// Display title used in the sidebar and table border.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Zones => "Zones",
            Self::Services => "Services",
            Self::Ports => "Ports",
            Self::Forwarding => "Forward",
            Self::RichRules => "Rich Rules",
            Self::Interfaces => "Interfaces",
            Self::Sources => "Sources",
            Self::IpSets => "IPSets",
            Self::Direct => "Direct",
            Self::Logs => "Logs",
        }
    }

    /// Column headers for this view's table.
    #[must_use]
    pub const fn columns(self) -> &'static [&'static str] {
        match self {
            Self::Zones => &[
                "NAME",
                "≠",
                "ACTIVE",
                "DEFAULT",
                "TARGET",
                "INTERFACES",
                "SOURCES",
                "SVCS",
                "MASQ",
            ],
            Self::Services => &["NAME", "PORTS", "PROTOCOLS", "SCOPE"],
            Self::Ports => &["PORT", "PROTOCOL", "SCOPE"],
            Self::Forwarding => &["PORT", "PROTOCOL", "TO PORT", "TO ADDRESS", "SCOPE"],
            Self::RichRules => &["FAMILY", "ACTION", "SCOPE", "RULE"],
            Self::Interfaces => &["INTERFACE", "ZONE", "ACTIVE"],
            Self::Sources => &["SOURCE", "FAMILY", "ZONE"],
            Self::IpSets => &["NAME", "TYPE", "ENTRIES", "SCOPE"],
            Self::Direct => &["FAMILY", "TABLE", "CHAIN", "PRIO", "ARGS"],
            Self::Logs => &[
                "TIME",
                "ACTION",
                "SOURCE",
                "DESTINATION",
                "DPORT",
                "PROTO",
                "IFACE",
            ],
        }
    }

    /// Column width constraints, matching [`ViewId::columns`] one-to-one.
    #[must_use]
    pub fn widths(self) -> Vec<Constraint> {
        match self {
            Self::Zones => vec![
                Constraint::Min(10),
                Constraint::Length(4),
                Constraint::Length(6),
                Constraint::Length(7),
                Constraint::Length(10),
                Constraint::Min(10),
                Constraint::Min(12),
                Constraint::Length(4),
                Constraint::Length(4),
            ],
            Self::Services => vec![
                Constraint::Min(16),
                Constraint::Min(12),
                Constraint::Min(10),
                Constraint::Length(9),
            ],
            Self::Ports => vec![
                Constraint::Length(12),
                Constraint::Length(8),
                Constraint::Length(9),
            ],
            Self::Forwarding => vec![
                Constraint::Length(12),
                Constraint::Length(8),
                Constraint::Length(12),
                Constraint::Min(15),
                Constraint::Length(9),
            ],
            Self::RichRules => vec![
                Constraint::Length(6),
                Constraint::Length(8),
                Constraint::Length(9),
                Constraint::Min(30),
            ],
            Self::Interfaces => vec![
                Constraint::Min(12),
                Constraint::Min(12),
                Constraint::Length(6),
            ],
            Self::Sources => vec![
                Constraint::Min(20),
                Constraint::Length(6),
                Constraint::Min(12),
            ],
            Self::IpSets => vec![
                Constraint::Min(16),
                Constraint::Min(10),
                Constraint::Length(8),
                Constraint::Length(9),
            ],
            Self::Direct => vec![
                Constraint::Length(6),
                Constraint::Length(8),
                Constraint::Min(10),
                Constraint::Length(5),
                Constraint::Min(20),
            ],
            Self::Logs => vec![
                Constraint::Length(9),
                Constraint::Length(7),
                Constraint::Min(15),
                Constraint::Min(15),
                Constraint::Length(6),
                Constraint::Length(6),
                Constraint::Min(8),
            ],
        }
    }
}

/// Scope of an entry relative to the runtime/permanent configurations.
/// The runtime and permanent slices of one zone attribute, selected by an
/// accessor — the shared prelude of every scoped-entry row builder.
fn zone_slices<'a, T>(
    snap: &'a FirewallSnapshot,
    zone: &ZoneName,
    field: impl Fn(&'a crate::domain::ZoneDetails) -> &'a [T],
) -> (&'a [T], &'a [T]) {
    (
        snap.runtime.get(zone).map(&field).unwrap_or_default(),
        snap.permanent.get(zone).map(&field).unwrap_or_default(),
    )
}

/// Which configuration(s) a row's item lives in. The typed form of the SCOPE
/// column: rows stringify via [`Scope::as_str`], and mutation code parses the
/// cell back with [`Scope::parse`] instead of string-matching ad hoc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Present in runtime and permanent.
    Both,
    /// Runtime only — disappears on reload.
    Runtime,
    /// Permanent only — takes effect after a reload.
    Permanent,
    /// Present in both configurations, but the values differ.
    Drift,
    /// Present in neither (an empty cell).
    None,
}

impl Scope {
    /// The canonical cell text for this scope.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::Runtime => "runtime",
            Self::Permanent => "permanent",
            Self::Drift => "drift",
            Self::None => "",
        }
    }

    /// Parses a SCOPE cell back; unknown text maps to [`Scope::None`].
    #[must_use]
    pub fn parse(cell: &str) -> Self {
        match cell {
            "both" => Self::Both,
            "runtime" => Self::Runtime,
            "permanent" => Self::Permanent,
            "drift" => Self::Drift,
            _ => Self::None,
        }
    }

    /// The mutation target this scope narrows to, or `default` when the item
    /// exists in both configurations (or the scope is unknown).
    #[must_use]
    pub fn target_or(self, default: ConfigurationTarget) -> ConfigurationTarget {
        match self {
            Self::Runtime => ConfigurationTarget::Runtime,
            Self::Permanent => ConfigurationTarget::Permanent,
            Self::Both | Self::Drift | Self::None => default,
        }
    }
}

/// SCOPE cell text for an item based on which configurations contain it.
fn scope<T: PartialEq>(item: &T, runtime: &[T], permanent: &[T]) -> &'static str {
    match (runtime.contains(item), permanent.contains(item)) {
        (true, true) => Scope::Both,
        (true, false) => Scope::Runtime,
        (false, true) => Scope::Permanent,
        (false, false) => Scope::None,
    }
    .as_str()
}

/// Sorted, deduplicated union of two slices.
fn union<'a, T: Ord>(a: &'a [T], b: &'a [T]) -> Vec<&'a T> {
    let mut all: Vec<&T> = a.iter().chain(b.iter()).collect();
    all.sort();
    all.dedup();
    all
}

fn join<T: ToString>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Entry views (Services/Ports/…) always list the **union** of runtime and
/// permanent with a scope column — drift is never hidden. `config` selects the
/// perspective for zone attributes (Zones) and bindings (Interfaces/Sources).
#[must_use]
pub fn rows(
    view: ViewId,
    snap: &FirewallSnapshot,
    zone: &ZoneName,
    config: ConfigurationTarget,
) -> Vec<Vec<String>> {
    match view {
        ViewId::Zones => zones_rows(snap, config),
        ViewId::Services => services_rows(snap, zone),
        ViewId::Ports => ports_rows(snap, zone),
        ViewId::Forwarding => forwarding_rows(snap, zone),
        ViewId::RichRules => rich_rules_rows(snap, zone),
        ViewId::Interfaces => interfaces_rows(snap, config),
        ViewId::Sources => sources_rows(snap, config),
        ViewId::IpSets => ipsets_rows(snap, config),
        ViewId::Direct => direct_rows(snap),
        // Logs rows come from the UI's ring buffer (`UiState::all_rows`).
        ViewId::Logs => Vec::new(),
    }
}

fn ipsets_rows(snap: &FirewallSnapshot, config: ConfigurationTarget) -> Vec<Vec<String>> {
    let mut names: Vec<_> = snap
        .ipsets
        .runtime
        .keys()
        .chain(snap.ipsets.permanent.keys())
        .collect();
    names.sort();
    names.dedup();
    names
        .into_iter()
        .filter_map(|name| {
            let runtime = snap.ipsets.runtime.get(name);
            let permanent = snap.ipsets.permanent.get(name);
            let info = if config == ConfigurationTarget::Permanent {
                permanent.or(runtime)
            } else {
                runtime.or(permanent)
            }?;
            let scope = match (runtime, permanent) {
                (Some(runtime), Some(permanent)) if runtime == permanent => Scope::Both,
                (Some(_), Some(_)) => Scope::Drift,
                (Some(_), None) => Scope::Runtime,
                (None, Some(_)) => Scope::Permanent,
                (None, None) => Scope::None,
            };
            Some(vec![
                name.to_string(),
                info.kind.clone(),
                info.entries.len().to_string(),
                scope.as_str().to_owned(),
            ])
        })
        .collect()
}

fn direct_rows(snap: &FirewallSnapshot) -> Vec<Vec<String>> {
    snap.direct_rules
        .iter()
        .map(|rule| {
            let mut tokens = rule.split_whitespace();
            let mut cell = |_: usize| tokens.next().unwrap_or("").to_owned();
            let family = cell(0);
            let table = cell(1);
            let chain = cell(2);
            let priority = cell(3);
            let args = tokens.collect::<Vec<_>>().join(" ");
            vec![family, table, chain, priority, args]
        })
        .collect()
}

fn zones_rows(snap: &FirewallSnapshot, config: ConfigurationTarget) -> Vec<Vec<String>> {
    snap.zone_names()
        .into_iter()
        .map(|name| {
            let details = if config == ConfigurationTarget::Permanent {
                snap.permanent.get(name).or_else(|| snap.runtime.get(name))
            } else {
                snap.runtime.get(name).or_else(|| snap.permanent.get(name))
            };
            let (target, interfaces, sources, services, masquerade) = details.map_or(
                (String::new(), String::new(), String::new(), 0, false),
                |d| {
                    (
                        d.target.as_str().to_owned(),
                        join(&d.interfaces),
                        join(&d.sources),
                        d.services.len(),
                        d.masquerade,
                    )
                },
            );
            vec![
                name.to_string(),
                if snap.is_zone_synced(name) { "" } else { "≠" }.to_owned(),
                if snap.is_active(name) { "yes" } else { "" }.to_owned(),
                if *name == snap.default_zone {
                    "yes"
                } else {
                    ""
                }
                .to_owned(),
                target,
                interfaces,
                sources,
                services.to_string(),
                if masquerade { "yes" } else { "" }.to_owned(),
            ]
        })
        .collect()
}

fn services_rows(snap: &FirewallSnapshot, zone: &ZoneName) -> Vec<Vec<String>> {
    let (runtime, permanent) = zone_slices(snap, zone, |z| z.services.as_slice());
    union(runtime, permanent)
        .into_iter()
        .map(|service| {
            let definition = snap.service_definitions.get(service);
            let ports = definition
                .map(|d| join(&d.ports))
                .filter(|p| p != "-")
                .unwrap_or_else(|| "-".to_owned());
            let protocols = definition
                .map(|d| d.protocols.join(","))
                .filter(|p| !p.is_empty())
                .unwrap_or_else(|| "-".to_owned());
            vec![
                service.to_string(),
                ports,
                protocols,
                scope(service, runtime, permanent).to_owned(),
            ]
        })
        .collect()
}

fn ports_rows(snap: &FirewallSnapshot, zone: &ZoneName) -> Vec<Vec<String>> {
    let (runtime, permanent) = zone_slices(snap, zone, |z| z.ports.as_slice());
    union(runtime, permanent)
        .into_iter()
        .map(|port| {
            vec![
                port.port.to_string(),
                port.protocol.to_string(),
                scope(port, runtime, permanent).to_owned(),
            ]
        })
        .collect()
}

fn forwarding_rows(snap: &FirewallSnapshot, zone: &ZoneName) -> Vec<Vec<String>> {
    let (runtime, permanent) = zone_slices(snap, zone, |z| z.forward_ports.as_slice());
    let mut all: Vec<&crate::domain::ForwardPort> =
        runtime.iter().chain(permanent.iter()).collect();
    all.dedup_by(|a, b| a == b);
    all.into_iter()
        .map(|fwd| {
            vec![
                fwd.port.to_string(),
                fwd.protocol.to_string(),
                fwd.to_port.map(|p| p.to_string()).unwrap_or_default(),
                fwd.to_addr.map(|a| a.to_string()).unwrap_or_default(),
                scope(fwd, runtime, permanent).to_owned(),
            ]
        })
        .collect()
}

fn rich_rules_rows(snap: &FirewallSnapshot, zone: &ZoneName) -> Vec<Vec<String>> {
    let (runtime, permanent) = zone_slices(snap, zone, |z| z.rich_rules.as_slice());
    union(runtime, permanent)
        .into_iter()
        .map(|rule| {
            vec![
                rule.family().unwrap_or("-").to_owned(),
                rule.action().unwrap_or("-").to_owned(),
                scope(rule, runtime, permanent).to_owned(),
                rule.to_string(),
            ]
        })
        .collect()
}

fn interfaces_rows(snap: &FirewallSnapshot, config: ConfigurationTarget) -> Vec<Vec<String>> {
    if config == ConfigurationTarget::Permanent {
        // Permanent bindings live in the zone definitions, not the active map.
        return snap
            .permanent
            .iter()
            .flat_map(|(zone, details)| {
                details
                    .interfaces
                    .iter()
                    .map(move |iface| vec![iface.to_string(), zone.to_string(), String::new()])
            })
            .collect();
    }
    snap.active
        .iter()
        .flat_map(|(zone, active)| {
            active
                .interfaces
                .iter()
                .map(move |iface| vec![iface.to_string(), zone.to_string(), "yes".to_owned()])
        })
        .collect()
}

fn sources_rows(snap: &FirewallSnapshot, config: ConfigurationTarget) -> Vec<Vec<String>> {
    if config == ConfigurationTarget::Permanent {
        return snap
            .permanent
            .iter()
            .flat_map(|(zone, details)| {
                details.sources.iter().map(move |source| {
                    vec![
                        source.to_string(),
                        source.family().map_or("-", |f| f.as_str()).to_owned(),
                        zone.to_string(),
                    ]
                })
            })
            .collect();
    }
    snap.active
        .iter()
        .flat_map(|(zone, active)| {
            active.sources.iter().map(move |source| {
                vec![
                    source.to_string(),
                    source.family().map_or("-", |f| f.as_str()).to_owned(),
                    zone.to_string(),
                ]
            })
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::domain::mock;

    #[test]
    fn zones_view_lists_all_zones_with_markers() {
        let snap = mock::sample().unwrap();
        let rows = rows(
            ViewId::Zones,
            &snap,
            &snap.default_zone,
            ConfigurationTarget::Runtime,
        );
        assert!(rows.len() >= 9);
        let public = rows.iter().find(|r| r[0] == "public").unwrap();
        assert_eq!(public[1], "≠"); // drifted (mock seeds runtime-only entries)
        assert_eq!(public[2], "yes"); // active
        assert_eq!(public[3], "yes"); // default
        let home = rows.iter().find(|r| r[0] == "home").unwrap();
        assert_eq!(home[1], ""); // synced
    }

    #[test]
    fn services_view_reports_scope_drift() {
        let snap = mock::sample().unwrap();
        let rows = rows(
            ViewId::Services,
            &snap,
            &snap.default_zone,
            ConfigurationTarget::Runtime,
        );
        let http = rows.iter().find(|r| r[0] == "http").unwrap();
        assert_eq!(http[3], "runtime");
        assert_eq!(http[1], "80/tcp", "definition enrichment");
        let https = rows.iter().find(|r| r[0] == "https").unwrap();
        assert_eq!(https[3], "both");
    }

    #[test]
    fn permanent_perspective_switches_binding_sources() {
        let snap = mock::sample().unwrap();
        // Runtime view: interfaces come from the active map (eth0, eth1).
        let runtime = rows(
            ViewId::Interfaces,
            &snap,
            &snap.default_zone,
            ConfigurationTarget::Runtime,
        );
        assert!(runtime.iter().any(|r| r[0] == "eth0" && r[2] == "yes"));
        // Permanent view: interfaces come from the permanent zone definitions.
        let permanent = rows(
            ViewId::Interfaces,
            &snap,
            &snap.default_zone,
            ConfigurationTarget::Permanent,
        );
        assert!(permanent.iter().any(|r| r[0] == "eth0" && r[2].is_empty()));
    }

    #[test]
    fn ipsets_and_direct_render_from_snapshot() {
        let snap = mock::sample().unwrap();
        let ipsets = rows(
            ViewId::IpSets,
            &snap,
            &snap.default_zone,
            ConfigurationTarget::Runtime,
        );
        assert_eq!(ipsets[0][0], "blocklist");
        assert_eq!(ipsets[0][2], "1");
        assert_eq!(ipsets[0][3], "both");
        let direct = rows(
            ViewId::Direct,
            &snap,
            &snap.default_zone,
            ConfigurationTarget::Runtime,
        );
        assert_eq!(direct[0][0], "ipv4");
        assert!(direct[0][4].contains("--dport 12345"));
    }
}
