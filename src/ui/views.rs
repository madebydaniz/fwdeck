//! View catalog: identity, columns, widths, and row extraction from a snapshot.
//! Row extraction is pure — the render layer only formats what comes out of here.

use ratatui::layout::Constraint;
use strum::{EnumIter, FromRepr};

use crate::domain::{
    ConfigurationTarget, FirewallSnapshot, ForwardPort, InterfaceName, IpSetName, LogEntry,
    PolicyName, PortSpec, RichRule, ServiceName, SourceAddress, ZoneName,
};

/// Number of views; sizes the per-view state array in `UiState`.
pub const VIEW_COUNT: usize = 11;

/// Stable, typed identity and mutation payload for one table row.
///
/// Zone-scoped variants carry their owning zone so a mark created in one zone
/// can never target a same-looking row in another zone. Mutable presence and
/// configuration metadata live on [`ViewRow`], keeping identity stable across
/// refreshes. No mutation path needs to parse rendered cells back into domain
/// values.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum RowId {
    /// A firewalld zone.
    Zone(ZoneName),
    /// A zone service.
    Service {
        /// Owning zone.
        zone: ZoneName,
        /// Service name.
        service: ServiceName,
    },
    /// A zone port.
    Port {
        /// Owning zone.
        zone: ZoneName,
        /// Typed port specification.
        port: PortSpec,
    },
    /// A zone forwarding rule.
    Forwarding {
        /// Owning zone.
        zone: ZoneName,
        /// Typed forwarding rule.
        forward: ForwardPort,
    },
    /// A verbatim rich rule.
    RichRule {
        /// Owning zone.
        zone: ZoneName,
        /// Validated verbatim rule.
        rule: RichRule,
    },
    /// An interface binding.
    Interface {
        /// Bound zone.
        zone: ZoneName,
        /// Interface name.
        interface: InterfaceName,
    },
    /// A source binding.
    Source {
        /// Bound zone.
        zone: ZoneName,
        /// Typed source binding.
        source: SourceAddress,
    },
    /// A named IP set.
    IpSet {
        /// IP set name.
        name: IpSetName,
    },
    /// A firewalld policy object.
    Policy {
        /// Policy name.
        name: PolicyName,
    },
    /// A read-only direct rule. The ordinal distinguishes duplicate text.
    Direct {
        /// Position in the snapshot's direct-rule list.
        ordinal: usize,
        /// Original rule text.
        rule: String,
    },
    /// A parsed log entry with a session-unique sequence.
    Log {
        /// Monotonic sequence assigned when the UI receives the entry.
        sequence: u64,
        /// Typed observation used by proposal actions.
        entry: LogEntry,
    },
}

/// One typed table row: stable identity plus presentation-only cells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewRow {
    /// Typed identity used by selection, marking, and actions.
    pub id: RowId,
    metadata: RowMetadata,
    cells: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RowMetadata {
    None,
    Scope(Scope),
    ConfigurationTarget(ConfigurationTarget),
    IpSet { scope: Scope, kind: String },
}

impl ViewRow {
    pub(super) fn new(id: RowId, cells: Vec<String>) -> Self {
        Self {
            id,
            metadata: RowMetadata::None,
            cells,
        }
    }

    pub(super) fn scoped(id: RowId, scope: Scope, cells: Vec<String>) -> Self {
        Self {
            id,
            metadata: RowMetadata::Scope(scope),
            cells,
        }
    }

    pub(super) fn targeted(
        id: RowId,
        configuration_target: ConfigurationTarget,
        cells: Vec<String>,
    ) -> Self {
        Self {
            id,
            metadata: RowMetadata::ConfigurationTarget(configuration_target),
            cells,
        }
    }

    fn ipset(id: RowId, scope: Scope, kind: String, cells: Vec<String>) -> Self {
        Self {
            id,
            metadata: RowMetadata::IpSet { scope, kind },
            cells,
        }
    }

    /// Presentation cells rendered and searched by the UI.
    #[must_use]
    pub fn cells(&self) -> &[String] {
        &self.cells
    }

    /// Runtime/permanent presence metadata for scoped resource rows.
    #[must_use]
    pub const fn scope(&self) -> Option<Scope> {
        match &self.metadata {
            RowMetadata::Scope(scope) | RowMetadata::IpSet { scope, .. } => Some(*scope),
            RowMetadata::None | RowMetadata::ConfigurationTarget(_) => None,
        }
    }

    /// Configuration perspective represented by a binding row.
    #[must_use]
    pub const fn configuration_target(&self) -> Option<ConfigurationTarget> {
        match &self.metadata {
            RowMetadata::ConfigurationTarget(target) => Some(*target),
            RowMetadata::None | RowMetadata::Scope(_) | RowMetadata::IpSet { .. } => None,
        }
    }

    /// IP set type used when cloning the selected definition.
    #[must_use]
    pub fn ipset_kind(&self) -> Option<&str> {
        match &self.metadata {
            RowMetadata::IpSet { kind, .. } => Some(kind),
            RowMetadata::None | RowMetadata::Scope(_) | RowMetadata::ConfigurationTarget(_) => None,
        }
    }
}

impl std::ops::Deref for ViewRow {
    type Target = [String];

    fn deref(&self) -> &Self::Target {
        &self.cells
    }
}

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
    /// Policy objects governing traffic between zones.
    Policies,
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
            Self::Policies => "Policies",
        }
    }

    /// Sidebar/keyboard shortcut for this view.
    #[must_use]
    pub const fn shortcut(self) -> &'static str {
        match self {
            Self::Zones => "0",
            Self::Services => "1",
            Self::Ports => "2",
            Self::Forwarding => "3",
            Self::RichRules => "4",
            Self::Interfaces => "5",
            Self::Sources => "6",
            Self::IpSets => "7",
            Self::Direct => "8",
            Self::Logs => "9",
            Self::Policies => "p",
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
            Self::Policies => &[
                "NAME", "TARGET", "INGRESS", "EGRESS", "SERVICES", "RULES", "STATE", "SCOPE",
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
            Self::Policies => vec![
                Constraint::Min(14),
                Constraint::Length(10),
                Constraint::Min(12),
                Constraint::Min(12),
                Constraint::Min(14),
                Constraint::Length(7),
                Constraint::Length(9),
                Constraint::Length(9),
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

/// Which configuration(s) a row's item lives in. The typed form is carried in
/// [`ViewRow`]; [`Scope::as_str`] is presentation-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
fn scope<T: PartialEq>(item: &T, runtime: &[T], permanent: &[T]) -> Scope {
    match (runtime.contains(item), permanent.contains(item)) {
        (true, true) => Scope::Both,
        (true, false) => Scope::Runtime,
        (false, true) => Scope::Permanent,
        (false, false) => Scope::None,
    }
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
) -> Vec<ViewRow> {
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
        ViewId::Policies => policies_rows(snap, config),
    }
}

fn policies_rows(snap: &FirewallSnapshot, config: ConfigurationTarget) -> Vec<ViewRow> {
    let mut names: Vec<_> = snap
        .policies
        .runtime
        .keys()
        .chain(snap.policies.permanent.keys())
        .collect();
    names.sort();
    names.dedup();
    names
        .into_iter()
        .filter_map(|name| {
            let runtime = snap.policies.runtime.get(name);
            let permanent = snap.policies.permanent.get(name);
            let policy = if config == ConfigurationTarget::Permanent {
                permanent.or(runtime)
            } else {
                runtime.or(permanent)
            }?;
            let scope = match (runtime, permanent) {
                (Some(runtime), Some(permanent)) if runtime.configuration_eq(permanent) => {
                    Scope::Both
                }
                (Some(_), Some(_)) => Scope::Drift,
                (Some(_), None) => Scope::Runtime,
                (None, Some(_)) => Scope::Permanent,
                (None, None) => Scope::None,
            };
            let rules = policy.services.len()
                + policy.ports.len()
                + policy.protocols.len()
                + policy.forward_ports.len()
                + policy.source_ports.len()
                + policy.icmp_blocks.len()
                + policy.rich_rules.len()
                + usize::from(policy.masquerade);
            let dependency_issues = policy_dependency_issues(snap, policy);
            let state = if !dependency_issues.is_empty() {
                "broken"
            } else if policy.disabled {
                "disabled"
            } else if policy.active {
                "active"
            } else {
                "inactive"
            };
            Some(ViewRow::scoped(
                RowId::Policy { name: name.clone() },
                scope,
                vec![
                    name.to_string(),
                    policy.target.as_str().to_owned(),
                    join(&policy.ingress_zones),
                    join(&policy.egress_zones),
                    join(&policy.services),
                    rules.to_string(),
                    state.to_owned(),
                    scope.as_str().to_owned(),
                ],
            ))
        })
        .collect()
}

/// Missing zone/service references for one policy. Symbolic zones are valid
/// graph endpoints and therefore never reported as missing dependencies.
pub(super) fn policy_dependency_issues(
    snapshot: &FirewallSnapshot,
    policy: &crate::domain::PolicyDetails,
) -> Vec<String> {
    let mut missing = Vec::new();
    for zone in policy
        .ingress_zones
        .iter()
        .chain(&policy.egress_zones)
        .filter(|zone| zone.as_str() != "ANY" && zone.as_str() != "HOST")
    {
        let known = snapshot
            .runtime
            .keys()
            .chain(snapshot.permanent.keys())
            .any(|known| known.as_str() == zone);
        if !known {
            missing.push(format!("zone `{zone}`"));
        }
    }
    for service in &policy.services {
        let known = snapshot.available_services.contains(service)
            || snapshot.service_definitions.contains_key(service);
        if !known {
            missing.push(format!("service `{service}`"));
        }
    }
    missing.sort();
    missing.dedup();
    missing
}

fn ipsets_rows(snap: &FirewallSnapshot, config: ConfigurationTarget) -> Vec<ViewRow> {
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
            Some(ViewRow::ipset(
                RowId::IpSet { name: name.clone() },
                scope,
                info.kind.clone(),
                vec![
                    name.to_string(),
                    info.kind.clone(),
                    info.entries.len().to_string(),
                    scope.as_str().to_owned(),
                ],
            ))
        })
        .collect()
}

fn direct_rows(snap: &FirewallSnapshot) -> Vec<ViewRow> {
    snap.direct_rules
        .iter()
        .enumerate()
        .map(|(ordinal, rule)| {
            let mut tokens = rule.split_whitespace();
            let mut cell = |_: usize| tokens.next().unwrap_or("").to_owned();
            let family = cell(0);
            let table = cell(1);
            let chain = cell(2);
            let priority = cell(3);
            let args = tokens.collect::<Vec<_>>().join(" ");
            ViewRow::new(
                RowId::Direct {
                    ordinal,
                    rule: rule.clone(),
                },
                vec![family, table, chain, priority, args],
            )
        })
        .collect()
}

fn zones_rows(snap: &FirewallSnapshot, config: ConfigurationTarget) -> Vec<ViewRow> {
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
            ViewRow::new(
                RowId::Zone(name.clone()),
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
                ],
            )
        })
        .collect()
}

fn services_rows(snap: &FirewallSnapshot, zone: &ZoneName) -> Vec<ViewRow> {
    let (runtime, permanent) = zone_slices(snap, zone, |z| z.services.as_slice());
    union(runtime, permanent)
        .into_iter()
        .map(|service| {
            let scope = scope(service, runtime, permanent);
            let definition = snap.service_definitions.get(service);
            let ports = definition
                .map(|d| join(&d.ports))
                .filter(|p| p != "-")
                .unwrap_or_else(|| "-".to_owned());
            let protocols = definition
                .map(|d| d.protocols.join(","))
                .filter(|p| !p.is_empty())
                .unwrap_or_else(|| "-".to_owned());
            ViewRow::scoped(
                RowId::Service {
                    zone: zone.clone(),
                    service: service.clone(),
                },
                scope,
                vec![
                    service.to_string(),
                    ports,
                    protocols,
                    scope.as_str().to_owned(),
                ],
            )
        })
        .collect()
}

fn ports_rows(snap: &FirewallSnapshot, zone: &ZoneName) -> Vec<ViewRow> {
    let (runtime, permanent) = zone_slices(snap, zone, |z| z.ports.as_slice());
    union(runtime, permanent)
        .into_iter()
        .map(|port| {
            let scope = scope(port, runtime, permanent);
            ViewRow::scoped(
                RowId::Port {
                    zone: zone.clone(),
                    port: *port,
                },
                scope,
                vec![
                    port.port.to_string(),
                    port.protocol.to_string(),
                    scope.as_str().to_owned(),
                ],
            )
        })
        .collect()
}

fn forwarding_rows(snap: &FirewallSnapshot, zone: &ZoneName) -> Vec<ViewRow> {
    let (runtime, permanent) = zone_slices(snap, zone, |z| z.forward_ports.as_slice());
    union(runtime, permanent)
        .into_iter()
        .map(|fwd| {
            let scope = scope(fwd, runtime, permanent);
            ViewRow::scoped(
                RowId::Forwarding {
                    zone: zone.clone(),
                    forward: fwd.clone(),
                },
                scope,
                vec![
                    fwd.port.to_string(),
                    fwd.protocol.to_string(),
                    fwd.to_port.map(|p| p.to_string()).unwrap_or_default(),
                    fwd.to_addr.map(|a| a.to_string()).unwrap_or_default(),
                    scope.as_str().to_owned(),
                ],
            )
        })
        .collect()
}

fn rich_rules_rows(snap: &FirewallSnapshot, zone: &ZoneName) -> Vec<ViewRow> {
    let (runtime, permanent) = zone_slices(snap, zone, |z| z.rich_rules.as_slice());
    union(runtime, permanent)
        .into_iter()
        .map(|rule| {
            let scope = scope(rule, runtime, permanent);
            ViewRow::scoped(
                RowId::RichRule {
                    zone: zone.clone(),
                    rule: rule.clone(),
                },
                scope,
                vec![
                    rule.family().unwrap_or("-").to_owned(),
                    rule.action().unwrap_or("-").to_owned(),
                    scope.as_str().to_owned(),
                    rule.to_string(),
                ],
            )
        })
        .collect()
}

fn interfaces_rows(snap: &FirewallSnapshot, config: ConfigurationTarget) -> Vec<ViewRow> {
    if config == ConfigurationTarget::Permanent {
        // Permanent bindings live in the zone definitions, not the active map.
        return snap
            .permanent
            .iter()
            .flat_map(|(zone, details)| {
                details.interfaces.iter().map(move |iface| {
                    ViewRow::targeted(
                        RowId::Interface {
                            zone: zone.clone(),
                            interface: iface.clone(),
                        },
                        ConfigurationTarget::Permanent,
                        vec![iface.to_string(), zone.to_string(), String::new()],
                    )
                })
            })
            .collect();
    }
    snap.active
        .iter()
        .flat_map(|(zone, active)| {
            active.interfaces.iter().map(move |iface| {
                ViewRow::targeted(
                    RowId::Interface {
                        zone: zone.clone(),
                        interface: iface.clone(),
                    },
                    ConfigurationTarget::Runtime,
                    vec![iface.to_string(), zone.to_string(), "yes".to_owned()],
                )
            })
        })
        .collect()
}

fn sources_rows(snap: &FirewallSnapshot, config: ConfigurationTarget) -> Vec<ViewRow> {
    if config == ConfigurationTarget::Permanent {
        return snap
            .permanent
            .iter()
            .flat_map(|(zone, details)| {
                details.sources.iter().map(move |source| {
                    ViewRow::targeted(
                        RowId::Source {
                            zone: zone.clone(),
                            source: source.clone(),
                        },
                        ConfigurationTarget::Permanent,
                        vec![
                            source.to_string(),
                            source.family().map_or("-", |f| f.as_str()).to_owned(),
                            zone.to_string(),
                        ],
                    )
                })
            })
            .collect();
    }
    snap.active
        .iter()
        .flat_map(|(zone, active)| {
            active.sources.iter().map(move |source| {
                ViewRow::targeted(
                    RowId::Source {
                        zone: zone.clone(),
                        source: source.clone(),
                    },
                    ConfigurationTarget::Runtime,
                    vec![
                        source.to_string(),
                        source.family().map_or("-", |f| f.as_str()).to_owned(),
                        zone.to_string(),
                    ],
                )
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

    #[test]
    fn every_mutable_view_carries_typed_identity() {
        let snap = mock::sample().unwrap();
        let zone = snap.default_zone.clone();

        let zones = rows(ViewId::Zones, &snap, &zone, ConfigurationTarget::Runtime);
        assert!(zones.iter().all(|row| matches!(&row.id, RowId::Zone(_))));

        let services = rows(ViewId::Services, &snap, &zone, ConfigurationTarget::Runtime);
        assert!(services.iter().all(|row| matches!(
            &row.id,
            RowId::Service { zone: owner, .. } if owner == &zone
        )));

        let ports = rows(ViewId::Ports, &snap, &zone, ConfigurationTarget::Runtime);
        assert!(ports.iter().all(|row| matches!(
            &row.id,
            RowId::Port { zone: owner, .. } if owner == &zone
        )));

        let rich_rules = rows(
            ViewId::RichRules,
            &snap,
            &zone,
            ConfigurationTarget::Runtime,
        );
        assert!(rich_rules.iter().all(|row| matches!(
            &row.id,
            RowId::RichRule { zone: owner, .. } if owner == &zone
        )));

        let interfaces = rows(
            ViewId::Interfaces,
            &snap,
            &zone,
            ConfigurationTarget::Runtime,
        );
        assert!(interfaces.iter().all(|row| {
            matches!(&row.id, RowId::Interface { .. })
                && row.configuration_target() == Some(ConfigurationTarget::Runtime)
        }));

        let sources = rows(ViewId::Sources, &snap, &zone, ConfigurationTarget::Runtime);
        assert!(sources.iter().all(|row| {
            matches!(&row.id, RowId::Source { .. })
                && row.configuration_target() == Some(ConfigurationTarget::Runtime)
        }));

        let ipsets = rows(ViewId::IpSets, &snap, &zone, ConfigurationTarget::Runtime);
        assert!(
            ipsets
                .iter()
                .all(|row| matches!(&row.id, RowId::IpSet { .. }) && row.scope().is_some())
        );

        let policies = rows(ViewId::Policies, &snap, &zone, ConfigurationTarget::Runtime);
        assert!(
            policies
                .iter()
                .all(|row| { matches!(&row.id, RowId::Policy { .. }) && row.scope().is_some() })
        );
    }

    #[test]
    fn row_identity_stays_stable_when_scope_changes() {
        let id = RowId::Port {
            zone: ZoneName::parse("public").unwrap(),
            port: "8080/tcp".parse().unwrap(),
        };
        let runtime = ViewRow::scoped(id.clone(), Scope::Runtime, Vec::new());
        let both = ViewRow::scoped(id, Scope::Both, Vec::new());

        assert_eq!(runtime.id, both.id);
        assert_ne!(runtime.scope(), both.scope());
    }

    #[test]
    fn policies_view_summarizes_real_policy_state() {
        let snap = mock::sample().unwrap();
        let rows = rows(
            ViewId::Policies,
            &snap,
            &snap.default_zone,
            ConfigurationTarget::Runtime,
        );
        let policy = rows
            .iter()
            .find(|row| matches!(&row.id, RowId::Policy { name } if name.as_str() == "mypolicy"))
            .unwrap();

        assert_eq!(policy[1], "DROP");
        assert_eq!(policy[2], "public");
        assert_eq!(policy[3], "ANY");
        assert_eq!(policy[4], "http");
        assert_eq!(policy[6], "active");
        assert_eq!(policy[7], "both");
    }

    #[test]
    fn policies_view_flags_missing_dependencies() {
        let mut snap = mock::sample().unwrap();
        snap.policies
            .runtime
            .values_mut()
            .next()
            .unwrap()
            .ingress_zones
            .push("ghost-zone".to_owned());
        let rows = rows(
            ViewId::Policies,
            &snap,
            &snap.default_zone,
            ConfigurationTarget::Runtime,
        );

        assert_eq!(rows[0][6], "broken");
        let policy = snap.policies.runtime.values().next().unwrap();
        assert_eq!(
            policy_dependency_issues(&snap, policy),
            vec!["zone `ghost-zone`".to_owned()]
        );
    }
}
