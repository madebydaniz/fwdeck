//! Typed firewall mutations: validation against a snapshot, human-readable
//! descriptions for the confirmation modal and toasts, and inverse operations
//! as rollback metadata (ADR-3).

use super::address::{IpSetEntry, SourceAddress};
use super::ids::IpProtocol;
use super::ids::{IcmpType, InterfaceName, IpSetName, PolicyName, ServiceName, ZoneName};
use super::policy::PolicyTarget;
use super::port::{ForwardPort, PortSpec};
use super::rich_rule::RichRule;
use super::snapshot::{ConfigurationTarget, FirewallSnapshot, LogDenied, SnapshotSection};
use super::zone::ZoneTarget;

/// One typed firewall mutation — everything the UI can do to firewalld.
/// Execution layers translate a variant into the matching `firewall-cmd`
/// invocation(s) per configuration target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallOperation {
    /// Enable a service in a zone.
    AddService {
        /// Zone to modify.
        zone: ZoneName,
        /// Service to enable.
        service: ServiceName,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Temporarily allow a named service in the runtime only — firewalld
    /// removes it again after `seconds` (`--timeout`). Never touches the
    /// permanent config.
    AddTemporaryService {
        /// The zone to open.
        zone: ZoneName,
        /// The service to allow.
        service: ServiceName,
        /// Lifetime in seconds before firewalld auto-removes it.
        seconds: u32,
    },
    /// Disable a service in a zone.
    RemoveService {
        /// Zone to modify.
        zone: ZoneName,
        /// Service to disable.
        service: ServiceName,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Open a port (or range) in a zone.
    AddPort {
        /// Zone to modify.
        zone: ZoneName,
        /// Port(s) and protocol to open.
        port: PortSpec,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Close a port (or range) in a zone.
    RemovePort {
        /// Zone to modify.
        zone: ZoneName,
        /// Port(s) and protocol to close.
        port: PortSpec,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Change the default zone (always runtime and permanent in firewalld).
    SetDefaultZone {
        /// Zone to make the default.
        zone: ZoneName,
    },
    /// Enable or disable IP masquerading in a zone.
    SetMasquerade {
        /// Zone to modify.
        zone: ZoneName,
        /// Desired masquerade state.
        enabled: bool,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Set a zone's target — the fate of packets no rule matches. Permanent-only
    /// in firewalld; a reload activates it.
    SetZoneTarget {
        /// Zone to modify.
        zone: ZoneName,
        /// Desired target.
        zone_target: ZoneTarget,
    },
    /// Add a source-port match to a zone.
    AddSourcePort {
        /// Zone to modify.
        zone: ZoneName,
        /// Source port(s) and protocol.
        port: PortSpec,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Remove a source-port match from a zone.
    RemoveSourcePort {
        /// Zone to modify.
        zone: ZoneName,
        /// Source port(s) and protocol.
        port: PortSpec,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Allow an IP protocol in a zone (e.g. `gre`, `esp`).
    AddProtocol {
        /// Zone to modify.
        zone: ZoneName,
        /// Protocol to allow.
        protocol: IpProtocol,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Stop allowing an IP protocol in a zone.
    RemoveProtocol {
        /// Zone to modify.
        zone: ZoneName,
        /// Protocol to remove.
        protocol: IpProtocol,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Enable or disable intra-zone forwarding (firewalld 0.9+ `--add-forward`).
    SetForward {
        /// Zone to modify.
        zone: ZoneName,
        /// Desired forwarding state.
        enabled: bool,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Invert (or un-invert) a zone's icmp-block set: block everything except
    /// the listed types.
    SetIcmpBlockInversion {
        /// Zone to modify.
        zone: ZoneName,
        /// Desired inversion state.
        enabled: bool,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Add a port-forwarding rule to a zone.
    AddForwardPort {
        /// Zone to modify.
        zone: ZoneName,
        /// The forwarding rule.
        forward: ForwardPort,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Remove a port-forwarding rule from a zone.
    RemoveForwardPort {
        /// Zone to modify.
        zone: ZoneName,
        /// The forwarding rule.
        forward: ForwardPort,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Add a rich rule to a zone (passed to firewalld verbatim).
    AddRichRule {
        /// Zone to modify.
        zone: ZoneName,
        /// The rule text.
        rule: RichRule,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Remove a rich rule from a zone (matched by its verbatim text).
    RemoveRichRule {
        /// Zone to modify.
        zone: ZoneName,
        /// The rule text.
        rule: RichRule,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Bind an interface to a zone.
    AddInterface {
        /// Zone to bind to.
        zone: ZoneName,
        /// Interface to bind.
        interface: InterfaceName,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Unbind an interface from a zone.
    RemoveInterface {
        /// Zone to unbind from.
        zone: ZoneName,
        /// Interface to unbind.
        interface: InterfaceName,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Bind a source address to a zone.
    AddSource {
        /// Zone to bind to.
        zone: ZoneName,
        /// Source to bind.
        source: SourceAddress,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Unbind a source address from a zone.
    RemoveSource {
        /// Zone to unbind from.
        zone: ZoneName,
        /// Source to unbind.
        source: SourceAddress,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Block an ICMP type in a zone.
    AddIcmpBlock {
        /// Zone to modify.
        zone: ZoneName,
        /// ICMP type to block.
        icmp: IcmpType,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Unblock an ICMP type in a zone.
    RemoveIcmpBlock {
        /// Zone to modify.
        zone: ZoneName,
        /// ICMP type to unblock.
        icmp: IcmpType,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Custom service definitions are permanent-only; reload activates them.
    CreateService {
        /// Name for the new service.
        service: ServiceName,
    },
    /// Delete a custom service definition (permanent-only; reload applies).
    DeleteService {
        /// Service to delete.
        service: ServiceName,
    },
    /// Add a port to a custom service definition (permanent-only).
    AddServicePort {
        /// Service to modify.
        service: ServiceName,
        /// Port(s) and protocol to add.
        port: PortSpec,
    },
    /// Remove a port from a custom service definition (permanent-only).
    RemoveServicePort {
        /// Service to modify.
        service: ServiceName,
        /// Port(s) and protocol to remove.
        port: PortSpec,
    },
    /// Policy objects. Create/delete are permanent-only; rule edits honor the
    /// configuration target like zone edits.
    CreatePolicy {
        /// Name for the new policy.
        policy: PolicyName,
    },
    /// Delete a policy object (permanent-only; reload applies).
    DeletePolicy {
        /// Policy to delete.
        policy: PolicyName,
    },
    /// Set a policy's target, i.e. the fate of unmatched packets.
    SetPolicyTarget {
        /// Policy to modify.
        policy: PolicyName,
        /// Desired target.
        policy_target: PolicyTarget,
    },
    /// Add an ingress zone to a policy.
    AddPolicyIngressZone {
        /// Policy to modify.
        policy: PolicyName,
        /// Zone name; a plain string because `ANY`/`HOST` pseudo-zones
        /// are allowed here.
        zone: String,
    },
    /// Add an egress zone to a policy.
    AddPolicyEgressZone {
        /// Policy to modify.
        policy: PolicyName,
        /// Zone name; may be the `ANY`/`HOST` pseudo-zones.
        zone: String,
    },
    /// Allow a service in a policy.
    AddPolicyService {
        /// Policy to modify.
        policy: PolicyName,
        /// Service to allow.
        service: ServiceName,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Remove a service from a policy.
    RemovePolicyService {
        /// Policy to modify.
        policy: PolicyName,
        /// Service to remove.
        service: ServiceName,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Permanent-only, like zones; reload activates.
    CreateIpSet {
        /// Name for the new ipset.
        name: IpSetName,
        /// The ipset type; must be one of [`IPSET_TYPES`].
        kind: String,
    },
    /// Delete an ipset (permanent-only; reload applies).
    DeleteIpSet {
        /// Ipset to delete.
        name: IpSetName,
    },
    /// Add an entry to an ipset.
    AddIpSetEntry {
        /// Ipset to modify.
        name: IpSetName,
        /// Entry to add (verbatim; supports compound-type entries).
        entry: IpSetEntry,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// Remove an entry from an ipset.
    RemoveIpSetEntry {
        /// Ipset to modify.
        name: IpSetName,
        /// Entry to remove (verbatim; supports compound-type entries).
        entry: IpSetEntry,
        /// Configuration scope the change applies to.
        target: ConfigurationTarget,
    },
    /// `--new-zone` is permanent-only; a reload activates it (deliberately not
    /// automatic — reloads wipe runtime-only changes).
    CreateZone {
        /// Name for the new zone.
        zone: ZoneName,
    },
    /// Delete a zone (permanent-only; reload applies).
    DeleteZone {
        /// Zone to delete.
        zone: ZoneName,
    },
    /// Runtime-only emergency switch: drops every packet.
    SetPanicMode {
        /// Desired panic-mode state.
        enabled: bool,
    },
    /// Persist the entire runtime configuration to permanent.
    RuntimeToPermanent,
    /// Change firewalld's `LogDenied` setting.
    SetLogDenied {
        /// Desired setting.
        value: LogDenied,
    },
    /// Reload firewalld: permanent config becomes runtime, runtime-only
    /// changes are lost.
    Reload,
}

/// Why an operation was rejected before ever reaching firewalld.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OperationError {
    /// The referenced zone exists in neither runtime nor permanent config.
    #[error("zone `{0}` not found")]
    UnknownZone(String),
    /// The desired state already holds; applying would be a no-op.
    #[error("{0}")]
    NothingToDo(String),
    /// The operation can never succeed, e.g. the name is already taken.
    #[error("{0}")]
    Invalid(String),
}

/// The ipset types firewalld supports (`--get-ipset-types`); checked before
/// the type string can reach an argument vector.
pub const IPSET_TYPES: &[&str] = &[
    "hash:ip",
    "hash:ip,mark",
    "hash:ip,port",
    "hash:ip,port,ip",
    "hash:ip,port,net",
    "hash:mac",
    "hash:net",
    "hash:net,iface",
    "hash:net,net",
    "hash:net,port",
    "hash:net,port,net",
];

fn scoped_postcondition(
    target: ConfigurationTarget,
    runtime: Option<bool>,
    permanent: Option<bool>,
) -> Option<bool> {
    match target {
        ConfigurationTarget::Runtime => runtime,
        ConfigurationTarget::Permanent => permanent,
        ConfigurationTarget::RuntimeAndPermanent => Some(runtime? && permanent?),
    }
}

enum PostconditionProbe {
    NotApplicable,
    Unknown,
    Holds(bool),
}

impl PostconditionProbe {
    fn from_option(value: Option<bool>) -> Self {
        value.map_or(Self::Unknown, Self::Holds)
    }
}

impl FirewallOperation {
    /// Short imperative summary for the confirmation modal.
    #[must_use]
    #[allow(clippy::too_many_lines)] // one arm per operation
    pub fn describe(&self) -> String {
        match self {
            Self::AddTemporaryService {
                zone,
                service,
                seconds,
            } => format!("temporarily allow service `{service}` in zone `{zone}` for {seconds}s"),
            Self::AddService { zone, service, .. } => {
                format!("add service `{service}` to zone `{zone}`")
            }
            Self::RemoveService { zone, service, .. } => {
                format!("remove service `{service}` from zone `{zone}`")
            }
            Self::AddPort { zone, port, .. } => format!("open port {port} in zone `{zone}`"),
            Self::RemovePort { zone, port, .. } => {
                format!("close port {port} in zone `{zone}`")
            }
            Self::SetDefaultZone { zone } => format!("set default zone to `{zone}`"),
            Self::SetMasquerade {
                zone,
                enabled: true,
                ..
            } => {
                format!("enable masquerade in zone `{zone}`")
            }
            Self::SetMasquerade {
                zone,
                enabled: false,
                ..
            } => {
                format!("disable masquerade in zone `{zone}`")
            }
            Self::SetZoneTarget { zone, zone_target } => {
                format!("set target of zone `{zone}` to {}", zone_target.as_str())
            }
            Self::AddSourcePort { zone, port, .. } => {
                format!("add source-port {port} to zone `{zone}`")
            }
            Self::RemoveSourcePort { zone, port, .. } => {
                format!("remove source-port {port} from zone `{zone}`")
            }
            Self::AddProtocol { zone, protocol, .. } => {
                format!("allow protocol `{protocol}` in zone `{zone}`")
            }
            Self::RemoveProtocol { zone, protocol, .. } => {
                format!("stop allowing protocol `{protocol}` in zone `{zone}`")
            }
            Self::SetForward {
                zone,
                enabled: true,
                ..
            } => format!("enable intra-zone forwarding in `{zone}`"),
            Self::SetForward {
                zone,
                enabled: false,
                ..
            } => format!("disable intra-zone forwarding in `{zone}`"),
            Self::SetIcmpBlockInversion {
                zone,
                enabled: true,
                ..
            } => format!("invert icmp-block set in zone `{zone}`"),
            Self::SetIcmpBlockInversion {
                zone,
                enabled: false,
                ..
            } => format!("clear icmp-block inversion in zone `{zone}`"),
            Self::AddForwardPort { zone, forward, .. } => {
                format!("add forward {} to zone `{zone}`", forward.spec_string())
            }
            Self::RemoveForwardPort { zone, forward, .. } => {
                format!(
                    "remove forward {} from zone `{zone}`",
                    forward.spec_string()
                )
            }
            Self::AddRichRule { zone, rule, .. } => {
                format!("add rich rule to zone `{zone}`: {rule}")
            }
            Self::RemoveRichRule { zone, rule, .. } => {
                format!("remove rich rule from zone `{zone}`: {rule}")
            }
            Self::AddInterface {
                zone, interface, ..
            } => {
                format!("bind interface `{interface}` to zone `{zone}`")
            }
            Self::RemoveInterface {
                zone, interface, ..
            } => {
                format!("unbind interface `{interface}` from zone `{zone}`")
            }
            Self::AddSource { zone, source, .. } => {
                format!("bind source {source} to zone `{zone}`")
            }
            Self::RemoveSource { zone, source, .. } => {
                format!("unbind source {source} from zone `{zone}`")
            }
            Self::AddIcmpBlock { zone, icmp, .. } => {
                format!("block ICMP `{icmp}` in zone `{zone}`")
            }
            Self::RemoveIcmpBlock { zone, icmp, .. } => {
                format!("unblock ICMP `{icmp}` in zone `{zone}`")
            }
            Self::CreatePolicy { policy } => format!("create policy `{policy}` (permanent)"),
            Self::DeletePolicy { policy } => format!("delete policy `{policy}` (permanent)"),
            Self::SetPolicyTarget {
                policy,
                policy_target,
            } => {
                format!("set policy `{policy}` target to {}", policy_target.as_str())
            }
            Self::AddPolicyIngressZone { policy, zone } => {
                format!("add ingress zone `{zone}` to policy `{policy}`")
            }
            Self::AddPolicyEgressZone { policy, zone } => {
                format!("add egress zone `{zone}` to policy `{policy}`")
            }
            Self::AddPolicyService {
                policy, service, ..
            } => {
                format!("add service `{service}` to policy `{policy}`")
            }
            Self::RemovePolicyService {
                policy, service, ..
            } => {
                format!("remove service `{service}` from policy `{policy}`")
            }
            Self::CreateService { service } => {
                format!("create service `{service}` (permanent)")
            }
            Self::DeleteService { service } => format!("delete service `{service}` (permanent)"),
            Self::AddServicePort { service, port } => {
                format!("add port {port} to service `{service}` (permanent)")
            }
            Self::RemoveServicePort { service, port } => {
                format!("remove port {port} from service `{service}` (permanent)")
            }
            Self::CreateIpSet { name, kind } => {
                format!("create ipset `{name}` of type `{kind}` (permanent)")
            }
            Self::DeleteIpSet { name } => format!("delete ipset `{name}` (permanent)"),
            Self::AddIpSetEntry { name, entry, .. } => {
                format!("add {entry} to ipset `{name}`")
            }
            Self::RemoveIpSetEntry { name, entry, .. } => {
                format!("remove {entry} from ipset `{name}`")
            }
            Self::CreateZone { zone } => format!("create zone `{zone}` (permanent)"),
            Self::DeleteZone { zone } => format!("delete zone `{zone}` (permanent)"),
            Self::SetPanicMode { enabled: true } => "enable PANIC MODE".to_owned(),
            Self::SetPanicMode { enabled: false } => "disable panic mode".to_owned(),
            Self::RuntimeToPermanent => "persist runtime configuration to permanent".to_owned(),
            Self::SetLogDenied { value } => format!("set LogDenied to `{}`", value.as_str()),
            Self::Reload => "reload firewalld".to_owned(),
        }
    }

    /// Past-tense message for the success toast, spelling out the target.
    #[allow(clippy::too_many_lines)] // one arm per operation
    #[must_use]
    pub fn success_message(&self) -> String {
        let scoped =
            |text: String, target: ConfigurationTarget| format!("{text} ({})", target.label());
        match self {
            Self::AddTemporaryService {
                zone,
                service,
                seconds,
            } => format!(
                "service `{service}` temporarily allowed in zone `{zone}` — auto-removes in {seconds}s"
            ),
            Self::AddService {
                zone,
                service,
                target,
            } => scoped(
                format!("service `{service}` added to zone `{zone}`"),
                *target,
            ),
            Self::RemoveService {
                zone,
                service,
                target,
            } => scoped(
                format!("service `{service}` removed from zone `{zone}`"),
                *target,
            ),
            Self::AddPort { zone, port, target } => {
                scoped(format!("port {port} opened in zone `{zone}`"), *target)
            }
            Self::RemovePort { zone, port, target } => {
                scoped(format!("port {port} closed in zone `{zone}`"), *target)
            }
            Self::SetDefaultZone { zone } => format!("default zone set to `{zone}`"),
            Self::SetMasquerade {
                zone,
                enabled,
                target,
            } => scoped(
                format!(
                    "masquerade {} in zone `{zone}`",
                    if *enabled { "enabled" } else { "disabled" }
                ),
                *target,
            ),
            Self::SetZoneTarget { zone, zone_target } => format!(
                "target of zone `{zone}` set to {} (permanent; reload to activate)",
                zone_target.as_str()
            ),
            Self::AddSourcePort { zone, port, target } => scoped(
                format!("source-port {port} added to zone `{zone}`"),
                *target,
            ),
            Self::RemoveSourcePort { zone, port, target } => scoped(
                format!("source-port {port} removed from zone `{zone}`"),
                *target,
            ),
            Self::AddProtocol {
                zone,
                protocol,
                target,
            } => scoped(
                format!("protocol `{protocol}` allowed in zone `{zone}`"),
                *target,
            ),
            Self::RemoveProtocol {
                zone,
                protocol,
                target,
            } => scoped(
                format!("protocol `{protocol}` removed from zone `{zone}`"),
                *target,
            ),
            Self::SetForward {
                zone,
                enabled,
                target,
            } => scoped(
                format!(
                    "intra-zone forwarding {} in `{zone}`",
                    if *enabled { "enabled" } else { "disabled" }
                ),
                *target,
            ),
            Self::SetIcmpBlockInversion {
                zone,
                enabled,
                target,
            } => scoped(
                format!(
                    "icmp-block inversion {} in `{zone}`",
                    if *enabled { "on" } else { "off" }
                ),
                *target,
            ),
            Self::AddForwardPort {
                zone,
                forward,
                target,
            } => scoped(
                format!("forward {} added to zone `{zone}`", forward.spec_string()),
                *target,
            ),
            Self::RemoveForwardPort {
                zone,
                forward,
                target,
            } => scoped(
                format!(
                    "forward {} removed from zone `{zone}`",
                    forward.spec_string()
                ),
                *target,
            ),
            Self::AddRichRule { zone, target, .. } => {
                scoped(format!("rich rule added to zone `{zone}`"), *target)
            }
            Self::RemoveRichRule { zone, target, .. } => {
                scoped(format!("rich rule removed from zone `{zone}`"), *target)
            }
            Self::AddInterface {
                zone,
                interface,
                target,
            } => scoped(
                format!("interface `{interface}` bound to zone `{zone}`"),
                *target,
            ),
            Self::RemoveInterface {
                zone,
                interface,
                target,
            } => scoped(
                format!("interface `{interface}` unbound from zone `{zone}`"),
                *target,
            ),
            Self::AddSource {
                zone,
                source,
                target,
            } => scoped(format!("source {source} bound to zone `{zone}`"), *target),
            Self::RemoveSource {
                zone,
                source,
                target,
            } => scoped(
                format!("source {source} unbound from zone `{zone}`"),
                *target,
            ),
            Self::AddIcmpBlock { zone, icmp, target } => {
                scoped(format!("ICMP `{icmp}` blocked in zone `{zone}`"), *target)
            }
            Self::RemoveIcmpBlock { zone, icmp, target } => {
                scoped(format!("ICMP `{icmp}` unblocked in zone `{zone}`"), *target)
            }
            Self::CreatePolicy { policy } => {
                format!("policy `{policy}` created (permanent) — reload (ctrl-r) to activate")
            }
            Self::DeletePolicy { policy } => {
                format!("policy `{policy}` deleted (permanent) — reload (ctrl-r) to apply")
            }
            Self::SetPolicyTarget {
                policy,
                policy_target,
            } => {
                format!("policy `{policy}` target set to {}", policy_target.as_str())
            }
            Self::AddPolicyIngressZone { policy, zone } => {
                format!("ingress zone `{zone}` added to policy `{policy}` (permanent)")
            }
            Self::AddPolicyEgressZone { policy, zone } => {
                format!("egress zone `{zone}` added to policy `{policy}` (permanent)")
            }
            Self::AddPolicyService {
                policy,
                service,
                target,
            } => scoped(
                format!("service `{service}` added to policy `{policy}`"),
                *target,
            ),
            Self::RemovePolicyService {
                policy,
                service,
                target,
            } => scoped(
                format!("service `{service}` removed from policy `{policy}`"),
                *target,
            ),
            Self::CreateService { service } => {
                format!("service `{service}` created (permanent) — reload (ctrl-r) to activate")
            }
            Self::DeleteService { service } => {
                format!("service `{service}` deleted (permanent) — reload (ctrl-r) to apply")
            }
            Self::AddServicePort { service, port } => {
                format!("port {port} added to service `{service}` (permanent) — reload to apply")
            }
            Self::RemoveServicePort { service, port } => {
                format!(
                    "port {port} removed from service `{service}` (permanent) — reload to apply"
                )
            }
            Self::CreateIpSet { name, .. } => {
                format!("ipset `{name}` created (permanent) — reload (ctrl-r) to activate")
            }
            Self::DeleteIpSet { name } => {
                format!("ipset `{name}` deleted (permanent) — reload (ctrl-r) to apply")
            }
            Self::AddIpSetEntry {
                name,
                entry,
                target,
            } => {
                format!("{entry} added to ipset `{name}` ({})", target.label())
            }
            Self::RemoveIpSetEntry {
                name,
                entry,
                target,
            } => {
                format!("{entry} removed from ipset `{name}` ({})", target.label())
            }
            Self::CreateZone { zone } => {
                format!("zone `{zone}` created (permanent) — reload (ctrl-r) to activate")
            }
            Self::DeleteZone { zone } => {
                format!("zone `{zone}` deleted (permanent) — reload (ctrl-r) to apply")
            }
            Self::SetPanicMode { enabled: true } => {
                "PANIC MODE ENABLED — all packets are dropped".to_owned()
            }
            Self::SetPanicMode { enabled: false } => "panic mode disabled".to_owned(),
            Self::RuntimeToPermanent => "runtime configuration persisted to permanent".to_owned(),
            Self::SetLogDenied { value } => {
                format!("LogDenied set to `{}`", value.as_str())
            }
            Self::Reload => "firewalld reloaded — runtime reset to permanent".to_owned(),
        }
    }

    /// The zone a runtime invocation would reference (`--zone=…` /
    /// `--set-default-zone=…`), if any. Zone/ipset lifecycle operations return
    /// `None` — they only touch config files.
    #[must_use]
    pub fn zone(&self) -> Option<&ZoneName> {
        match self {
            Self::AddService { zone, .. }
            | Self::RemoveService { zone, .. }
            | Self::AddPort { zone, .. }
            | Self::RemovePort { zone, .. }
            | Self::SetMasquerade { zone, .. }
            | Self::AddForwardPort { zone, .. }
            | Self::RemoveForwardPort { zone, .. }
            | Self::AddRichRule { zone, .. }
            | Self::RemoveRichRule { zone, .. }
            | Self::AddInterface { zone, .. }
            | Self::RemoveInterface { zone, .. }
            | Self::AddSource { zone, .. }
            | Self::RemoveSource { zone, .. }
            | Self::AddIcmpBlock { zone, .. }
            | Self::RemoveIcmpBlock { zone, .. }
            | Self::SetZoneTarget { zone, .. }
            | Self::AddSourcePort { zone, .. }
            | Self::RemoveSourcePort { zone, .. }
            | Self::AddProtocol { zone, .. }
            | Self::RemoveProtocol { zone, .. }
            | Self::SetForward { zone, .. }
            | Self::SetIcmpBlockInversion { zone, .. }
            | Self::SetDefaultZone { zone } => Some(zone),
            _ => None,
        }
    }

    /// The same operation retargeted, for variants that carry a target.
    /// `None` when the variant's target is fixed (e.g. `SetDefaultZone`).
    #[must_use]
    pub fn with_target(&self, target: ConfigurationTarget) -> Option<Self> {
        let mut retargeted = self.clone();
        match &mut retargeted {
            Self::AddService { target: t, .. }
            | Self::RemoveService { target: t, .. }
            | Self::AddPort { target: t, .. }
            | Self::RemovePort { target: t, .. }
            | Self::SetMasquerade { target: t, .. }
            | Self::AddForwardPort { target: t, .. }
            | Self::RemoveForwardPort { target: t, .. }
            | Self::AddRichRule { target: t, .. }
            | Self::RemoveRichRule { target: t, .. }
            | Self::AddInterface { target: t, .. }
            | Self::RemoveInterface { target: t, .. }
            | Self::AddSource { target: t, .. }
            | Self::RemoveSource { target: t, .. }
            | Self::AddIpSetEntry { target: t, .. }
            | Self::RemoveIpSetEntry { target: t, .. }
            | Self::AddIcmpBlock { target: t, .. }
            | Self::RemoveIcmpBlock { target: t, .. }
            | Self::AddSourcePort { target: t, .. }
            | Self::RemoveSourcePort { target: t, .. }
            | Self::AddProtocol { target: t, .. }
            | Self::RemoveProtocol { target: t, .. }
            | Self::SetForward { target: t, .. }
            | Self::SetIcmpBlockInversion { target: t, .. }
            | Self::AddPolicyService { target: t, .. }
            | Self::RemovePolicyService { target: t, .. } => {
                *t = target;
                Some(retargeted)
            }
            _ => None,
        }
    }

    /// The membership probe for zone-scoped add/remove edits: a check for
    /// "is this item present in the given zone details" plus whether the
    /// operation adds (`true`) or removes (`false`). `None` for operations
    /// that are not simple zone-collection edits.
    #[must_use]
    #[allow(clippy::type_complexity)]
    fn zone_probe(&self) -> Option<(Box<dyn Fn(&super::zone::ZoneDetails) -> bool + '_>, bool)> {
        match self {
            Self::AddService { service, .. } => {
                Some((Box::new(move |z| z.services.contains(service)), true))
            }
            Self::RemoveService { service, .. } => {
                Some((Box::new(move |z| z.services.contains(service)), false))
            }
            Self::AddPort { port, .. } => Some((Box::new(move |z| z.ports.contains(port)), true)),
            Self::RemovePort { port, .. } => {
                Some((Box::new(move |z| z.ports.contains(port)), false))
            }
            Self::AddForwardPort { forward, .. } => {
                Some((Box::new(move |z| z.forward_ports.contains(forward)), true))
            }
            Self::RemoveForwardPort { forward, .. } => {
                Some((Box::new(move |z| z.forward_ports.contains(forward)), false))
            }
            Self::AddRichRule { rule, .. } => {
                Some((Box::new(move |z| z.rich_rules.contains(rule)), true))
            }
            Self::RemoveRichRule { rule, .. } => {
                Some((Box::new(move |z| z.rich_rules.contains(rule)), false))
            }
            Self::AddInterface { interface, .. } => {
                Some((Box::new(move |z| z.interfaces.contains(interface)), true))
            }
            Self::RemoveInterface { interface, .. } => {
                Some((Box::new(move |z| z.interfaces.contains(interface)), false))
            }
            Self::AddSource { source, .. } => {
                Some((Box::new(move |z| z.sources.contains(source)), true))
            }
            Self::RemoveSource { source, .. } => {
                Some((Box::new(move |z| z.sources.contains(source)), false))
            }
            Self::AddIcmpBlock { icmp, .. } => {
                Some((Box::new(move |z| z.icmp_blocks.contains(icmp)), true))
            }
            Self::RemoveIcmpBlock { icmp, .. } => {
                Some((Box::new(move |z| z.icmp_blocks.contains(icmp)), false))
            }
            Self::SetMasquerade { enabled, .. } => {
                let desired = *enabled;
                Some((Box::new(move |z| z.masquerade == desired), true))
            }
            Self::AddSourcePort { port, .. } => {
                Some((Box::new(move |z| z.source_ports.contains(port)), true))
            }
            Self::RemoveSourcePort { port, .. } => {
                Some((Box::new(move |z| z.source_ports.contains(port)), false))
            }
            Self::AddProtocol { protocol, .. } => {
                Some((Box::new(move |z| z.protocols.contains(protocol)), true))
            }
            Self::RemoveProtocol { protocol, .. } => {
                Some((Box::new(move |z| z.protocols.contains(protocol)), false))
            }
            Self::SetForward { enabled, .. } => {
                let desired = *enabled;
                Some((Box::new(move |z| z.forward == desired), true))
            }
            Self::SetIcmpBlockInversion { enabled, .. } => {
                let desired = *enabled;
                Some((Box::new(move |z| z.icmp_block_inversion == desired), true))
            }
            Self::SetZoneTarget { zone_target, .. } => {
                let desired = *zone_target;
                Some((Box::new(move |z| z.target == desired), true))
            }
            _ => None,
        }
    }

    fn ipset_postcondition(&self, snapshot: &FirewallSnapshot) -> PostconditionProbe {
        let target = self.target();
        let complete = snapshot.section_is_complete(SnapshotSection::IpSets, target);
        match self {
            Self::CreateIpSet { name, .. } => PostconditionProbe::from_option(
                complete.then(|| snapshot.ipsets.permanent.contains_key(name)),
            ),
            Self::DeleteIpSet { name } => PostconditionProbe::from_option(
                complete.then(|| !snapshot.ipsets.permanent.contains_key(name)),
            ),
            Self::AddIpSetEntry { name, entry, .. }
            | Self::RemoveIpSetEntry { name, entry, .. } => {
                if !complete {
                    return PostconditionProbe::Unknown;
                }
                let entry = entry.to_string();
                let adding = matches!(self, Self::AddIpSetEntry { .. });
                let desired =
                    |info: &super::snapshot::IpSetInfo| info.entries.contains(&entry) == adding;
                PostconditionProbe::from_option(scoped_postcondition(
                    target,
                    snapshot.ipsets.runtime.get(name).map(&desired),
                    snapshot.ipsets.permanent.get(name).map(&desired),
                ))
            }
            _ => PostconditionProbe::NotApplicable,
        }
    }

    fn policy_postcondition(&self, snapshot: &FirewallSnapshot) -> PostconditionProbe {
        let target = self.target();
        let complete = snapshot.section_is_complete(SnapshotSection::Policies, target);
        let permanent = |policy: &PolicyName| snapshot.policies.permanent.get(policy);
        let result = match self {
            Self::CreatePolicy { policy } => complete.then(|| permanent(policy).is_some()),
            Self::DeletePolicy { policy } => complete.then(|| permanent(policy).is_none()),
            Self::SetPolicyTarget {
                policy,
                policy_target,
            } => complete.then(|| permanent(policy).is_some_and(|p| p.target == *policy_target)),
            Self::AddPolicyIngressZone { policy, zone } => {
                complete.then(|| permanent(policy).is_some_and(|p| p.ingress_zones.contains(zone)))
            }
            Self::AddPolicyEgressZone { policy, zone } => {
                complete.then(|| permanent(policy).is_some_and(|p| p.egress_zones.contains(zone)))
            }
            Self::AddPolicyService {
                policy, service, ..
            }
            | Self::RemovePolicyService {
                policy, service, ..
            } => {
                if !complete {
                    return PostconditionProbe::Unknown;
                }
                let adding = matches!(self, Self::AddPolicyService { .. });
                let desired = |details: &super::policy::PolicyDetails| {
                    details.services.contains(service) == adding
                };
                return PostconditionProbe::from_option(scoped_postcondition(
                    target,
                    snapshot.policies.runtime.get(policy).map(&desired),
                    permanent(policy).map(&desired),
                ));
            }
            _ => return PostconditionProbe::NotApplicable,
        };
        PostconditionProbe::from_option(result)
    }

    /// Whether this operation's desired state is visible in `snapshot`:
    /// an add's item present (a remove's absent) in every targeted scope
    /// whose zone exists. `None` when the operation has no checkable
    /// zone-collection postcondition.
    #[must_use]
    pub fn postcondition_holds(&self, snapshot: &FirewallSnapshot) -> Option<bool> {
        let target = self.target();
        match self.ipset_postcondition(snapshot) {
            PostconditionProbe::Holds(holds) => return Some(holds),
            PostconditionProbe::Unknown => return None,
            PostconditionProbe::NotApplicable => {}
        }
        match self.policy_postcondition(snapshot) {
            PostconditionProbe::Holds(holds) => return Some(holds),
            PostconditionProbe::Unknown => return None,
            PostconditionProbe::NotApplicable => {}
        }
        if !snapshot.section_is_complete(SnapshotSection::Zones, target) {
            return None;
        }
        let zone = self.zone()?.clone();
        let (contains, adding) = self.zone_probe()?;
        let satisfied = |details: &super::zone::ZoneDetails| {
            if adding {
                contains(details)
            } else {
                !contains(details)
            }
        };
        scoped_postcondition(
            target,
            snapshot.runtime.get(&zone).map(&satisfied),
            snapshot.permanent.get(&zone).map(&satisfied),
        )
    }

    /// Desired-state narrowing: shrinks a `RuntimeAndPermanent` target to only
    /// the scope(s) that actually need the change. Adding a service that
    /// runtime already has but permanent lacks becomes a permanent-only
    /// operation (drift repair), and removing an item that exists only in
    /// runtime never issues a doomed permanent command. Single-scope targets
    /// and non-zone operations are returned unchanged; so is an operation
    /// where both or neither scope needs work (`validate()` reports the
    /// nothing-to-do case).
    #[must_use]
    pub fn narrowed_for(&self, snapshot: &FirewallSnapshot) -> Self {
        if self.target() != ConfigurationTarget::RuntimeAndPermanent {
            return self.clone();
        }
        let observed_section = match self {
            Self::AddIpSetEntry { .. } | Self::RemoveIpSetEntry { .. } => {
                Some(SnapshotSection::IpSets)
            }
            Self::AddPolicyService { .. } | Self::RemovePolicyService { .. } => {
                Some(SnapshotSection::Policies)
            }
            _ if self.zone_probe().is_some() => Some(SnapshotSection::Zones),
            _ => None,
        };
        if observed_section.is_some_and(|section| {
            !snapshot.section_is_complete(section, ConfigurationTarget::RuntimeAndPermanent)
        }) {
            return self.clone();
        }
        let scoped_needs = match self {
            Self::AddIpSetEntry { name, entry, .. }
            | Self::RemoveIpSetEntry { name, entry, .. } => {
                let entry = entry.to_string();
                let adding = matches!(self, Self::AddIpSetEntry { .. });
                let needs =
                    |info: &super::snapshot::IpSetInfo| info.entries.contains(&entry) != adding;
                Some((
                    snapshot.ipsets.runtime.get(name).is_some_and(&needs),
                    snapshot.ipsets.permanent.get(name).is_some_and(&needs),
                ))
            }
            Self::AddPolicyService {
                policy, service, ..
            }
            | Self::RemovePolicyService {
                policy, service, ..
            } => {
                let adding = matches!(self, Self::AddPolicyService { .. });
                let needs = |details: &super::policy::PolicyDetails| {
                    details.services.contains(service) != adding
                };
                Some((
                    snapshot.policies.runtime.get(policy).is_some_and(&needs),
                    snapshot.policies.permanent.get(policy).is_some_and(&needs),
                ))
            }
            _ => None,
        };
        if let Some((runtime_needs, permanent_needs)) = scoped_needs {
            let narrowed = match (runtime_needs, permanent_needs) {
                (true, false) => ConfigurationTarget::Runtime,
                (false, true) => ConfigurationTarget::Permanent,
                _ => return self.clone(),
            };
            return self.with_target(narrowed).unwrap_or_else(|| self.clone());
        }
        let Some(zone) = self.zone().cloned() else {
            return self.clone();
        };
        let Some((contains, adding)) = self.zone_probe() else {
            return self.clone();
        };
        // A scope needs the change when its zone exists there and the desired
        // state does not hold yet: an add needs scopes lacking the item, a
        // remove needs scopes that still have it.
        let needs = |details: &super::zone::ZoneDetails| {
            if adding {
                !contains(details)
            } else {
                contains(details)
            }
        };
        let runtime_needs = snapshot.runtime.get(&zone).is_some_and(&needs);
        let permanent_needs = snapshot.permanent.get(&zone).is_some_and(&needs);
        let narrowed = match (runtime_needs, permanent_needs) {
            (true, false) => ConfigurationTarget::Runtime,
            (false, true) => ConfigurationTarget::Permanent,
            _ => return self.clone(),
        };
        self.with_target(narrowed).unwrap_or_else(|| self.clone())
    }

    /// The configuration target this operation touches. Variants without a
    /// `target` field have a fixed answer: panic mode is runtime-only,
    /// lifecycle operations are permanent-only, global ones hit both.
    #[must_use]
    pub fn target(&self) -> ConfigurationTarget {
        match self {
            Self::AddService { target, .. }
            | Self::RemoveService { target, .. }
            | Self::AddPort { target, .. }
            | Self::RemovePort { target, .. }
            | Self::SetMasquerade { target, .. }
            | Self::AddForwardPort { target, .. }
            | Self::RemoveForwardPort { target, .. }
            | Self::AddRichRule { target, .. }
            | Self::RemoveRichRule { target, .. }
            | Self::AddInterface { target, .. }
            | Self::RemoveInterface { target, .. }
            | Self::AddSource { target, .. }
            | Self::RemoveSource { target, .. }
            | Self::AddIpSetEntry { target, .. }
            | Self::RemoveIpSetEntry { target, .. }
            | Self::AddIcmpBlock { target, .. }
            | Self::RemoveIcmpBlock { target, .. }
            | Self::AddSourcePort { target, .. }
            | Self::RemoveSourcePort { target, .. }
            | Self::AddProtocol { target, .. }
            | Self::RemoveProtocol { target, .. }
            | Self::SetForward { target, .. }
            | Self::SetIcmpBlockInversion { target, .. }
            | Self::AddPolicyService { target, .. }
            | Self::RemovePolicyService { target, .. } => *target,
            // Panic mode and timed rules are inherently runtime-only.
            Self::SetPanicMode { .. } | Self::AddTemporaryService { .. } => {
                ConfigurationTarget::Runtime
            }
            // Zone/ipset creation and deletion are permanent-only in firewalld.
            Self::CreateZone { .. }
            | Self::DeleteZone { .. }
            | Self::SetZoneTarget { .. }
            | Self::CreateService { .. }
            | Self::DeleteService { .. }
            | Self::AddServicePort { .. }
            | Self::RemoveServicePort { .. }
            | Self::CreatePolicy { .. }
            | Self::DeletePolicy { .. }
            | Self::SetPolicyTarget { .. }
            | Self::AddPolicyIngressZone { .. }
            | Self::AddPolicyEgressZone { .. }
            | Self::CreateIpSet { .. }
            | Self::DeleteIpSet { .. }
            | Self::RuntimeToPermanent => ConfigurationTarget::Permanent,
            // Global operations affect both configurations inherently.
            Self::SetDefaultZone { .. } | Self::SetLogDenied { .. } | Self::Reload => {
                ConfigurationTarget::RuntimeAndPermanent
            }
        }
    }

    /// Warning line for the confirmation modal, when the operation can break
    /// existing connectivity.
    #[must_use]
    pub const fn connectivity_warning(&self) -> Option<&'static str> {
        match self {
            Self::RemoveService { .. }
            | Self::RemovePort { .. }
            | Self::RemoveForwardPort { .. }
            | Self::RemoveSourcePort { .. }
            | Self::RemoveProtocol { .. }
            | Self::RemoveRichRule { .. } => Some("may cut existing connections using this rule"),
            Self::SetMasquerade { enabled: false, .. } => {
                Some("disabling masquerade may break NAT'd clients")
            }
            Self::SetForward { enabled: false, .. } => {
                Some("disabling forwarding may break routed traffic between this zone's interfaces")
            }
            Self::SetIcmpBlockInversion { enabled: true, .. } => {
                Some("inverting icmp-block blocks all ICMP except the listed types")
            }
            Self::SetZoneTarget {
                zone_target: ZoneTarget::Drop | ZoneTarget::Reject,
                ..
            } => Some("a DROP/REJECT target blocks everything not explicitly allowed"),
            Self::RemoveInterface { .. } => {
                Some("traffic on this interface falls back to the default zone")
            }
            Self::RemoveSource { .. } => {
                Some("traffic from this source falls back to the default zone")
            }
            Self::DeleteZone { .. } => {
                Some("zone bindings fall back to the default zone after the next reload")
            }
            Self::DeleteService { .. } => {
                Some("zones using this service lose it after the next reload")
            }
            Self::DeletePolicy { .. } => {
                Some("traffic governed by this policy falls back to zone rules")
            }
            Self::DeleteIpSet { .. } => {
                Some("zones referencing this ipset lose those sources after the next reload")
            }
            Self::RemoveIpSetEntry { .. } => Some("rules matching this entry stop applying to it"),
            Self::SetPanicMode { enabled: true } => {
                Some("DROPS ALL PACKETS — remote sessions WILL be cut")
            }
            Self::Reload => Some("runtime-only changes will be lost"),
            // Re-zoning: these silently decide what a session is allowed to do.
            Self::SetDefaultZone { .. } => Some(
                "re-homes every unbound interface and source — a restrictive default can cut your session",
            ),
            Self::AddInterface { .. } => Some(
                "moves this interface's traffic under a new zone's rules — may cut sessions on it",
            ),
            Self::AddSource { .. } => Some(
                "source bindings match at the highest precedence — binding your own client's address into a restrictive zone cuts you off",
            ),
            _ => None,
        }
    }

    /// Checks the operation makes sense against the current snapshot. This is
    /// a UX guard, not a race-free guarantee — firewalld revalidates anyway.
    #[allow(clippy::too_many_lines)] // one arm per operation
    pub fn validate(&self, snapshot: &FirewallSnapshot) -> Result<(), OperationError> {
        let target = self.target();
        let required_section = match self {
            Self::CreateIpSet { .. }
            | Self::DeleteIpSet { .. }
            | Self::AddIpSetEntry { .. }
            | Self::RemoveIpSetEntry { .. } => Some(SnapshotSection::IpSets),
            Self::CreatePolicy { .. }
            | Self::DeletePolicy { .. }
            | Self::SetPolicyTarget { .. }
            | Self::AddPolicyIngressZone { .. }
            | Self::AddPolicyEgressZone { .. }
            | Self::AddPolicyService { .. }
            | Self::RemovePolicyService { .. } => Some(SnapshotSection::Policies),
            Self::CreateService { .. }
            | Self::DeleteService { .. }
            | Self::AddServicePort { .. }
            | Self::RemoveServicePort { .. } => Some(SnapshotSection::Services),
            Self::AddService { .. }
            | Self::AddTemporaryService { .. }
            | Self::RemoveService { .. }
            | Self::AddPort { .. }
            | Self::RemovePort { .. }
            | Self::SetDefaultZone { .. }
            | Self::SetMasquerade { .. }
            | Self::SetZoneTarget { .. }
            | Self::AddForwardPort { .. }
            | Self::RemoveForwardPort { .. }
            | Self::AddRichRule { .. }
            | Self::RemoveRichRule { .. }
            | Self::AddInterface { .. }
            | Self::RemoveInterface { .. }
            | Self::AddSource { .. }
            | Self::RemoveSource { .. }
            | Self::CreateZone { .. }
            | Self::DeleteZone { .. }
            | Self::AddIcmpBlock { .. }
            | Self::RemoveIcmpBlock { .. }
            | Self::AddSourcePort { .. }
            | Self::RemoveSourcePort { .. }
            | Self::AddProtocol { .. }
            | Self::RemoveProtocol { .. }
            | Self::SetForward { .. }
            | Self::SetIcmpBlockInversion { .. } => Some(SnapshotSection::Zones),
            Self::SetPanicMode { .. }
            | Self::RuntimeToPermanent
            | Self::SetLogDenied { .. }
            | Self::Reload => None,
        };
        if let Some(section) = required_section
            && !snapshot.section_is_complete(section, target)
        {
            return Err(OperationError::Invalid(format!(
                "cannot safely validate {} {} state because the latest snapshot is incomplete",
                target.label(),
                section.label()
            )));
        }
        let zone_exists = |zone: &ZoneName| {
            if snapshot.runtime.contains_key(zone) || snapshot.permanent.contains_key(zone) {
                Ok(())
            } else {
                Err(OperationError::UnknownZone(zone.to_string()))
            }
        };
        let presence = |zone: &ZoneName, check: &dyn Fn(&super::zone::ZoneDetails) -> bool| {
            (
                snapshot.runtime.get(zone).is_some_and(check),
                snapshot.permanent.get(zone).is_some_and(check),
            )
        };
        let zone_exists_for = |zone: &ZoneName| {
            let runtime = snapshot.runtime.contains_key(zone);
            let permanent = snapshot.permanent.contains_key(zone);
            let exists = match target {
                ConfigurationTarget::Runtime => runtime,
                ConfigurationTarget::Permanent => permanent,
                ConfigurationTarget::RuntimeAndPermanent => runtime && permanent,
            };
            if exists {
                Ok(())
            } else {
                Err(OperationError::Invalid(format!(
                    "zone `{zone}` does not exist in the {} configuration",
                    target.label()
                )))
            }
        };
        // The shared body of every zone-collection add/remove arm: the zone
        // must exist, and adding an item present in both configs (or removing
        // one present in neither) is a no-op the modal should never offer.
        let membership = |zone: &ZoneName,
                          adding: bool,
                          check: &dyn Fn(&super::zone::ZoneDetails) -> bool,
                          message: String|
         -> Result<(), OperationError> {
            zone_exists_for(zone)?;
            let (runtime, permanent) = presence(zone, check);
            let all_present = match target {
                ConfigurationTarget::Runtime => runtime,
                ConfigurationTarget::Permanent => permanent,
                ConfigurationTarget::RuntimeAndPermanent => runtime && permanent,
            };
            let all_absent = match target {
                ConfigurationTarget::Runtime => !runtime,
                ConfigurationTarget::Permanent => !permanent,
                ConfigurationTarget::RuntimeAndPermanent => !runtime && !permanent,
            };
            if adding && all_present {
                return Err(OperationError::NothingToDo(message));
            }
            if !adding && all_absent {
                return Err(OperationError::NothingToDo(message));
            }
            Ok(())
        };

        match self {
            Self::AddTemporaryService { zone, service, .. } => membership(
                zone,
                true,
                &|z| z.services.contains(service),
                format!("service `{service}` is already enabled in runtime and permanent"),
            )?,
            Self::AddService { zone, service, .. } => membership(
                zone,
                true,
                &|z| z.services.contains(service),
                format!("service `{service}` is already enabled in runtime and permanent"),
            )?,
            Self::RemoveService { zone, service, .. } => membership(
                zone,
                false,
                &|z| z.services.contains(service),
                format!("service `{service}` is not enabled in zone `{zone}`"),
            )?,
            Self::AddPort { zone, port, .. } => membership(
                zone,
                true,
                &|z| z.ports.contains(port),
                format!("port {port} is already open in runtime and permanent"),
            )?,
            Self::RemovePort { zone, port, .. } => membership(
                zone,
                false,
                &|z| z.ports.contains(port),
                format!("port {port} is not open in zone `{zone}`"),
            )?,
            Self::SetDefaultZone { zone } => {
                zone_exists(zone)?;
                if *zone == snapshot.default_zone {
                    return Err(OperationError::NothingToDo(format!(
                        "`{zone}` is already the default zone"
                    )));
                }
            }
            Self::SetMasquerade { zone, enabled, .. } => {
                zone_exists_for(zone)?;
                let (runtime, permanent) = presence(zone, &|z| z.masquerade);
                let already_set = match target {
                    ConfigurationTarget::Runtime => runtime == *enabled,
                    ConfigurationTarget::Permanent => permanent == *enabled,
                    ConfigurationTarget::RuntimeAndPermanent => {
                        runtime == *enabled && permanent == *enabled
                    }
                };
                if already_set {
                    return Err(OperationError::NothingToDo(format!(
                        "masquerade is already {} in zone `{zone}`",
                        if *enabled { "enabled" } else { "disabled" }
                    )));
                }
            }
            Self::SetForward { zone, enabled, .. } => {
                zone_exists_for(zone)?;
                let (runtime, permanent) = presence(zone, &|z| z.forward);
                let already_set = match target {
                    ConfigurationTarget::Runtime => runtime == *enabled,
                    ConfigurationTarget::Permanent => permanent == *enabled,
                    ConfigurationTarget::RuntimeAndPermanent => {
                        runtime == *enabled && permanent == *enabled
                    }
                };
                if already_set {
                    return Err(OperationError::NothingToDo(format!(
                        "intra-zone forwarding is already {} in zone `{zone}`",
                        if *enabled { "enabled" } else { "disabled" }
                    )));
                }
            }
            Self::SetIcmpBlockInversion { zone, enabled, .. } => {
                zone_exists_for(zone)?;
                let (runtime, permanent) = presence(zone, &|z| z.icmp_block_inversion);
                let already_set = match target {
                    ConfigurationTarget::Runtime => runtime == *enabled,
                    ConfigurationTarget::Permanent => permanent == *enabled,
                    ConfigurationTarget::RuntimeAndPermanent => {
                        runtime == *enabled && permanent == *enabled
                    }
                };
                if already_set {
                    return Err(OperationError::NothingToDo(format!(
                        "icmp-block inversion is already {} in zone `{zone}`",
                        if *enabled { "on" } else { "off" }
                    )));
                }
            }
            Self::SetZoneTarget { zone, zone_target } => {
                if !snapshot.permanent.contains_key(zone) {
                    return Err(OperationError::Invalid(format!(
                        "zone `{zone}` does not exist in permanent configuration"
                    )));
                }
                if snapshot
                    .permanent
                    .get(zone)
                    .is_some_and(|z| z.target == *zone_target)
                {
                    return Err(OperationError::NothingToDo(format!(
                        "zone `{zone}` already targets {}",
                        zone_target.as_str()
                    )));
                }
            }
            Self::AddSourcePort { zone, port, .. } => membership(
                zone,
                true,
                &|z| z.source_ports.contains(port),
                format!("source-port {port} is already set in runtime and permanent"),
            )?,
            Self::RemoveSourcePort { zone, port, .. } => membership(
                zone,
                false,
                &|z| z.source_ports.contains(port),
                format!("source-port {port} is not set in zone `{zone}`"),
            )?,
            Self::AddProtocol { zone, protocol, .. } => membership(
                zone,
                true,
                &|z| z.protocols.contains(protocol),
                format!("protocol `{protocol}` is already allowed in runtime and permanent"),
            )?,
            Self::RemoveProtocol { zone, protocol, .. } => membership(
                zone,
                false,
                &|z| z.protocols.contains(protocol),
                format!("protocol `{protocol}` is not allowed in zone `{zone}`"),
            )?,
            Self::AddForwardPort { zone, forward, .. } => membership(
                zone,
                true,
                &|z| z.forward_ports.contains(forward),
                "this forward port already exists in runtime and permanent".to_owned(),
            )?,
            Self::RemoveForwardPort { zone, forward, .. } => membership(
                zone,
                false,
                &|z| z.forward_ports.contains(forward),
                format!(
                    "forward {} does not exist in zone `{zone}`",
                    forward.spec_string()
                ),
            )?,
            Self::AddRichRule { zone, rule, .. } => membership(
                zone,
                true,
                &|z| z.rich_rules.contains(rule),
                "this rich rule already exists in runtime and permanent".to_owned(),
            )?,
            Self::RemoveRichRule { zone, rule, .. } => membership(
                zone,
                false,
                &|z| z.rich_rules.contains(rule),
                format!("this rich rule does not exist in zone `{zone}`"),
            )?,
            Self::AddInterface {
                zone, interface, ..
            } => membership(
                zone,
                true,
                &|z| z.interfaces.contains(interface),
                format!("interface `{interface}` is already bound to zone `{zone}`"),
            )?,
            Self::RemoveInterface {
                zone, interface, ..
            } => membership(
                zone,
                false,
                &|z| z.interfaces.contains(interface),
                format!("interface `{interface}` is not bound to zone `{zone}`"),
            )?,
            Self::AddSource { zone, source, .. } => membership(
                zone,
                true,
                &|z| z.sources.contains(source),
                format!("source {source} is already bound to zone `{zone}`"),
            )?,
            Self::RemoveSource { zone, source, .. } => membership(
                zone,
                false,
                &|z| z.sources.contains(source),
                format!("source {source} is not bound to zone `{zone}`"),
            )?,
            Self::CreateService { service } => {
                if snapshot.available_services.contains(service) {
                    return Err(OperationError::Invalid(format!(
                        "service `{service}` already exists"
                    )));
                }
            }
            Self::CreatePolicy { policy } => {
                if snapshot.policies.permanent.contains_key(policy) {
                    return Err(OperationError::Invalid(format!(
                        "policy `{policy}` already exists"
                    )));
                }
            }
            Self::DeletePolicy { policy } => {
                if !snapshot.policies.permanent.contains_key(policy) {
                    return Err(OperationError::NothingToDo(format!(
                        "policy `{policy}` does not exist in permanent configuration"
                    )));
                }
            }
            Self::SetPolicyTarget {
                policy,
                policy_target,
            } => match snapshot.policies.permanent.get(policy) {
                None => {
                    return Err(OperationError::Invalid(format!(
                        "policy `{policy}` does not exist in permanent configuration"
                    )));
                }
                Some(details) if details.target == *policy_target => {
                    return Err(OperationError::NothingToDo(format!(
                        "policy `{policy}` already targets {}",
                        policy_target.as_str()
                    )));
                }
                Some(_) => {}
            },
            Self::AddPolicyIngressZone { policy, zone } => {
                let Some(details) = snapshot.policies.permanent.get(policy) else {
                    return Err(OperationError::Invalid(format!(
                        "policy `{policy}` does not exist in permanent configuration"
                    )));
                };
                if details.ingress_zones.contains(zone) {
                    return Err(OperationError::NothingToDo(format!(
                        "zone `{zone}` is already an ingress zone for policy `{policy}`"
                    )));
                }
            }
            Self::AddPolicyEgressZone { policy, zone } => {
                let Some(details) = snapshot.policies.permanent.get(policy) else {
                    return Err(OperationError::Invalid(format!(
                        "policy `{policy}` does not exist in permanent configuration"
                    )));
                };
                if details.egress_zones.contains(zone) {
                    return Err(OperationError::NothingToDo(format!(
                        "zone `{zone}` is already an egress zone for policy `{policy}`"
                    )));
                }
            }
            Self::AddPolicyService {
                policy, service, ..
            } => {
                let runtime = snapshot.policies.runtime.get(policy);
                let permanent = snapshot.policies.permanent.get(policy);
                let exists = match target {
                    ConfigurationTarget::Runtime => runtime.is_some(),
                    ConfigurationTarget::Permanent => permanent.is_some(),
                    ConfigurationTarget::RuntimeAndPermanent => {
                        runtime.is_some() && permanent.is_some()
                    }
                };
                if !exists {
                    return Err(OperationError::Invalid(format!(
                        "policy `{policy}` does not exist in {} configuration",
                        target.label()
                    )));
                }
                let already_set = match target {
                    ConfigurationTarget::Runtime => {
                        runtime.is_some_and(|p| p.services.contains(service))
                    }
                    ConfigurationTarget::Permanent => {
                        permanent.is_some_and(|p| p.services.contains(service))
                    }
                    ConfigurationTarget::RuntimeAndPermanent => {
                        runtime.is_some_and(|p| p.services.contains(service))
                            && permanent.is_some_and(|p| p.services.contains(service))
                    }
                };
                if already_set {
                    return Err(OperationError::NothingToDo(format!(
                        "service `{service}` is already in policy `{policy}`"
                    )));
                }
            }
            Self::RemovePolicyService {
                policy, service, ..
            } => {
                let runtime = snapshot.policies.runtime.get(policy);
                let permanent = snapshot.policies.permanent.get(policy);
                let exists = match target {
                    ConfigurationTarget::Runtime => runtime.is_some(),
                    ConfigurationTarget::Permanent => permanent.is_some(),
                    ConfigurationTarget::RuntimeAndPermanent => {
                        runtime.is_some() && permanent.is_some()
                    }
                };
                if !exists {
                    return Err(OperationError::Invalid(format!(
                        "policy `{policy}` does not exist in {} configuration",
                        target.label()
                    )));
                }
                let already_absent = match target {
                    ConfigurationTarget::Runtime => {
                        runtime.is_some_and(|p| !p.services.contains(service))
                    }
                    ConfigurationTarget::Permanent => {
                        permanent.is_some_and(|p| !p.services.contains(service))
                    }
                    ConfigurationTarget::RuntimeAndPermanent => {
                        runtime.is_some_and(|p| !p.services.contains(service))
                            && permanent.is_some_and(|p| !p.services.contains(service))
                    }
                };
                if already_absent {
                    return Err(OperationError::NothingToDo(format!(
                        "service `{service}` is not in policy `{policy}`"
                    )));
                }
            }

            Self::CreateIpSet { name, kind } => {
                if !IPSET_TYPES.contains(&kind.as_str()) {
                    return Err(OperationError::Invalid(format!(
                        "unknown ipset type `{kind}` (e.g. hash:ip, hash:net)"
                    )));
                }
                if snapshot.ipsets.permanent.contains_key(name) {
                    return Err(OperationError::Invalid(format!(
                        "ipset `{name}` already exists"
                    )));
                }
            }
            Self::DeleteIpSet { name } => {
                if !snapshot.ipsets.permanent.contains_key(name) {
                    return Err(OperationError::NothingToDo(format!(
                        "ipset `{name}` does not exist in permanent configuration"
                    )));
                }
            }
            Self::AddIpSetEntry { name, entry, .. } => {
                let runtime = snapshot.ipsets.runtime.get(name);
                let permanent = snapshot.ipsets.permanent.get(name);
                let exists = match target {
                    ConfigurationTarget::Runtime => runtime.is_some(),
                    ConfigurationTarget::Permanent => permanent.is_some(),
                    ConfigurationTarget::RuntimeAndPermanent => {
                        runtime.is_some() && permanent.is_some()
                    }
                };
                if !exists {
                    return Err(OperationError::Invalid(format!(
                        "ipset `{name}` does not exist in {} configuration",
                        target.label()
                    )));
                }
                let entry = entry.to_string();
                let already_set = match target {
                    ConfigurationTarget::Runtime => {
                        runtime.is_some_and(|info| info.entries.contains(&entry))
                    }
                    ConfigurationTarget::Permanent => {
                        permanent.is_some_and(|info| info.entries.contains(&entry))
                    }
                    ConfigurationTarget::RuntimeAndPermanent => {
                        runtime.is_some_and(|info| info.entries.contains(&entry))
                            && permanent.is_some_and(|info| info.entries.contains(&entry))
                    }
                };
                if already_set {
                    return Err(OperationError::NothingToDo(format!(
                        "{entry} is already in ipset `{name}`"
                    )));
                }
            }
            Self::RemoveIpSetEntry { name, entry, .. } => {
                let runtime = snapshot.ipsets.runtime.get(name);
                let permanent = snapshot.ipsets.permanent.get(name);
                let exists = match target {
                    ConfigurationTarget::Runtime => runtime.is_some(),
                    ConfigurationTarget::Permanent => permanent.is_some(),
                    ConfigurationTarget::RuntimeAndPermanent => {
                        runtime.is_some() && permanent.is_some()
                    }
                };
                if !exists {
                    return Err(OperationError::Invalid(format!(
                        "ipset `{name}` does not exist in {} configuration",
                        target.label()
                    )));
                }
                let entry = entry.to_string();
                let already_absent = match target {
                    ConfigurationTarget::Runtime => {
                        runtime.is_some_and(|info| !info.entries.contains(&entry))
                    }
                    ConfigurationTarget::Permanent => {
                        permanent.is_some_and(|info| !info.entries.contains(&entry))
                    }
                    ConfigurationTarget::RuntimeAndPermanent => {
                        runtime.is_some_and(|info| !info.entries.contains(&entry))
                            && permanent.is_some_and(|info| !info.entries.contains(&entry))
                    }
                };
                if already_absent {
                    return Err(OperationError::NothingToDo(format!(
                        "{entry} is not in ipset `{name}`"
                    )));
                }
            }
            Self::CreateZone { zone } => {
                if snapshot.runtime.contains_key(zone) || snapshot.permanent.contains_key(zone) {
                    return Err(OperationError::Invalid(format!(
                        "zone `{zone}` already exists"
                    )));
                }
            }
            Self::DeleteZone { zone } => {
                if !snapshot.permanent.contains_key(zone) {
                    return Err(OperationError::Invalid(format!(
                        "zone `{zone}` does not exist in permanent configuration"
                    )));
                }
                if *zone == snapshot.default_zone {
                    return Err(OperationError::Invalid(format!(
                        "`{zone}` is the default zone — set another default first"
                    )));
                }
            }
            Self::AddIcmpBlock { zone, icmp, .. } => membership(
                zone,
                true,
                &|z| z.icmp_blocks.contains(icmp),
                format!("ICMP `{icmp}` is already blocked in zone `{zone}`"),
            )?,
            Self::RemoveIcmpBlock { zone, icmp, .. } => membership(
                zone,
                false,
                &|z| z.icmp_blocks.contains(icmp),
                format!("ICMP `{icmp}` is not blocked in zone `{zone}`"),
            )?,
            Self::SetPanicMode { enabled } => {
                if snapshot.status.panic_mode == *enabled {
                    return Err(OperationError::NothingToDo(format!(
                        "panic mode is already {}",
                        if *enabled { "on" } else { "off" }
                    )));
                }
            }
            Self::RuntimeToPermanent => {
                if snapshot.all_synced() {
                    return Err(OperationError::NothingToDo(
                        "runtime and permanent are already in sync".to_owned(),
                    ));
                }
            }
            Self::SetLogDenied { value } => {
                if snapshot.status.log_denied == *value {
                    return Err(OperationError::NothingToDo(format!(
                        "LogDenied is already `{}`",
                        value.as_str()
                    )));
                }
            }
            // Service definition details are fetched only for referenced
            // services, so firewalld gives the final word for service internals.
            Self::DeleteService { .. }
            | Self::AddServicePort { .. }
            | Self::RemoveServicePort { .. }
            | Self::Reload => {}
        }
        Ok(())
    }

    /// The runtime-scoped inverse, used as rollback metadata when the runtime
    /// step succeeded but the permanent step failed (ADR-3).
    #[must_use]
    pub fn inverse_runtime(&self) -> Option<Self> {
        self.inverse_op(ConfigurationTarget::Runtime)
    }

    /// The same-target inverse, used by the timed-rollback dead-man's switch
    /// to undo a fully applied operation.
    #[must_use]
    pub fn inverse(&self) -> Option<Self> {
        self.inverse_op(self.target())
    }

    /// Shared body of [`Self::inverse`] and [`Self::inverse_runtime`]: the
    /// opposite operation with the given target scope, or `None` for
    /// operations without a clean inverse (lifecycle, reload, default zone).
    #[allow(clippy::too_many_lines)] // one arm per operation
    fn inverse_op(&self, runtime: ConfigurationTarget) -> Option<Self> {
        match self {
            Self::AddTemporaryService { zone, service, .. } => Some(Self::RemoveService {
                zone: zone.clone(),
                service: service.clone(),
                target: ConfigurationTarget::Runtime,
            }),
            Self::AddService { zone, service, .. } => Some(Self::RemoveService {
                zone: zone.clone(),
                service: service.clone(),
                target: runtime,
            }),
            Self::RemoveService { zone, service, .. } => Some(Self::AddService {
                zone: zone.clone(),
                service: service.clone(),
                target: runtime,
            }),
            Self::AddPort { zone, port, .. } => Some(Self::RemovePort {
                zone: zone.clone(),
                port: *port,
                target: runtime,
            }),
            Self::RemovePort { zone, port, .. } => Some(Self::AddPort {
                zone: zone.clone(),
                port: *port,
                target: runtime,
            }),
            Self::SetMasquerade { zone, enabled, .. } => Some(Self::SetMasquerade {
                zone: zone.clone(),
                enabled: !enabled,
                target: runtime,
            }),
            Self::SetForward { zone, enabled, .. } => Some(Self::SetForward {
                zone: zone.clone(),
                enabled: !enabled,
                target: runtime,
            }),
            Self::SetIcmpBlockInversion { zone, enabled, .. } => {
                Some(Self::SetIcmpBlockInversion {
                    zone: zone.clone(),
                    enabled: !enabled,
                    target: runtime,
                })
            }
            Self::AddSourcePort { zone, port, .. } => Some(Self::RemoveSourcePort {
                zone: zone.clone(),
                port: *port,
                target: runtime,
            }),
            Self::RemoveSourcePort { zone, port, .. } => Some(Self::AddSourcePort {
                zone: zone.clone(),
                port: *port,
                target: runtime,
            }),
            Self::AddProtocol { zone, protocol, .. } => Some(Self::RemoveProtocol {
                zone: zone.clone(),
                protocol: protocol.clone(),
                target: runtime,
            }),
            Self::RemoveProtocol { zone, protocol, .. } => Some(Self::AddProtocol {
                zone: zone.clone(),
                protocol: protocol.clone(),
                target: runtime,
            }),
            Self::AddForwardPort { zone, forward, .. } => Some(Self::RemoveForwardPort {
                zone: zone.clone(),
                forward: forward.clone(),
                target: runtime,
            }),
            Self::RemoveForwardPort { zone, forward, .. } => Some(Self::AddForwardPort {
                zone: zone.clone(),
                forward: forward.clone(),
                target: runtime,
            }),
            Self::AddRichRule { zone, rule, .. } => Some(Self::RemoveRichRule {
                zone: zone.clone(),
                rule: rule.clone(),
                target: runtime,
            }),
            Self::RemoveRichRule { zone, rule, .. } => Some(Self::AddRichRule {
                zone: zone.clone(),
                rule: rule.clone(),
                target: runtime,
            }),
            Self::AddInterface {
                zone, interface, ..
            } => Some(Self::RemoveInterface {
                zone: zone.clone(),
                interface: interface.clone(),
                target: runtime,
            }),
            Self::RemoveInterface {
                zone, interface, ..
            } => Some(Self::AddInterface {
                zone: zone.clone(),
                interface: interface.clone(),
                target: runtime,
            }),
            Self::AddSource { zone, source, .. } => Some(Self::RemoveSource {
                zone: zone.clone(),
                source: source.clone(),
                target: runtime,
            }),
            Self::RemoveSource { zone, source, .. } => Some(Self::AddSource {
                zone: zone.clone(),
                source: source.clone(),
                target: runtime,
            }),
            Self::AddIcmpBlock { zone, icmp, .. } => Some(Self::RemoveIcmpBlock {
                zone: zone.clone(),
                icmp: icmp.clone(),
                target: runtime,
            }),
            Self::RemoveIcmpBlock { zone, icmp, .. } => Some(Self::AddIcmpBlock {
                zone: zone.clone(),
                icmp: icmp.clone(),
                target: runtime,
            }),
            Self::SetPanicMode { enabled } => Some(Self::SetPanicMode { enabled: !enabled }),
            Self::AddIpSetEntry { name, entry, .. } => Some(Self::RemoveIpSetEntry {
                name: name.clone(),
                entry: entry.clone(),
                target: runtime,
            }),
            Self::RemoveIpSetEntry { name, entry, .. } => Some(Self::AddIpSetEntry {
                name: name.clone(),
                entry: entry.clone(),
                target: runtime,
            }),
            Self::AddServicePort { service, port } => Some(Self::RemoveServicePort {
                service: service.clone(),
                port: *port,
            }),
            Self::AddPolicyService {
                policy, service, ..
            } => Some(Self::RemovePolicyService {
                policy: policy.clone(),
                service: service.clone(),
                target: runtime,
            }),
            Self::RemovePolicyService {
                policy, service, ..
            } => Some(Self::AddPolicyService {
                policy: policy.clone(),
                service: service.clone(),
                target: runtime,
            }),
            Self::RemoveServicePort { service, port } => Some(Self::AddServicePort {
                service: service.clone(),
                port: *port,
            }),
            // SetZoneTarget has no clean inverse — we don't record the previous
            // target, so the operator restores it explicitly if needed.
            Self::SetZoneTarget { .. }
            | Self::SetDefaultZone { .. }
            | Self::CreateZone { .. }
            | Self::DeleteZone { .. }
            | Self::CreateService { .. }
            | Self::DeleteService { .. }
            | Self::CreatePolicy { .. }
            | Self::DeletePolicy { .. }
            | Self::SetPolicyTarget { .. }
            | Self::AddPolicyIngressZone { .. }
            | Self::AddPolicyEgressZone { .. }
            | Self::CreateIpSet { .. }
            | Self::DeleteIpSet { .. }
            | Self::RuntimeToPermanent
            | Self::SetLogDenied { .. }
            | Self::Reload => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::super::mock;
    use super::*;

    fn zone(name: &str) -> ZoneName {
        ZoneName::parse(name).unwrap()
    }

    fn service(name: &str) -> ServiceName {
        ServiceName::parse(name).unwrap()
    }

    #[test]
    fn add_existing_service_is_nothing_to_do() {
        let snapshot = mock::sample().unwrap();
        // `https` is in runtime AND permanent in the mock.
        let op = FirewallOperation::AddService {
            zone: zone("public"),
            service: service("https"),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        assert!(matches!(
            op.validate(&snapshot),
            Err(OperationError::NothingToDo(_))
        ));
        // `http` is runtime-only, so adding it (to sync permanent) is fine.
        let op = FirewallOperation::AddService {
            zone: zone("public"),
            service: service("http"),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        assert!(op.validate(&snapshot).is_ok());
    }

    #[test]
    fn remove_absent_service_is_nothing_to_do() {
        let snapshot = mock::sample().unwrap();
        let op = FirewallOperation::RemoveService {
            zone: zone("public"),
            service: service("telnet"),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        assert!(matches!(
            op.validate(&snapshot),
            Err(OperationError::NothingToDo(_))
        ));
    }

    #[test]
    fn unknown_zone_is_rejected() {
        let snapshot = mock::sample().unwrap();
        let op = FirewallOperation::SetDefaultZone { zone: zone("nope") };
        assert!(matches!(
            op.validate(&snapshot),
            Err(OperationError::UnknownZone(_))
        ));
    }

    #[test]
    fn current_default_zone_is_nothing_to_do() {
        let snapshot = mock::sample().unwrap();
        let op = FirewallOperation::SetDefaultZone {
            zone: zone("public"),
        };
        assert!(matches!(
            op.validate(&snapshot),
            Err(OperationError::NothingToDo(_))
        ));
        let op = FirewallOperation::SetDefaultZone { zone: zone("home") };
        assert!(op.validate(&snapshot).is_ok());
    }

    #[test]
    fn same_target_inverse_preserves_the_target() {
        let op = FirewallOperation::RemoveService {
            zone: zone("public"),
            service: service("http"),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        match op.inverse().unwrap() {
            FirewallOperation::AddService { target, .. } => {
                assert_eq!(target, ConfigurationTarget::RuntimeAndPermanent);
            }
            other => panic!("unexpected inverse: {other:?}"),
        }
    }

    #[test]
    fn inverse_maps_add_to_remove_runtime_scoped() {
        let op = FirewallOperation::AddService {
            zone: zone("public"),
            service: service("http"),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        match op.inverse_runtime().unwrap() {
            FirewallOperation::RemoveService { target, .. } => {
                assert_eq!(target, ConfigurationTarget::Runtime);
            }
            other => panic!("unexpected inverse: {other:?}"),
        }
        assert!(FirewallOperation::Reload.inverse_runtime().is_none());
    }

    #[test]
    fn parity_operations_invert_and_target_correctly() {
        use crate::domain::{IpProtocol, ZoneTarget};
        let z = zone("public");

        // Toggles invert to their opposite, runtime-scoped.
        match (FirewallOperation::SetForward {
            zone: z.clone(),
            enabled: true,
            target: ConfigurationTarget::RuntimeAndPermanent,
        })
        .inverse()
        .unwrap()
        {
            FirewallOperation::SetForward { enabled, .. } => assert!(!enabled),
            other => panic!("unexpected inverse: {other:?}"),
        }

        // Source-port add ↔ remove.
        match (FirewallOperation::AddSourcePort {
            zone: z.clone(),
            port: "68/udp".parse().unwrap(),
            target: ConfigurationTarget::Runtime,
        })
        .inverse()
        .unwrap()
        {
            FirewallOperation::RemoveSourcePort { .. } => {}
            other => panic!("unexpected inverse: {other:?}"),
        }

        // Protocol add ↔ remove.
        assert!(matches!(
            (FirewallOperation::AddProtocol {
                zone: z.clone(),
                protocol: IpProtocol::parse("gre").unwrap(),
                target: ConfigurationTarget::Runtime,
            })
            .inverse(),
            Some(FirewallOperation::RemoveProtocol { .. })
        ));

        // Zone target is permanent-only and has no clean inverse.
        let set_target = FirewallOperation::SetZoneTarget {
            zone: z,
            zone_target: ZoneTarget::Drop,
        };
        assert_eq!(set_target.target(), ConfigurationTarget::Permanent);
        assert!(set_target.inverse().is_none());
    }

    #[test]
    fn rezoning_ops_warn_and_are_reversible() {
        // Regression guard: re-zoning is the classic self-lockout vector, so all
        // three ops must carry a connectivity warning — that is what makes the
        // SSH notice fire AND arms the dead-man's switch (both key off it).
        let z = zone("public");
        let iface = FirewallOperation::AddInterface {
            zone: z.clone(),
            interface: InterfaceName::parse("eth0").unwrap(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        let src = FirewallOperation::AddSource {
            zone: z.clone(),
            source: SourceAddress::parse("203.0.113.0/24").unwrap(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        let def = FirewallOperation::SetDefaultZone { zone: z };

        for op in [&iface, &src, &def] {
            assert!(
                op.connectivity_warning().is_some(),
                "missing connectivity warning for {op:?}"
            );
        }
        // AddInterface / AddSource have clean inverses, so rollback can revert
        // them; SetDefaultZone captures no prior default, so it warns but (like
        // Reload) cannot auto-revert.
        assert!(matches!(
            iface.inverse(),
            Some(FirewallOperation::RemoveInterface { .. })
        ));
        assert!(matches!(
            src.inverse(),
            Some(FirewallOperation::RemoveSource { .. })
        ));
        assert!(def.inverse().is_none());
    }

    #[test]
    fn panic_and_sync_validations_check_current_state() {
        let snapshot = mock::sample().unwrap();
        // panic is off in the mock
        assert!(matches!(
            FirewallOperation::SetPanicMode { enabled: false }.validate(&snapshot),
            Err(OperationError::NothingToDo(_))
        ));
        assert!(
            FirewallOperation::SetPanicMode { enabled: true }
                .validate(&snapshot)
                .is_ok()
        );
        // mock has drift → runtime-to-permanent makes sense
        assert!(
            FirewallOperation::RuntimeToPermanent
                .validate(&snapshot)
                .is_ok()
        );
        // LogDenied is off in the mock
        assert!(matches!(
            FirewallOperation::SetLogDenied {
                value: crate::domain::LogDenied::Off
            }
            .validate(&snapshot),
            Err(OperationError::NothingToDo(_))
        ));
    }

    #[test]
    fn ipset_validations() {
        use crate::domain::{IpSetEntry, IpSetName};
        let snapshot = mock::sample().unwrap();
        let blocklist = IpSetName::parse("blocklist").unwrap();
        // unknown type rejected before it can reach argv
        assert!(matches!(
            FirewallOperation::CreateIpSet {
                name: IpSetName::parse("x").unwrap(),
                kind: "hash:$(bad)".to_owned(),
            }
            .validate(&snapshot),
            Err(OperationError::Invalid(_))
        ));
        // duplicate entry is nothing-to-do
        assert!(matches!(
            FirewallOperation::AddIpSetEntry {
                name: blocklist.clone(),
                entry: IpSetEntry::parse("203.0.113.9").unwrap(),
                target: ConfigurationTarget::RuntimeAndPermanent,
            }
            .validate(&snapshot),
            Err(OperationError::NothingToDo(_))
        ));
        assert!(
            FirewallOperation::AddIpSetEntry {
                name: blocklist,
                entry: IpSetEntry::parse("198.51.100.44").unwrap(),
                target: ConfigurationTarget::RuntimeAndPermanent,
            }
            .validate(&snapshot)
            .is_ok()
        );
    }

    #[test]
    fn policy_validations_and_inverse() {
        use crate::domain::PolicyName;
        let snapshot = mock::sample().unwrap();
        let policy = PolicyName::parse("mypolicy").unwrap();
        // exists in the mock
        assert!(matches!(
            FirewallOperation::CreatePolicy {
                policy: policy.clone()
            }
            .validate(&snapshot),
            Err(OperationError::Invalid(_))
        ));
        // http already in the policy
        assert!(matches!(
            FirewallOperation::AddPolicyService {
                policy: policy.clone(),
                service: service("http"),
                target: ConfigurationTarget::RuntimeAndPermanent,
            }
            .validate(&snapshot),
            Err(OperationError::NothingToDo(_))
        ));
        // adding a new service is fine and has a runtime-scoped inverse
        let add = FirewallOperation::AddPolicyService {
            policy,
            service: service("https"),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        assert!(add.validate(&snapshot).is_ok());
        assert!(matches!(
            add.inverse().unwrap(),
            FirewallOperation::RemovePolicyService { .. }
        ));
    }

    #[test]
    fn service_lifecycle_validations_and_inverse() {
        let snapshot = mock::sample().unwrap();
        // ssh already exists in the mock catalog
        assert!(matches!(
            FirewallOperation::CreateService {
                service: service("ssh")
            }
            .validate(&snapshot),
            Err(OperationError::Invalid(_))
        ));
        assert!(
            FirewallOperation::CreateService {
                service: service("myapp")
            }
            .validate(&snapshot)
            .is_ok()
        );
        // add-port has a same-target permanent inverse
        let add = FirewallOperation::AddServicePort {
            service: service("myapp"),
            port: "9200/tcp".parse().unwrap(),
        };
        match add.inverse().unwrap() {
            FirewallOperation::RemoveServicePort { port, .. } => {
                assert_eq!(port.to_string(), "9200/tcp");
            }
            other => panic!("unexpected inverse: {other:?}"),
        }
    }

    #[test]
    fn zone_lifecycle_validations() {
        let snapshot = mock::sample().unwrap();
        // create: name must be new
        assert!(matches!(
            FirewallOperation::CreateZone {
                zone: zone("public")
            }
            .validate(&snapshot),
            Err(OperationError::Invalid(_))
        ));
        assert!(
            FirewallOperation::CreateZone {
                zone: zone("staging")
            }
            .validate(&snapshot)
            .is_ok()
        );
        // delete: default zone is protected
        assert!(matches!(
            FirewallOperation::DeleteZone {
                zone: zone("public")
            }
            .validate(&snapshot),
            Err(OperationError::Invalid(_))
        ));
        assert!(
            FirewallOperation::DeleteZone { zone: zone("home") }
                .validate(&snapshot)
                .is_ok()
        );
    }

    #[test]
    fn narrowing_repairs_drift_scope() {
        let snapshot = mock::sample().unwrap();
        // `http` is runtime-only in the mock: adding with Both must narrow to
        // Permanent (the missing half), removing must narrow to Runtime.
        let add = FirewallOperation::AddService {
            zone: zone("public"),
            service: service("http"),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        assert_eq!(
            add.narrowed_for(&snapshot).target(),
            ConfigurationTarget::Permanent
        );
        let remove = FirewallOperation::RemoveService {
            zone: zone("public"),
            service: service("http"),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        assert_eq!(
            remove.narrowed_for(&snapshot).target(),
            ConfigurationTarget::Runtime
        );
        // `https` exists in both: removing keeps Both; explicit single-scope
        // targets are never rewritten.
        let remove_both = FirewallOperation::RemoveService {
            zone: zone("public"),
            service: service("https"),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        assert_eq!(
            remove_both.narrowed_for(&snapshot).target(),
            ConfigurationTarget::RuntimeAndPermanent
        );
        let explicit = FirewallOperation::AddService {
            zone: zone("public"),
            service: service("http"),
            target: ConfigurationTarget::Runtime,
        };
        assert_eq!(
            explicit.narrowed_for(&snapshot).target(),
            ConfigurationTarget::Runtime
        );
    }

    #[test]
    fn validation_honors_an_explicit_zone_target() {
        let snapshot = mock::sample().unwrap();
        // `http` is runtime-only in the mock. Runtime is already satisfied,
        // while permanent is a valid drift-repair target.
        let runtime = FirewallOperation::AddService {
            zone: zone("public"),
            service: service("http"),
            target: ConfigurationTarget::Runtime,
        };
        assert!(matches!(
            runtime.validate(&snapshot),
            Err(OperationError::NothingToDo(_))
        ));
        let permanent = runtime.with_target(ConfigurationTarget::Permanent).unwrap();
        assert!(permanent.validate(&snapshot).is_ok());
    }

    #[test]
    fn ipset_validation_narrowing_and_postconditions_are_scoped() {
        let mut snapshot = mock::sample().unwrap();
        let name = IpSetName::parse("blocklist").unwrap();
        let entry = IpSetEntry::parse("203.0.113.9").unwrap();
        snapshot
            .ipsets
            .permanent
            .get_mut(&name)
            .unwrap()
            .entries
            .clear();
        assert!(!snapshot.all_synced(), "ipset drift is configuration drift");

        let add = FirewallOperation::AddIpSetEntry {
            name,
            entry,
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        assert_eq!(
            add.narrowed_for(&snapshot).target(),
            ConfigurationTarget::Permanent
        );
        assert_eq!(add.postcondition_holds(&snapshot), Some(false));
        assert!(matches!(
            add.with_target(ConfigurationTarget::Runtime)
                .unwrap()
                .validate(&snapshot),
            Err(OperationError::NothingToDo(_))
        ));
        assert!(
            add.with_target(ConfigurationTarget::Permanent)
                .unwrap()
                .validate(&snapshot)
                .is_ok()
        );
    }

    #[test]
    fn incomplete_scope_blocks_only_dependent_mutations() {
        let mut snapshot = mock::sample().unwrap();
        snapshot
            .degraded
            .push(super::super::snapshot::DegradedSection::new(
                SnapshotSection::IpSets,
                Some(ConfigurationTarget::Permanent),
                "permission denied",
            ));
        let name = IpSetName::parse("blocklist").unwrap();
        let entry = IpSetEntry::parse("198.51.100.2").unwrap();
        let permanent = FirewallOperation::AddIpSetEntry {
            name: name.clone(),
            entry: entry.clone(),
            target: ConfigurationTarget::Permanent,
        };
        assert!(matches!(
            permanent.validate(&snapshot),
            Err(OperationError::Invalid(_))
        ));
        let both = permanent
            .with_target(ConfigurationTarget::RuntimeAndPermanent)
            .unwrap();
        assert_eq!(
            both.narrowed_for(&snapshot).target(),
            ConfigurationTarget::RuntimeAndPermanent,
            "unknown permanent state must never be narrowed away"
        );
        let runtime = FirewallOperation::AddIpSetEntry {
            name,
            entry,
            target: ConfigurationTarget::Runtime,
        };
        assert!(runtime.validate(&snapshot).is_ok());
        assert_eq!(permanent.postcondition_holds(&snapshot), None);
    }

    #[test]
    fn descriptions_are_specific() {
        let op = FirewallOperation::AddService {
            zone: zone("public"),
            service: service("https"),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        assert_eq!(op.describe(), "add service `https` to zone `public`");
        assert_eq!(
            op.success_message(),
            "service `https` added to zone `public` (runtime + permanent)"
        );
        assert!(FirewallOperation::Reload.connectivity_warning().is_some());
    }
}
