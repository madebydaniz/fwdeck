//! Computes the operations that transform the current firewall state into a
//! saved snapshot. The result is a *staged plan* the operator reviews and
//! applies deliberately — restore never runs automatically.
//!
//! Runtime and permanent are diffed **independently**: runtime differences
//! produce runtime-scoped operations and permanent differences produce
//! permanent-scoped ones, so a runtime-only rule is restored without touching
//! the permanent config and vice versa.
//!
//! Scope: per-zone attributes (services, ports, source-ports, protocols,
//! forward ports, rich rules, sources, icmp blocks, masquerade, intra-zone
//! forwarding, icmp-block inversion, and the permanent zone target) plus the
//! default zone. Zone/ipset/policy
//! lifecycle and interface bindings are intentionally not synthesized —
//! moving interfaces or deleting zones during a restore is far riskier than
//! the operator re-checking those by hand.

use super::operation::FirewallOperation;
use super::snapshot::{ConfigurationTarget, FirewallSnapshot};
use super::zone::ZoneDetails;

/// Operations to make `current` match `target`. Empty when already equal.
#[must_use]
pub fn plan(current: &FirewallSnapshot, target: &FirewallSnapshot) -> Vec<FirewallOperation> {
    let mut ops = Vec::new();

    // Default zone first: later per-zone edits read more naturally under it.
    // Runtime presence is required — `--set-default-zone` on a permanent-only
    // zone fails with INVALID_ZONE until a reload.
    if current.default_zone != target.default_zone
        && current.runtime.contains_key(&target.default_zone)
    {
        ops.push(FirewallOperation::SetDefaultZone {
            zone: target.default_zone.clone(),
        });
    }

    // Runtime and permanent are restored independently. Only zones that exist
    // in the current config of the same scope are touched — we don't create or
    // delete zones during a restore (see the module note).
    for (zone, target_zone) in &target.runtime {
        if let Some(current_zone) = current.runtime.get(zone) {
            diff_zone(
                zone,
                current_zone,
                target_zone,
                ConfigurationTarget::Runtime,
                &mut ops,
            );
        }
    }
    for (zone, target_zone) in &target.permanent {
        if let Some(current_zone) = current.permanent.get(zone) {
            diff_zone(
                zone,
                current_zone,
                target_zone,
                ConfigurationTarget::Permanent,
                &mut ops,
            );
        }
    }
    ops
}

/// Emits the add/remove/set operations that bring one zone's `current`
/// details to `target`, all scoped to the given configuration target.
#[allow(clippy::too_many_lines)] // one diff block per zone attribute
fn diff_zone(
    zone: &super::ids::ZoneName,
    current: &ZoneDetails,
    target: &ZoneDetails,
    scope: ConfigurationTarget,
    ops: &mut Vec<FirewallOperation>,
) {
    diff_pairs(
        &current.services,
        &target.services,
        |service| FirewallOperation::AddService {
            zone: zone.clone(),
            service,
            target: scope,
        },
        |service| FirewallOperation::RemoveService {
            zone: zone.clone(),
            service,
            target: scope,
        },
        ops,
    );
    diff_pairs(
        &current.ports,
        &target.ports,
        |port| FirewallOperation::AddPort {
            zone: zone.clone(),
            port,
            target: scope,
        },
        |port| FirewallOperation::RemovePort {
            zone: zone.clone(),
            port,
            target: scope,
        },
        ops,
    );
    diff_pairs(
        &current.forward_ports,
        &target.forward_ports,
        |forward| FirewallOperation::AddForwardPort {
            zone: zone.clone(),
            forward,
            target: scope,
        },
        |forward| FirewallOperation::RemoveForwardPort {
            zone: zone.clone(),
            forward,
            target: scope,
        },
        ops,
    );
    diff_pairs(
        &current.rich_rules,
        &target.rich_rules,
        |rule| FirewallOperation::AddRichRule {
            zone: zone.clone(),
            rule,
            target: scope,
        },
        |rule| FirewallOperation::RemoveRichRule {
            zone: zone.clone(),
            rule,
            target: scope,
        },
        ops,
    );
    diff_pairs(
        &current.sources,
        &target.sources,
        |source| FirewallOperation::AddSource {
            zone: zone.clone(),
            source,
            target: scope,
        },
        |source| FirewallOperation::RemoveSource {
            zone: zone.clone(),
            source,
            target: scope,
        },
        ops,
    );
    diff_pairs(
        &current.icmp_blocks,
        &target.icmp_blocks,
        |icmp| FirewallOperation::AddIcmpBlock {
            zone: zone.clone(),
            icmp,
            target: scope,
        },
        |icmp| FirewallOperation::RemoveIcmpBlock {
            zone: zone.clone(),
            icmp,
            target: scope,
        },
        ops,
    );
    diff_pairs(
        &current.source_ports,
        &target.source_ports,
        |port| FirewallOperation::AddSourcePort {
            zone: zone.clone(),
            port,
            target: scope,
        },
        |port| FirewallOperation::RemoveSourcePort {
            zone: zone.clone(),
            port,
            target: scope,
        },
        ops,
    );
    diff_pairs(
        &current.protocols,
        &target.protocols,
        |protocol| FirewallOperation::AddProtocol {
            zone: zone.clone(),
            protocol,
            target: scope,
        },
        |protocol| FirewallOperation::RemoveProtocol {
            zone: zone.clone(),
            protocol,
            target: scope,
        },
        ops,
    );
    if current.masquerade != target.masquerade {
        ops.push(FirewallOperation::SetMasquerade {
            zone: zone.clone(),
            enabled: target.masquerade,
            target: scope,
        });
    }
    if current.forward != target.forward {
        ops.push(FirewallOperation::SetForward {
            zone: zone.clone(),
            enabled: target.forward,
            target: scope,
        });
    }
    if current.icmp_block_inversion != target.icmp_block_inversion {
        ops.push(FirewallOperation::SetIcmpBlockInversion {
            zone: zone.clone(),
            enabled: target.icmp_block_inversion,
            target: scope,
        });
    }
    // Zone target is permanent-only in firewalld, so only reconcile it in the
    // permanent scope (a reload then carries it into runtime).
    if scope == ConfigurationTarget::Permanent && current.target != target.target {
        ops.push(FirewallOperation::SetZoneTarget {
            zone: zone.clone(),
            zone_target: target.target,
        });
    }
}

/// Emits add operations for items only in `target` and remove operations for
/// items only in `current` — the shared body of every per-attribute diff.
fn diff_pairs<T: Clone + PartialEq>(
    current: &[T],
    target: &[T],
    make_add: impl Fn(T) -> FirewallOperation,
    make_remove: impl Fn(T) -> FirewallOperation,
    ops: &mut Vec<FirewallOperation>,
) {
    ops.extend(added(current, target).cloned().map(make_add));
    ops.extend(added(target, current).cloned().map(make_remove));
}

/// Items present in `target` but not in `have` — i.e. what to add to reach it.
fn added<'a, T: PartialEq>(have: &[T], target: &'a [T]) -> impl Iterator<Item = &'a T> {
    target.iter().filter(move |item| !have.contains(item))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::ids::{ServiceName, ZoneName};
    use super::super::mock;
    use super::*;

    #[test]
    fn identical_snapshots_produce_no_operations() {
        let snap = mock::sample().unwrap();
        assert!(plan(&snap, &snap).is_empty());
    }

    #[test]
    fn diff_adds_and_removes_to_reach_target() {
        let current = mock::sample().unwrap();
        let mut target = current.clone();
        let public = ZoneName::parse("public").unwrap();
        // Target removes `https` (present in permanent) and adds `ftp`.
        let ftp = ServiceName::parse("ftp").unwrap();
        let z = target.permanent.get_mut(&public).unwrap();
        z.services.retain(|s| s.as_str() != "https");
        z.services.push(ftp.clone());

        // The diff drives off the permanent config.
        let ops = plan(&current, &target);
        assert!(ops.iter().any(|op| matches!(
            op,
            FirewallOperation::AddService { service, .. } if service.as_str() == "ftp"
        )));
        assert!(ops.iter().any(|op| matches!(
            op,
            FirewallOperation::RemoveService { service, .. } if service.as_str() == "https"
        )));
    }

    #[test]
    fn diff_reconciles_the_parity_attributes() {
        use super::super::ids::IpProtocol;
        use super::super::zone::ZoneTarget;
        let current = mock::sample().unwrap();
        let mut target = current.clone();
        let public = ZoneName::parse("public").unwrap();
        let z = target.permanent.get_mut(&public).unwrap();
        z.protocols.push(IpProtocol::parse("esp").unwrap());
        z.source_ports.push("546/udp".parse().unwrap());
        z.forward = !z.forward;
        z.icmp_block_inversion = !z.icmp_block_inversion;
        z.target = ZoneTarget::Drop;

        let ops = plan(&current, &target);
        assert!(
            ops.iter()
                .any(|op| matches!(op, FirewallOperation::AddProtocol { .. }))
        );
        assert!(
            ops.iter()
                .any(|op| matches!(op, FirewallOperation::AddSourcePort { .. }))
        );
        assert!(
            ops.iter()
                .any(|op| matches!(op, FirewallOperation::SetForward { .. }))
        );
        assert!(
            ops.iter()
                .any(|op| matches!(op, FirewallOperation::SetIcmpBlockInversion { .. }))
        );
        // Zone target is emitted permanent-only.
        assert!(ops.iter().any(|op| matches!(
            op,
            FirewallOperation::SetZoneTarget {
                zone_target: ZoneTarget::Drop,
                ..
            }
        )));
    }

    #[test]
    fn zone_absent_from_runtime_narrows_to_permanent() {
        use super::super::snapshot::ConfigurationTarget;
        use super::super::zone::ZoneDetails;
        let current = mock::sample().unwrap();
        let mut target = current.clone();
        // A permanent-only zone (created, not reloaded) gains a service.
        let fresh = ZoneName::parse("staging").unwrap();
        let mut cur2 = current.clone();
        cur2.permanent
            .insert(fresh.clone(), ZoneDetails::empty(fresh.clone()));
        let mut z = ZoneDetails::empty(fresh.clone());
        z.services.push(ServiceName::parse("ssh").unwrap());
        target.permanent.insert(fresh.clone(), z);

        let ops = plan(&cur2, &target);
        let op = ops
            .iter()
            .find(|op| matches!(op, FirewallOperation::AddService { zone, .. } if *zone == fresh))
            .unwrap();
        assert!(
            matches!(op, FirewallOperation::AddService { target, .. }
                if *target == ConfigurationTarget::Permanent),
            "runtime step would hit INVALID_ZONE: {op:?}"
        );
    }

    #[test]
    fn default_zone_change_requires_runtime_presence() {
        let current = mock::sample().unwrap();
        let mut target = current.clone();
        // Point the default at a zone that exists only in permanent.
        let fresh = ZoneName::parse("staging").unwrap();
        let mut cur2 = current.clone();
        cur2.permanent.insert(
            fresh.clone(),
            super::super::zone::ZoneDetails::empty(fresh.clone()),
        );
        target.permanent.insert(
            fresh.clone(),
            super::super::zone::ZoneDetails::empty(fresh.clone()),
        );
        target.default_zone = fresh;
        let ops = plan(&cur2, &target);
        assert!(
            !ops.iter()
                .any(|op| matches!(op, FirewallOperation::SetDefaultZone { .. })),
            "set-default-zone on a permanent-only zone fails with INVALID_ZONE"
        );
    }

    #[test]
    fn default_zone_change_is_emitted_first() {
        let current = mock::sample().unwrap();
        let mut target = current.clone();
        target.default_zone = ZoneName::parse("home").unwrap();
        let ops = plan(&current, &target);
        assert!(matches!(
            ops.first(),
            Some(FirewallOperation::SetDefaultZone { .. })
        ));
    }
}
