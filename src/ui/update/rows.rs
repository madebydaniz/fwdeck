//! Row-scoped actions on the visible table: activate, clone, mark, delete
//! (single and bulk), and yank.

use crate::domain::{DeniedFlow, FirewallOperation, FirewallSnapshot, IpSetName, ZoneName};
use crate::ui::action::{Effect, UiAction};
use crate::ui::details;
use crate::ui::overlays::{FormKind, Overlay};
use crate::ui::state::{ToastKind, UiState};
use crate::ui::views::{RowId, ViewId, ViewRow};

use super::{blocked_read_only, request_operation, selected_row, target_for_scope, update};

/// Propose a least-privilege allow rule from the selected denied log row. Bound
/// to `a` (add entry) in the Logs view: build a source-scoped rich rule for the
/// blocked flow and route it through the normal confirm -> stage -> apply path.
/// Nothing is applied automatically; non-denied or portless rows just explain
/// why they can't become a rule.
pub(super) fn propose_from_log(state: &mut UiState) -> Vec<Effect> {
    let Some(row) = selected_row(state) else {
        state.toast(ToastKind::Info, "no log line selected");
        return Vec::new();
    };
    let RowId::Log { entry, .. } = &row.id else {
        state.toast(ToastKind::Info, "unexpected log row");
        return Vec::new();
    };
    if !entry.action.is_denied() {
        state.toast(
            ToastKind::Info,
            "select a denied (DROP/REJECT) row to propose an allow rule",
        );
        return Vec::new();
    }
    let flow = match DeniedFlow::parse(&entry.src, &entry.dport, &entry.proto, &entry.iface) {
        Ok(flow) => flow,
        Err(err) => {
            state.toast(ToastKind::Info, err.to_string());
            return Vec::new();
        }
    };
    let Some(snapshot) = state.snapshot.clone() else {
        state.toast(ToastKind::Warning, "no firewall data yet — refresh first");
        return Vec::new();
    };
    // Resolve the zone by the ingress interface (where the traffic actually
    // arrives), not the spoofable source; fall back to the default zone.
    let zone = zone_for_iface(&snapshot, flow.iface.as_deref())
        .unwrap_or_else(|| snapshot.default_zone.clone());
    let Some(operation) = flow.propose_allow(zone, state.target) else {
        state.toast(ToastKind::Warning, "could not build a rule for this flow");
        return Vec::new();
    };
    request_operation(state, operation)
}

/// The zone whose bound interfaces include `iface`, if any.
fn zone_for_iface(snapshot: &FirewallSnapshot, iface: Option<&str>) -> Option<ZoneName> {
    let iface = iface?;
    snapshot.active.iter().find_map(|(zone, active)| {
        active
            .interfaces
            .iter()
            .any(|bound| bound.as_str() == iface)
            .then(|| zone.clone())
    })
}

pub(super) fn activate_row(state: &mut UiState) {
    if state.view == ViewId::Zones {
        let rows = state.visible_rows();
        let Some(RowId::Zone(zone)) = rows.get(state.view_state().selected).map(|row| &row.id)
        else {
            return;
        };
        state.selected_zone = Some(zone.clone());
        // Enter selects the zone AND opens its overview.
        if let Some(snapshot) = state.snapshot.clone()
            && let Some(content) = details::for_zone(&snapshot, zone)
        {
            state.overlays.push(Overlay::Details(content));
        }
        return;
    }

    let content = state.snapshot.clone().and_then(|snapshot| {
        let zone = state.effective_zone()?;
        let rows = state.visible_rows();
        let row = rows.get(state.view_state().selected)?;
        details::for_row(state.view, &snapshot, &zone, row)
    });
    if let Some(content) = content {
        state.overlays.push(Overlay::Details(content));
    }
}

/// Clones the selected row into a prefilled add form for the current view.
pub(super) fn clone_entry(state: &mut UiState) -> Vec<Effect> {
    let Some(row) = selected_row(state) else {
        return Vec::new();
    };
    let (kind, buffer) = match &row.id {
        RowId::Service { service, .. } => (FormKind::AddService, service.to_string()),
        RowId::Port { port, .. } => (FormKind::AddPort, port.to_string()),
        RowId::Forwarding { forward, .. } => (FormKind::AddForwardPort, forward.spec_string()),
        RowId::RichRule { rule, .. } => (FormKind::AddRichRule, rule.to_string()),
        RowId::Source { source, .. } => (FormKind::AddSource, source.to_string()),
        RowId::IpSet { name } => {
            let Some(kind) = row.ipset_kind() else {
                state.toast(ToastKind::Warning, "selected IP set has no type metadata");
                return Vec::new();
            };
            (FormKind::CreateIpSet, format!("{name} {kind}"))
        }
        _ => {
            state.toast(ToastKind::Info, "nothing to clone on this view");
            return Vec::new();
        }
    };
    update(state, UiAction::OpenFormPrefilled(kind, buffer))
}

pub(super) fn toggle_mark(state: &mut UiState) {
    let Some(key) = selected_row(state).map(|row| row.id) else {
        return;
    };
    let marked = &mut state.view_state_mut().marked;
    if !marked.remove(&key) {
        marked.insert(key);
    }
}

/// Builds a remove operation for one row of the current view (the shared body
/// of single and bulk delete). `None` if the row can't be turned into one.
fn remove_operation_for_row(state: &UiState, row: &ViewRow) -> Option<FirewallOperation> {
    match &row.id {
        RowId::Service { zone, service } => Some(FirewallOperation::RemoveService {
            zone: zone.clone(),
            service: service.clone(),
            target: target_for_scope(row.scope()?, state.target),
        }),
        RowId::Port { zone, port } => Some(FirewallOperation::RemovePort {
            zone: zone.clone(),
            port: *port,
            target: target_for_scope(row.scope()?, state.target),
        }),
        RowId::RichRule { zone, rule } => Some(FirewallOperation::RemoveRichRule {
            zone: zone.clone(),
            rule: rule.clone(),
            target: target_for_scope(row.scope()?, state.target),
        }),
        RowId::Forwarding { zone, forward } => Some(FirewallOperation::RemoveForwardPort {
            zone: zone.clone(),
            forward: forward.clone(),
            target: target_for_scope(row.scope()?, state.target),
        }),
        RowId::Source { zone, source } => Some(FirewallOperation::RemoveSource {
            zone: zone.clone(),
            source: source.clone(),
            target: row.configuration_target()?,
        }),
        // Zones/IpSets/Interfaces stay single-delete only: bulk-removing zones
        // or interface bindings is riskier than the retyping it saves.
        _ => None,
    }
}

pub(super) fn delete_entry(state: &mut UiState) -> Vec<Effect> {
    // Bulk path: if rows are marked, stage a remove for each behind one confirm.
    if !state.view_state().marked.is_empty() {
        return bulk_delete(state);
    }
    let Some(row) = selected_row(state) else {
        state.toast(ToastKind::Info, "nothing selected");
        return Vec::new();
    };
    // The single-delete-only views (deliberately excluded from bulk delete);
    // everything else shares remove_operation_for_row with the bulk path, so
    // the column layout is interpreted in exactly one place.
    let operation = match &row.id {
        RowId::Interface { zone, interface } => FirewallOperation::RemoveInterface {
            zone: zone.clone(),
            interface: interface.clone(),
            target: match row.configuration_target() {
                Some(target) => target,
                None => return Vec::new(),
            },
        },
        RowId::Zone(zone) => FirewallOperation::DeleteZone { zone: zone.clone() },
        RowId::IpSet { name, .. } => FirewallOperation::DeleteIpSet { name: name.clone() },
        RowId::Direct { .. } | RowId::Log { .. } => {
            state.toast(ToastKind::Info, "no delete action on this view");
            return Vec::new();
        }
        _ => match remove_operation_for_row(state, &row) {
            Some(operation) => operation,
            None => return Vec::new(),
        },
    };
    request_operation(state, operation)
}

/// The ipset selected in the `IPSets` view, for entry-scoped forms.
pub(super) fn selected_ipset(state: &UiState) -> Option<IpSetName> {
    if state.view != ViewId::IpSets {
        return None;
    }
    match selected_row(state)?.id {
        RowId::IpSet { name, .. } => Some(name),
        _ => None,
    }
}

fn bulk_delete(state: &mut UiState) -> Vec<Effect> {
    if blocked_read_only(state) {
        return Vec::new();
    }
    let marked = state.view_state().marked.clone();
    let rows = state.visible_rows();
    let ops: Vec<FirewallOperation> = rows
        .iter()
        .filter(|row| marked.contains(&row.id))
        .filter_map(|row| remove_operation_for_row(state, row))
        .collect();
    if ops.is_empty() {
        state.toast(ToastKind::Info, "no removable rows in the selection");
        return Vec::new();
    }
    state.view_state_mut().marked.clear();
    // Stage the batch and route it through the unified plan path, which builds
    // the confirmation (with SSH-lockout analysis) and pre-arms the dead-man's
    // switch — the same safety net a single delete gets.
    state.staged.extend(ops);
    super::plans::apply_staged_plan(state)
}

pub(super) fn yank_row(state: &mut UiState) -> Vec<Effect> {
    let Some(row) = selected_row(state) else {
        state.toast(ToastKind::Info, "nothing selected");
        return Vec::new();
    };
    // The last cell holds the fullest text (rule / args); fall back to the join.
    let text = row
        .last()
        .filter(|cell| !cell.is_empty())
        .cloned()
        .unwrap_or_else(|| row.join(" "));
    state.toast(ToastKind::Info, "row copied to clipboard");
    vec![Effect::CopyToClipboard(text)]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::domain::{ConfigurationTarget, SourceAddress};
    use crate::ui::views::Scope;

    fn state() -> UiState {
        UiState::new(&Config::default(), "test".to_owned(), false, None)
    }

    #[test]
    fn remove_port_uses_typed_identity_not_rendered_cells() {
        let zone = ZoneName::parse("public").unwrap();
        let row = ViewRow::scoped(
            RowId::Port {
                zone: zone.clone(),
                port: "8080/tcp".parse().unwrap(),
            },
            Scope::Runtime,
            vec!["22".to_owned(), "udp".to_owned(), "permanent".to_owned()],
        );
        let operation = remove_operation_for_row(&state(), &row).unwrap();
        match operation {
            FirewallOperation::RemovePort {
                zone: actual_zone,
                port,
                target,
            } => {
                assert_eq!(actual_zone, zone);
                assert_eq!(port.to_string(), "8080/tcp");
                assert_eq!(target, ConfigurationTarget::Runtime);
            }
            other => panic!("unexpected operation: {other:?}"),
        }
    }

    #[test]
    fn remove_source_uses_typed_binding_metadata_not_rendered_cells() {
        let zone = ZoneName::parse("dmz").unwrap();
        let source = SourceAddress::parse("203.0.113.0/24").unwrap();
        let row = ViewRow::targeted(
            RowId::Source {
                zone: zone.clone(),
                source: source.clone(),
            },
            ConfigurationTarget::Permanent,
            vec![
                "198.51.100.0/24".to_owned(),
                "ipv4".to_owned(),
                "public".to_owned(),
            ],
        );
        let operation = remove_operation_for_row(&state(), &row).unwrap();
        match operation {
            FirewallOperation::RemoveSource {
                zone: actual_zone,
                source: actual_source,
                target,
            } => {
                assert_eq!(actual_zone, zone);
                assert_eq!(actual_source, source);
                assert_eq!(target, ConfigurationTarget::Permanent);
            }
            other => panic!("unexpected operation: {other:?}"),
        }
    }
}
