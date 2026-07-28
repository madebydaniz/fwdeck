//! Row-scoped actions on the visible table: activate, clone, mark, delete
//! (single and bulk), and yank.

use crate::domain::{
    DeniedFlow, FirewallOperation, FirewallSnapshot, ForwardPort, InterfaceName, IpSetName,
    PortSpec, RichRule, ServiceName, SourceAddress, ZoneName,
};
use crate::ui::action::{Effect, UiAction};
use crate::ui::details;
use crate::ui::overlays::{FormKind, Overlay};
use crate::ui::state::{ToastKind, UiState};
use crate::ui::views::ViewId;

use super::{blocked_read_only, request_operation, selected_row, target_for_scope, update};

/// Propose a least-privilege allow rule from the selected denied log row. Bound
/// to `a` (add entry) in the Logs view: build a source-scoped rich rule for the
/// blocked flow and route it through the normal confirm -> stage -> apply path.
/// Nothing is applied automatically; non-denied or portless rows just explain
/// why they can't become a rule.
pub(super) fn propose_from_log(state: &mut UiState) -> Vec<Effect> {
    let Some(cells) = selected_row(state) else {
        state.toast(ToastKind::Info, "no log line selected");
        return Vec::new();
    };
    // Logs columns: [time, action, src, dst, dport, proto, iface].
    let (Some(action), Some(src), Some(dport), Some(proto), Some(iface)) = (
        cells.get(1),
        cells.get(2),
        cells.get(4),
        cells.get(5),
        cells.get(6),
    ) else {
        state.toast(ToastKind::Info, "unexpected log row");
        return Vec::new();
    };
    if action != "DROP" && action != "REJECT" {
        state.toast(
            ToastKind::Info,
            "select a denied (DROP/REJECT) row to propose an allow rule",
        );
        return Vec::new();
    }
    let flow = match DeniedFlow::parse(src, dport, proto, iface) {
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
        let Some(name) = rows
            .get(state.view_state().selected)
            .and_then(|row| row.first())
        else {
            return;
        };
        if let Ok(zone) = ZoneName::parse(name) {
            state.selected_zone = Some(zone.clone());
            // Enter selects the zone AND opens its overview.
            if let Some(snapshot) = state.snapshot.clone()
                && let Some(content) = details::for_zone(&snapshot, &zone)
            {
                state.overlays.push(Overlay::Details(content));
            }
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
    let cell = |i: usize| row.get(i).cloned().unwrap_or_default();
    let (kind, buffer) = match state.view {
        ViewId::Services => (FormKind::AddService, cell(0)),
        ViewId::Ports => (FormKind::AddPort, format!("{}/{}", cell(0), cell(1))),
        ViewId::Forwarding => {
            let Some(forward) = ForwardPort::from_parts(&cell(0), &cell(1), &cell(2), &cell(3))
            else {
                return Vec::new();
            };
            (FormKind::AddForwardPort, forward.spec_string())
        }
        ViewId::RichRules => (FormKind::AddRichRule, cell(3)),
        ViewId::Sources => (FormKind::AddSource, cell(0)),
        ViewId::IpSets => (FormKind::CreateIpSet, format!("{} {}", cell(0), cell(1))),
        _ => {
            state.toast(ToastKind::Info, "nothing to clone on this view");
            return Vec::new();
        }
    };
    update(state, UiAction::OpenFormPrefilled(kind, buffer))
}

pub(super) fn toggle_mark(state: &mut UiState) {
    let Some(key) = selected_row(state).map(|row| crate::ui::state::row_key(&row)) else {
        return;
    };
    let marked = &mut state.view_state_mut().marked;
    if !marked.remove(&key) {
        marked.insert(key);
    }
}

/// Builds a remove operation for one row of the current view (the shared body
/// of single and bulk delete). `None` if the row can't be turned into one.
fn remove_operation_for_row(state: &UiState, row: &[String]) -> Option<FirewallOperation> {
    let zone = state.effective_zone()?;
    let name = row.first().cloned().unwrap_or_default();
    match state.view {
        ViewId::Services => {
            let service = ServiceName::parse(&name).ok()?;
            let scope = row.get(3).map(String::as_str).unwrap_or_default();
            Some(FirewallOperation::RemoveService {
                zone,
                service,
                target: target_for_scope(scope, state.target),
            })
        }
        ViewId::Ports => {
            let spec = format!(
                "{}/{}",
                name,
                row.get(1).map(String::as_str).unwrap_or_default()
            );
            let port = spec.parse::<PortSpec>().ok()?;
            let scope = row.get(2).map(String::as_str).unwrap_or_default();
            Some(FirewallOperation::RemovePort {
                zone,
                port,
                target: target_for_scope(scope, state.target),
            })
        }
        ViewId::RichRules => {
            let rule = RichRule::parse(row.get(3).map(String::as_str).unwrap_or_default()).ok()?;
            let scope = row.get(2).map(String::as_str).unwrap_or_default();
            Some(FirewallOperation::RemoveRichRule {
                zone,
                rule,
                target: target_for_scope(scope, state.target),
            })
        }
        ViewId::Forwarding => {
            let forward = ForwardPort::from_parts(
                &name,
                row.get(1).map(String::as_str).unwrap_or_default(),
                row.get(2).map(String::as_str).unwrap_or_default(),
                row.get(3).map(String::as_str).unwrap_or_default(),
            )?;
            let scope = row.get(4).map(String::as_str).unwrap_or_default();
            Some(FirewallOperation::RemoveForwardPort {
                zone,
                forward,
                target: target_for_scope(scope, state.target),
            })
        }
        ViewId::Sources => {
            let source = SourceAddress::parse(&name).ok()?;
            let row_zone =
                ZoneName::parse(row.get(2).map(String::as_str).unwrap_or_default()).ok()?;
            Some(FirewallOperation::RemoveSource {
                zone: row_zone,
                source,
                target: state.config_view,
            })
        }
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
    let name = row.first().cloned().unwrap_or_default();
    // The single-delete-only views (deliberately excluded from bulk delete);
    // everything else shares remove_operation_for_row with the bulk path, so
    // the column layout is interpreted in exactly one place.
    let operation = match state.view {
        ViewId::Interfaces => {
            // Rows are global: the zone comes from the row, not the context.
            let (Ok(interface), Ok(row_zone)) = (
                InterfaceName::parse(&name),
                ZoneName::parse(row.get(1).map(String::as_str).unwrap_or_default()),
            ) else {
                return Vec::new();
            };
            // The perspective (`t`) decides which binding this row represents.
            FirewallOperation::RemoveInterface {
                zone: row_zone,
                interface,
                target: state.config_view,
            }
        }
        ViewId::Zones => {
            let Ok(target_zone) = ZoneName::parse(&name) else {
                return Vec::new();
            };
            FirewallOperation::DeleteZone { zone: target_zone }
        }
        ViewId::IpSets => {
            let Ok(set_name) = IpSetName::parse(&name) else {
                return Vec::new();
            };
            FirewallOperation::DeleteIpSet { name: set_name }
        }
        ViewId::Direct | ViewId::Logs => {
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
    let name = selected_row(state)?.first()?.clone();
    IpSetName::parse(&name).ok()
}

fn bulk_delete(state: &mut UiState) -> Vec<Effect> {
    if blocked_read_only(state) {
        return Vec::new();
    }
    let marked = state.view_state().marked.clone();
    let rows = state.visible_rows();
    let ops: Vec<FirewallOperation> = rows
        .iter()
        .filter(|row| marked.contains(&crate::ui::state::row_key(row)))
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
