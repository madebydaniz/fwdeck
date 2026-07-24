//! Form flows: submitted form buffers parsed into validated operations, the
//! rich-rule builder commit, and the read-only traffic explainer.

use crate::domain::{
    ConfigurationTarget, FirewallOperation, ForwardPort, IcmpType, InterfaceName, IpProtocol,
    IpSetEntry, IpSetName, PolicyName, PortSpec, RichRule, ServiceName, SourceAddress, ZoneName,
    ZoneTarget,
};
use crate::ui::action::Effect;
use crate::ui::overlays::{DetailsContent, FormKind, Overlay};
use crate::ui::state::{ToastKind, UiState};

use super::plans::restore_snapshot;
use super::request_operation;
use super::rows::selected_ipset;

#[allow(clippy::too_many_lines)] // one arm per view
/// Toggles the selected row's identity in the multi-select set.
/// Advances the rich-rule builder; on the final step, validates the assembled
/// rule and routes it into the normal add-rich-rule confirmation flow.
pub(super) fn rich_builder_commit(state: &mut UiState) -> Vec<Effect> {
    let Some(Overlay::RichBuilder(builder)) = state.overlays.last_mut() else {
        return Vec::new();
    };
    let Some(assembled) = builder.commit() else {
        return Vec::new(); // more steps to go
    };
    state.overlays.pop();
    let Some(zone) = state.effective_zone() else {
        return Vec::new();
    };
    match RichRule::parse(&assembled) {
        Ok(rule) => request_operation(
            state,
            FirewallOperation::AddRichRule {
                zone,
                rule,
                target: state.target,
            },
        ),
        Err(err) => {
            state.toast(
                ToastKind::Warning,
                format!("assembled an invalid rule: {err}"),
            );
            Vec::new()
        }
    }
}

/// Turns the submitted form buffer into an operation. Every arm produces
/// `Result<_, String>`; the single epilogue toasts the error and keeps the
/// form open for correction — the invalid-input policy lives in one place.
#[allow(clippy::too_many_lines)] // one arm per form kind
pub(super) fn form_submit(state: &mut UiState) -> Vec<Effect> {
    let Some(Overlay::Form(form)) = state.overlays.last() else {
        return Vec::new();
    };
    let kind = form.kind;
    let input = form.buffer.trim().to_owned();
    let Some(zone) = state.effective_zone() else {
        return Vec::new();
    };
    let err_string = |err: &dyn std::fmt::Display| err.to_string();
    let target = state.target;
    let built: Result<FirewallOperation, String> = match kind {
        FormKind::RestoreSnapshot => return restore_snapshot(state, &input),
        FormKind::DiffSnapshot => return super::plans::diff_snapshot(state, &input),
        FormKind::ExplainTraffic => return explain_traffic(state, &input),
        FormKind::AddTemporaryService => {
            let mut parts = input.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some(raw_service), Some(raw_secs)) => {
                    match (ServiceName::parse(raw_service), raw_secs.parse::<u32>()) {
                        (Ok(service), Ok(seconds)) if seconds > 0 => {
                            Ok(FirewallOperation::AddTemporaryService {
                                zone,
                                service,
                                seconds,
                            })
                        }
                        (Ok(_), _) => Err("seconds must be a positive number".to_owned()),
                        (Err(err), _) => Err(err.to_string()),
                    }
                }
                _ => Err("expected: <service> <seconds>".to_owned()),
            }
        }
        FormKind::AddService => ServiceName::parse(&input)
            .map(|service| FirewallOperation::AddService {
                zone,
                service,
                target,
            })
            .map_err(|e| err_string(&e)),
        FormKind::AddPort => input
            .parse::<PortSpec>()
            .map(|port| FirewallOperation::AddPort { zone, port, target })
            .map_err(|e| err_string(&e)),
        FormKind::AddForwardPort => input
            .parse::<ForwardPort>()
            .map(|forward| FirewallOperation::AddForwardPort {
                zone,
                forward,
                target,
            })
            .map_err(|e| err_string(&e)),
        FormKind::AddRichRule => RichRule::parse(&input)
            .map(|rule| FirewallOperation::AddRichRule { zone, rule, target })
            .map_err(|e| err_string(&e)),
        FormKind::AddInterface => InterfaceName::parse(&input)
            .map(|interface| FirewallOperation::AddInterface {
                zone,
                interface,
                target,
            })
            .map_err(|e| err_string(&e)),
        FormKind::AddSource => SourceAddress::parse(&input)
            .map(|source| FirewallOperation::AddSource {
                zone,
                source,
                target,
            })
            .map_err(|e| err_string(&e)),
        FormKind::AddIcmpBlock => IcmpType::parse(&input)
            .map(|icmp| FirewallOperation::AddIcmpBlock { zone, icmp, target })
            .map_err(|e| err_string(&e)),
        FormKind::SetZoneTarget => input
            .trim()
            .parse::<ZoneTarget>()
            .map(|zone_target| FirewallOperation::SetZoneTarget { zone, zone_target })
            .map_err(|e| err_string(&e)),
        FormKind::AddSourcePort => input
            .parse::<PortSpec>()
            .map(|port| FirewallOperation::AddSourcePort { zone, port, target })
            .map_err(|e| err_string(&e)),
        FormKind::RemoveSourcePort => input
            .parse::<PortSpec>()
            .map(|port| FirewallOperation::RemoveSourcePort { zone, port, target })
            .map_err(|e| err_string(&e)),
        FormKind::AddProtocol => IpProtocol::parse(&input)
            .map(|protocol| FirewallOperation::AddProtocol {
                zone,
                protocol,
                target,
            })
            .map_err(|e| err_string(&e)),
        FormKind::RemoveProtocol => IpProtocol::parse(&input)
            .map(|protocol| FirewallOperation::RemoveProtocol {
                zone,
                protocol,
                target,
            })
            .map_err(|e| err_string(&e)),
        FormKind::CreateZone => ZoneName::parse(&input)
            .map(|new_zone| FirewallOperation::CreateZone { zone: new_zone })
            .map_err(|e| err_string(&e)),
        FormKind::CreateService => ServiceName::parse(&input)
            .map(|service| FirewallOperation::CreateService { service })
            .map_err(|e| err_string(&e)),
        FormKind::CreatePolicy => PolicyName::parse(&input)
            .map(|policy| FirewallOperation::CreatePolicy { policy })
            .map_err(|e| err_string(&e)),
        FormKind::CreateIpSet => {
            let mut parts = input.split_whitespace();
            let raw_name = parts.next().unwrap_or_default();
            let kind = parts.next().unwrap_or("hash:ip").to_owned();
            IpSetName::parse(raw_name)
                .map(|name| FirewallOperation::CreateIpSet { name, kind })
                .map_err(|e| err_string(&e))
        }
        FormKind::AddPolicyService => parse_policy_service_form(&input, target),
        FormKind::AddServicePort | FormKind::RemoveServicePort => {
            parse_service_port_form(kind, &input)
        }
        FormKind::AddIpSetEntry | FormKind::RemoveIpSetEntry => {
            parse_ipset_entry_form(state, kind, &input, target)
        }
    };
    let operation = match built {
        Ok(operation) => operation,
        Err(message) => {
            // Keep the form open for correction.
            state.toast(ToastKind::Warning, message);
            return Vec::new();
        }
    };
    state.overlays.pop(); // the confirmation replaces the form
    request_operation(state, operation)
}

/// Parses the ipset-entry form input against the selected ipset row.
fn parse_ipset_entry_form(
    state: &UiState,
    kind: FormKind,
    input: &str,
    target: ConfigurationTarget,
) -> Result<FirewallOperation, String> {
    let Some(name) = selected_ipset(state) else {
        return Err("select an ipset row first".to_owned());
    };
    // Verbatim entry: covers simple (203.0.113.9) and compound
    // (1.2.3.4,tcp:80 / 10.0.0.0/8,eth0) types; firewalld validates the grammar.
    let entry = IpSetEntry::parse(input).map_err(|err| err.to_string())?;
    Ok(if kind == FormKind::AddIpSetEntry {
        FirewallOperation::AddIpSetEntry {
            name,
            entry,
            target,
        }
    } else {
        FirewallOperation::RemoveIpSetEntry {
            name,
            entry,
            target,
        }
    })
}

/// Parses the two-field `<policy> <service>` form input.
fn parse_policy_service_form(
    input: &str,
    target: ConfigurationTarget,
) -> Result<FirewallOperation, String> {
    let mut parts = input.split_whitespace();
    let (Some(raw_policy), Some(raw_service)) = (parts.next(), parts.next()) else {
        return Err("expected: <policy> <service>".to_owned());
    };
    match (
        PolicyName::parse(raw_policy),
        ServiceName::parse(raw_service),
    ) {
        (Ok(policy), Ok(service)) => Ok(FirewallOperation::AddPolicyService {
            policy,
            service,
            target,
        }),
        (Err(err), _) | (_, Err(err)) => Err(err.to_string()),
    }
}

/// Parses the two-field `<service> <port>/<proto>` form input.
fn parse_service_port_form(kind: FormKind, input: &str) -> Result<FirewallOperation, String> {
    let mut parts = input.split_whitespace();
    let (Some(raw_service), Some(raw_port)) = (parts.next(), parts.next()) else {
        return Err("expected: <service> <port>/<proto>".to_owned());
    };
    match (
        ServiceName::parse(raw_service),
        raw_port.parse::<PortSpec>(),
    ) {
        (Ok(service), Ok(port)) => Ok(if kind == FormKind::AddServicePort {
            FirewallOperation::AddServicePort { service, port }
        } else {
            FirewallOperation::RemoveServicePort { service, port }
        }),
        (Err(err), _) | (_, Err(err)) => Err(err.to_string()),
    }
}

/// Parses `<source-ip> <port>/<proto>`, runs the domain traffic explainer
/// against the current snapshot, and shows the result in a details overlay.
/// Read-only — this is not an operation and never reaches the engine. Parse
/// errors toast and keep the form open, like every other form.
fn explain_traffic(state: &mut UiState, input: &str) -> Vec<Effect> {
    let Some(snapshot) = state.snapshot.clone() else {
        state.toast(ToastKind::Warning, "no firewall data yet — refresh first");
        return Vec::new();
    };
    let mut parts = input.split_whitespace();
    let (Some(raw_source), Some(raw_port)) = (parts.next(), parts.next()) else {
        state.toast(ToastKind::Warning, "expected: <source-ip> <port>/<proto>");
        return Vec::new();
    };
    match SourceAddress::parse(raw_source) {
        Ok(SourceAddress::Ip { prefix: None, .. }) => {}
        Ok(SourceAddress::Ip { .. }) => {
            state.toast(
                ToastKind::Warning,
                "enter a single source IP, without a CIDR prefix",
            );
            return Vec::new();
        }
        Ok(_) => {
            state.toast(
                ToastKind::Warning,
                "enter a plain IP address (MAC and ipset sources cannot be traced)",
            );
            return Vec::new();
        }
        Err(err) => {
            state.toast(ToastKind::Warning, err.to_string());
            return Vec::new();
        }
    }
    let port: PortSpec = match raw_port.parse() {
        Ok(port) => port,
        Err(err) => {
            state.toast(ToastKind::Warning, err.to_string());
            return Vec::new();
        }
    };
    let lines = crate::domain::explain::explain(&snapshot, raw_source, port);
    state.overlays.pop(); // the details replace the form
    state.overlays.push(Overlay::Details(DetailsContent {
        title: format!("Traffic: {raw_source} → {port}"),
        lines,
    }));
    Vec::new()
}
