//! Pure builders for the details overlay content: zone inspection, per-row
//! details (rich rules especially — they rarely fit a table row), and backend
//! error diagnostics with recovery hints.

use crate::application::ports::{FirewallError, OperationOutcome};
use crate::domain::{FirewallOperation, FirewallSnapshot, ZoneName};

use super::views::{RowId, ViewId, ViewRow};

/// Read-only rendering of live nftables rule-hit counters, busiest chain first.
/// An empty list is normal — firewalld only counters some rules.
#[must_use]
pub fn counters(counters: &[crate::domain::ChainCounter]) -> DetailsContent {
    let mut lines: Vec<(String, String)> = if counters.is_empty() {
        vec![(
            String::new(),
            "no rule-hit counters (needs the nftables backend + root; firewalld \
             counters only some rules)"
                .to_owned(),
        )]
    } else {
        counters
            .iter()
            .map(|c| {
                (
                    c.chain.clone(),
                    format!("{} packets · {} bytes", c.packets, c.bytes),
                )
            })
            .collect()
    };
    lines.push((String::new(), String::new()));
    lines.push((String::new(), "live nft counters · esc to close".to_owned()));
    DetailsContent {
        title: format!("Rule-hit counters ({})", counters.len()),
        lines,
    }
}

/// Read-only rendering of a diff between two states, as the ordered list of
/// operations that would transform one into the other. Shared by the
/// session-diff and snapshot-diff views (which never stage — they only show).
#[must_use]
pub fn diff(title: String, ops: &[FirewallOperation]) -> DetailsContent {
    let mut lines: Vec<(String, String)> = if ops.is_empty() {
        vec![(String::new(), "no differences".to_owned())]
    } else {
        ops.iter()
            .enumerate()
            .map(|(index, op)| (format!("{}.", index + 1), op.describe()))
            .collect()
    };
    lines.push((String::new(), String::new()));
    lines.push((String::new(), "read-only diff · esc to close".to_owned()));
    DetailsContent { title, lines }
}

/// Content of the details overlay: a title plus labeled lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailsContent {
    /// Modal title.
    pub title: String,
    /// `key: value` pairs; an empty key renders as a continuation/plain line.
    pub lines: Vec<(String, String)>,
}

fn line(key: &str, value: impl Into<String>) -> (String, String) {
    (key.to_owned(), value.into())
}

fn join<T: ToString>(items: &[T]) -> String {
    if items.is_empty() {
        "-".to_owned()
    } else {
        items
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Zone Overview: a composite of one zone's complete configuration. Attributes
/// that differ between runtime and permanent are shown on separate `… (runtime)`
/// / `… (permanent)` lines so drift is visible per attribute, not just as a flag.
#[must_use]
pub fn for_zone(snapshot: &FirewallSnapshot, zone: &ZoneName) -> Option<DetailsContent> {
    let runtime = snapshot.runtime.get(zone);
    let permanent = snapshot.permanent.get(zone);
    let details = runtime.or(permanent)?;

    let mut lines = vec![
        line("target", details.target.as_str()),
        line("active", yes_no(snapshot.is_active(zone))),
        line("default", yes_no(*zone == snapshot.default_zone)),
        line(
            "state",
            if snapshot.is_zone_synced(zone) {
                "runtime + permanent · synced"
            } else {
                "runtime + permanent · DIFFERENT"
            },
        ),
        (String::new(), String::new()),
    ];

    // Bindings come from the active (runtime) map; permanent bindings from the
    // permanent config — show both when they differ.
    drift_line(&mut lines, "interfaces", runtime, permanent, |z| {
        join(&z.interfaces)
    });
    drift_line(&mut lines, "sources", runtime, permanent, |z| {
        join(&z.sources)
    });
    drift_bool(&mut lines, "masquerade", runtime, permanent, |z| {
        z.masquerade
    });
    drift_bool(&mut lines, "forward", runtime, permanent, |z| z.forward);
    drift_bool(&mut lines, "icmp-inversion", runtime, permanent, |z| {
        z.icmp_block_inversion
    });

    lines.push((String::new(), String::new()));
    drift_services(&mut lines, snapshot, runtime, permanent);
    drift_line(&mut lines, "ports", runtime, permanent, |z| join(&z.ports));
    drift_line(&mut lines, "source-ports", runtime, permanent, |z| {
        join(&z.source_ports)
    });
    drift_line(&mut lines, "protocols", runtime, permanent, |z| {
        join(&z.protocols)
    });
    drift_line(&mut lines, "icmp-blocks", runtime, permanent, |z| {
        join(&z.icmp_blocks)
    });

    for forward in &details.forward_ports {
        lines.push(line("forward", forward_desc(forward)));
    }
    for rule in &details.rich_rules {
        lines.push(line("rich rule", rule.as_str()));
    }
    Some(DetailsContent {
        title: format!("Zone `{zone}` — overview"),
        lines,
    })
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// One-line description of a forward-port rule.
fn forward_desc(forward: &crate::domain::ForwardPort) -> String {
    format!(
        "{}/{} -> port {} addr {}",
        forward.port,
        forward.protocol,
        forward
            .to_port
            .map_or_else(|| "-".to_owned(), |p| p.to_string()),
        forward
            .to_addr
            .map_or_else(|| "-".to_owned(), |a| a.to_string()),
    )
}

/// Emits one line for a string attribute, or a `(runtime)`/`(permanent)` pair
/// when the two configurations disagree.
fn drift_line(
    lines: &mut Vec<(String, String)>,
    label: &str,
    runtime: Option<&crate::domain::ZoneDetails>,
    permanent: Option<&crate::domain::ZoneDetails>,
    render: impl Fn(&crate::domain::ZoneDetails) -> String,
) {
    let r = runtime.map(&render);
    let p = permanent.map(&render);
    match (r, p) {
        (Some(r), Some(p)) if r == p => lines.push(line(label, r)),
        (Some(r), Some(p)) => {
            lines.push(line(&format!("{label} (rt)"), r));
            lines.push(line(&format!("{label} (perm)"), p));
        }
        (Some(v), None) | (None, Some(v)) => lines.push(line(label, v)),
        (None, None) => {}
    }
}

fn drift_bool(
    lines: &mut Vec<(String, String)>,
    label: &str,
    runtime: Option<&crate::domain::ZoneDetails>,
    permanent: Option<&crate::domain::ZoneDetails>,
    field: impl Fn(&crate::domain::ZoneDetails) -> bool,
) {
    drift_line(lines, label, runtime, permanent, |z| {
        yes_no(field(z)).to_owned()
    });
}

/// Services with their port definitions, drift-aware.
fn drift_services(
    lines: &mut Vec<(String, String)>,
    snapshot: &FirewallSnapshot,
    runtime: Option<&crate::domain::ZoneDetails>,
    permanent: Option<&crate::domain::ZoneDetails>,
) {
    let render = |z: &crate::domain::ZoneDetails| {
        z.services
            .iter()
            .map(|service| {
                snapshot
                    .service_definitions
                    .get(service)
                    .map(|def| join(&def.ports))
                    .filter(|ports| ports != "-")
                    .map_or_else(
                        || service.to_string(),
                        |ports| format!("{service}({ports})"),
                    )
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    drift_line(lines, "services", runtime, permanent, render);
}

/// Details for the selected typed row of the current view.
#[must_use]
pub fn for_row(
    view: ViewId,
    snapshot: &FirewallSnapshot,
    zone: &ZoneName,
    row: &ViewRow,
) -> Option<DetailsContent> {
    let cell = |index: usize| row.get(index).cloned().unwrap_or_default();
    match view {
        ViewId::Zones => {
            let RowId::Zone(name) = &row.id else {
                return None;
            };
            for_zone(snapshot, name)
        }
        ViewId::Services => Some(DetailsContent {
            title: format!("Service `{}`", cell(0)),
            lines: vec![
                line("zone", zone.to_string()),
                line("ports", cell(1)),
                line("protocols", cell(2)),
                line("scope", cell(3)),
            ],
        }),
        ViewId::Ports => Some(DetailsContent {
            title: format!("Port {}/{}", cell(0), cell(1)),
            lines: vec![line("zone", zone.to_string()), line("scope", cell(2))],
        }),
        ViewId::Forwarding => Some(DetailsContent {
            title: format!("Forward {}/{}", cell(0), cell(1)),
            lines: vec![
                line("zone", zone.to_string()),
                line("to port", cell(2)),
                line("to address", cell(3)),
                line("scope", cell(4)),
            ],
        }),
        ViewId::RichRules => {
            let RowId::RichRule { rule, .. } = &row.id else {
                return None;
            };
            Some(DetailsContent {
                title: "Rich rule".to_owned(),
                lines: vec![
                    line("zone", zone.to_string()),
                    line("family", rule.family().unwrap_or("-")),
                    line("action", rule.action().unwrap_or("-")),
                    line("scope", cell(2)),
                    line("rule", rule.as_str()),
                ],
            })
        }
        ViewId::Interfaces => Some(DetailsContent {
            title: format!("Interface `{}`", cell(0)),
            lines: vec![line("zone", cell(1)), line("active", cell(2))],
        }),
        ViewId::Sources => Some(DetailsContent {
            title: format!("Source {}", cell(0)),
            lines: vec![line("family", cell(1)), line("zone", cell(2))],
        }),
        ViewId::IpSets => {
            let RowId::IpSet { name } = &row.id else {
                return None;
            };
            ipset_details(snapshot, name, row.scope()?)
        }
        ViewId::Policies => {
            let RowId::Policy { name } = &row.id else {
                return None;
            };
            policy_details(snapshot, name)
        }
        ViewId::Direct => Some(DetailsContent {
            title: "Direct rule (deprecated)".to_owned(),
            lines: vec![
                line("family", cell(0)),
                line("table", cell(1)),
                line("chain", cell(2)),
                line("priority", cell(3)),
                line("args", cell(4)),
                line(
                    "note",
                    "direct rules are deprecated in firewalld — prefer rich rules or policies",
                ),
            ],
        }),
        ViewId::Logs => Some(DetailsContent {
            title: "Log entry".to_owned(),
            lines: vec![
                line("time", cell(0)),
                line("action", cell(1)),
                line("source", cell(2)),
                line("destination", cell(3)),
                line("dport", cell(4)),
                line("protocol", cell(5)),
                line("interface", cell(6)),
            ],
        }),
    }
}

fn policy_details(
    snapshot: &FirewallSnapshot,
    name: &crate::domain::PolicyName,
) -> Option<DetailsContent> {
    let runtime = snapshot.policies.runtime.get(name);
    let permanent = snapshot.policies.permanent.get(name);
    if runtime.is_none() && permanent.is_none() {
        return None;
    }

    let mut lines = Vec::new();
    match (runtime, permanent) {
        (Some(runtime), Some(permanent)) if runtime.configuration_eq(permanent) => {
            append_policy_configuration(&mut lines, "both", runtime);
        }
        (Some(runtime), Some(permanent)) => {
            append_policy_configuration(&mut lines, "runtime (drift)", runtime);
            append_policy_configuration(&mut lines, "permanent (drift)", permanent);
        }
        (Some(runtime), None) => append_policy_configuration(&mut lines, "runtime", runtime),
        (None, Some(permanent)) => {
            append_policy_configuration(&mut lines, "permanent", permanent);
        }
        (None, None) => {}
    }

    let missing = match (runtime, permanent) {
        (Some(runtime), Some(permanent)) if runtime.configuration_eq(permanent) => {
            super::views::policy_dependency_issues(snapshot, runtime)
        }
        (Some(runtime), Some(permanent)) => {
            super::views::policy_dependency_issues(snapshot, runtime)
                .into_iter()
                .map(|issue| format!("runtime {issue}"))
                .chain(
                    super::views::policy_dependency_issues(snapshot, permanent)
                        .into_iter()
                        .map(|issue| format!("permanent {issue}")),
                )
                .collect()
        }
        (Some(runtime), None) => super::views::policy_dependency_issues(snapshot, runtime),
        (None, Some(permanent)) => super::views::policy_dependency_issues(snapshot, permanent),
        (None, None) => Vec::new(),
    };
    lines.push(line(
        "dependencies",
        if missing.is_empty() {
            "all referenced zones/services are known".to_owned()
        } else {
            format!("missing: {}", missing.join(", "))
        },
    ));

    Some(DetailsContent {
        title: format!("Policy `{name}`"),
        lines,
    })
}

fn append_policy_configuration(
    lines: &mut Vec<(String, String)>,
    scope: &str,
    policy: &crate::domain::PolicyDetails,
) {
    lines.push(line("configuration", scope));
    lines.push(line(
        "state",
        if policy.disabled {
            "disabled"
        } else if policy.active {
            "active"
        } else {
            "inactive"
        },
    ));
    lines.push(line("priority", policy.priority.to_string()));
    lines.push(line("target", policy.target.as_str()));
    lines.push(line(
        "flow",
        format!(
            "{} → {}",
            join(&policy.ingress_zones),
            join(&policy.egress_zones)
        ),
    ));
    lines.push(line("services", join(&policy.services)));
    lines.push(line("ports", join(&policy.ports)));
    lines.push(line("protocols", join(&policy.protocols)));
    lines.push(line("source ports", join(&policy.source_ports)));
    let forward_ports: Vec<_> = policy
        .forward_ports
        .iter()
        .map(crate::domain::ForwardPort::spec_string)
        .collect();
    lines.push(line("forward ports", join(&forward_ports)));
    lines.push(line("icmp blocks", join(&policy.icmp_blocks)));
    lines.push(line(
        "masquerade",
        if policy.masquerade { "yes" } else { "no" },
    ));
    for rule in &policy.rich_rules {
        lines.push(line("rich rule", rule.as_str()));
    }
}

fn ipset_details(
    snapshot: &FirewallSnapshot,
    name: &crate::domain::IpSetName,
    scope: crate::ui::views::Scope,
) -> Option<DetailsContent> {
    let runtime = snapshot.ipsets.runtime.get(name);
    let permanent = snapshot.ipsets.permanent.get(name);
    let info = runtime.or(permanent)?;
    let mut lines = vec![
        line("type", info.kind.clone()),
        line("scope", scope.as_str()),
    ];
    if runtime.is_none_or(|value| value.entries.is_empty()) {
        lines.push(line("runtime entries", "none"));
    }
    if let Some(runtime) = runtime {
        for entry in &runtime.entries {
            lines.push(line("runtime entry", entry.clone()));
        }
    }
    if permanent.is_none_or(|value| value.entries.is_empty()) {
        lines.push(line("permanent entries", "none"));
    }
    if let Some(permanent) = permanent {
        for entry in &permanent.entries {
            lines.push(line("permanent entry", entry.clone()));
        }
    }
    Some(DetailsContent {
        title: format!("IPSet `{name}`"),
        lines,
    })
}

/// Post-execution operation report: one line per step with the exact
/// invocation, plus rollback metadata on partial failure.
#[must_use]
pub fn for_outcome(outcome: &OperationOutcome) -> DetailsContent {
    let title = match outcome {
        OperationOutcome::Applied { .. } => "Operation applied",
        OperationOutcome::PartiallyApplied { .. } => "PARTIAL FAILURE",
        OperationOutcome::Failed { .. } => "Operation failed",
        OperationOutcome::Indeterminate { .. } => "OUTCOME UNKNOWN — verify before retrying",
    };
    let mut lines = vec![line("operation", outcome.operation().describe())];
    for step in outcome.steps() {
        let status = match &step.result {
            Ok(()) => "ok".to_owned(),
            Err(err) => err.to_string(),
        };
        lines.push(line(
            step.target,
            format!("firewall-cmd {} → {status}", step.invocation.join(" ")),
        ));
    }
    if let OperationOutcome::PartiallyApplied { rollback_hint, .. } = outcome {
        lines.push(line(
            "state",
            "runtime and permanent configurations are now OUT OF SYNC",
        ));
        if let Some(hint) = rollback_hint {
            lines.push(line(
                "rollback",
                format!("to undo the applied half: {}", hint.describe()),
            ));
        }
    }
    if let Some(error) = outcome.first_error() {
        lines.push(line("suggested", recovery_hint(error)));
    }
    DetailsContent {
        title: title.to_owned(),
        lines,
    }
}

/// All policy objects with their ingress/egress zones, target, and services.
#[must_use]
pub fn policy_browse(snapshot: &FirewallSnapshot) -> DetailsContent {
    let mut lines: Vec<(String, String)> = Vec::new();
    let mut names: Vec<_> = snapshot
        .policies
        .runtime
        .keys()
        .chain(snapshot.policies.permanent.keys())
        .collect();
    names.sort();
    names.dedup();
    if names.is_empty() {
        lines.push(("policies".to_owned(), "none defined".to_owned()));
    }
    let mut add_policy =
        |name: &crate::domain::PolicyName, scope: &str, policy: &crate::domain::PolicyDetails| {
            lines.push((format!("{name} [{scope}]"), String::new()));
            lines.push((String::new(), format!("target: {}", policy.target.as_str())));
            lines.push((
                String::new(),
                format!(
                    "ingress: {} → egress: {}",
                    join(&policy.ingress_zones),
                    join(&policy.egress_zones)
                ),
            ));
            if !policy.services.is_empty() {
                lines.push((
                    String::new(),
                    format!("services: {}", join(&policy.services)),
                ));
            }
            if !policy.ports.is_empty() {
                lines.push((String::new(), format!("ports: {}", join(&policy.ports))));
            }
        };
    for name in &names {
        let runtime = snapshot.policies.runtime.get(*name);
        let permanent = snapshot.policies.permanent.get(*name);
        match (runtime, permanent) {
            (Some(runtime), Some(permanent)) if runtime.configuration_eq(permanent) => {
                add_policy(name, "both", runtime);
            }
            (Some(runtime), Some(permanent)) => {
                add_policy(name, "runtime drift", runtime);
                add_policy(name, "permanent drift", permanent);
            }
            (Some(runtime), None) => add_policy(name, "runtime", runtime),
            (None, Some(permanent)) => add_policy(name, "permanent", permanent),
            (None, None) => {}
        }
    }
    DetailsContent {
        title: format!("Policies ({})", names.len()),
        lines,
    }
}

/// Drift workspace: every runtime vs permanent difference across zones,
/// ipsets, and policies, so an operator sees what won't survive a reload.
#[must_use]
pub fn drift_workspace(snapshot: &FirewallSnapshot) -> DetailsContent {
    let mut lines: Vec<(String, String)> = Vec::new();
    let mut differences = 0usize;

    for zone in snapshot.zone_names() {
        match (snapshot.runtime.get(zone), snapshot.permanent.get(zone)) {
            (Some(_), None) => {
                lines.push(line(
                    "zone",
                    format!("{zone} — runtime only (lost on reload)"),
                ));
                differences += 1;
            }
            (None, Some(_)) => {
                lines.push(line(
                    "zone",
                    format!("{zone} — permanent only (reload to activate)"),
                ));
                differences += 1;
            }
            (Some(runtime), Some(permanent)) => {
                let group = zone_drift_lines(zone, runtime, permanent);
                if !group.is_empty() {
                    differences += group.len();
                    lines.push((zone.to_string(), String::new()));
                    lines.extend(group);
                }
            }
            (None, None) => {}
        }
    }
    let object_drift = scoped_object_drift_lines(snapshot);
    differences += object_drift.len();
    lines.extend(object_drift);

    if differences == 0 {
        let complete = [
            crate::domain::SnapshotSection::Zones,
            crate::domain::SnapshotSection::IpSets,
            crate::domain::SnapshotSection::Policies,
        ]
        .into_iter()
        .all(|section| {
            snapshot.section_is_complete(
                section,
                crate::domain::ConfigurationTarget::RuntimeAndPermanent,
            )
        });
        lines.push((
            String::new(),
            if complete {
                "runtime and permanent are in sync".to_owned()
            } else {
                "no observed drift, but incomplete sections make sync status unknown".to_owned()
            },
        ));
    }
    DetailsContent {
        title: format!("Drift ({differences} differences)"),
        lines,
    }
}

fn scoped_object_drift_lines(snapshot: &FirewallSnapshot) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    let mut ipsets: Vec<_> = snapshot
        .ipsets
        .runtime
        .keys()
        .chain(snapshot.ipsets.permanent.keys())
        .collect();
    ipsets.sort();
    ipsets.dedup();
    for name in ipsets {
        match (
            snapshot.ipsets.runtime.get(name),
            snapshot.ipsets.permanent.get(name),
        ) {
            (Some(runtime), Some(permanent)) if runtime != permanent => lines.push(line(
                "ipset",
                format!(
                    "{name} — runtime {} ({} entries) / permanent {} ({} entries)",
                    runtime.kind,
                    runtime.entries.len(),
                    permanent.kind,
                    permanent.entries.len()
                ),
            )),
            (Some(_), None) => lines.push(line("ipset", format!("{name} — runtime only"))),
            (None, Some(_)) => lines.push(line("ipset", format!("{name} — permanent only"))),
            _ => {}
        }
    }

    let mut policies: Vec<_> = snapshot
        .policies
        .runtime
        .keys()
        .chain(snapshot.policies.permanent.keys())
        .collect();
    policies.sort();
    policies.dedup();
    for name in policies {
        match (
            snapshot.policies.runtime.get(name),
            snapshot.policies.permanent.get(name),
        ) {
            (Some(runtime), Some(permanent)) if !runtime.configuration_eq(permanent) => {
                lines.push(line(
                    "policy",
                    format!(
                        "{name} — runtime {} ({} services) / permanent {} ({} services)",
                        runtime.target.as_str(),
                        runtime.services.len(),
                        permanent.target.as_str(),
                        permanent.services.len()
                    ),
                ));
            }
            (Some(_), None) => lines.push(line("policy", format!("{name} — runtime only"))),
            (None, Some(_)) => lines.push(line("policy", format!("{name} — permanent only"))),
            _ => {}
        }
    }
    lines
}

/// Per-attribute drift lines for one zone present in both scopes.
fn zone_drift_lines(
    zone: &ZoneName,
    runtime: &crate::domain::ZoneDetails,
    permanent: &crate::domain::ZoneDetails,
) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    diff_items(
        &mut lines,
        zone,
        "service",
        &runtime.services,
        &permanent.services,
        ToString::to_string,
    );
    diff_items(
        &mut lines,
        zone,
        "port",
        &runtime.ports,
        &permanent.ports,
        ToString::to_string,
    );
    diff_items(
        &mut lines,
        zone,
        "forward",
        &runtime.forward_ports,
        &permanent.forward_ports,
        forward_desc,
    );
    diff_items(
        &mut lines,
        zone,
        "rich rule",
        &runtime.rich_rules,
        &permanent.rich_rules,
        |r| r.as_str().to_owned(),
    );
    diff_items(
        &mut lines,
        zone,
        "source",
        &runtime.sources,
        &permanent.sources,
        ToString::to_string,
    );
    diff_items(
        &mut lines,
        zone,
        "interface",
        &runtime.interfaces,
        &permanent.interfaces,
        ToString::to_string,
    );
    diff_items(
        &mut lines,
        zone,
        "icmp-block",
        &runtime.icmp_blocks,
        &permanent.icmp_blocks,
        ToString::to_string,
    );
    if runtime.masquerade != permanent.masquerade {
        lines.push((
            format!("{zone} · masquerade"),
            format!(
                "runtime {} / permanent {}",
                yes_no(runtime.masquerade),
                yes_no(permanent.masquerade)
            ),
        ));
    }
    lines
}

/// One `— runtime only` / `— permanent only` line per element present in
/// exactly one scope.
// O(n²) contains scan — zone attribute lists are tiny.
fn diff_items<T: PartialEq>(
    lines: &mut Vec<(String, String)>,
    zone: &ZoneName,
    label: &str,
    runtime: &[T],
    permanent: &[T],
    render: impl Fn(&T) -> String,
) {
    for item in runtime {
        if !permanent.contains(item) {
            lines.push((
                format!("{zone} · {label}"),
                format!("{} — runtime only", render(item)),
            ));
        }
    }
    for item in permanent {
        if !runtime.contains(item) {
            lines.push((
                format!("{zone} · {label}"),
                format!("{} — permanent only", render(item)),
            ));
        }
    }
}

/// The full service catalog with ports for any cached definition.
#[must_use]
pub fn service_catalog(snapshot: &FirewallSnapshot) -> DetailsContent {
    let lines: Vec<(String, String)> = snapshot
        .available_services
        .iter()
        .map(|service| {
            let ports = snapshot
                .service_definitions
                .get(service)
                .map(|def| join(&def.ports))
                .filter(|ports| ports != "-")
                .unwrap_or_default();
            (service.to_string(), ports)
        })
        .collect();
    DetailsContent {
        title: format!("Service catalog ({})", snapshot.available_services.len()),
        lines,
    }
}

/// Backend error diagnostics with a category-specific recovery hint.
#[must_use]
pub fn for_error(error: &FirewallError) -> DetailsContent {
    let mut lines = vec![line("error", error.to_string())];
    if let FirewallError::CommandFailed { code, stderr } = error {
        lines.push(line("exit code", code.to_string()));
        lines.push(line("stderr", stderr.clone()));
    }
    lines.push(line("suggested", recovery_hint(error)));
    DetailsContent {
        title: "Backend error".to_owned(),
        lines,
    }
}

fn recovery_hint(error: &FirewallError) -> &'static str {
    match error {
        FirewallError::NotInstalled => "install firewalld (e.g. `dnf install firewalld`)",
        FirewallError::DaemonNotRunning => "start the daemon: `systemctl start firewalld`",
        FirewallError::PermissionDenied { .. } => {
            "run fwdeck as root, or configure a polkit rule for your user"
        }
        FirewallError::Timeout(_) => {
            "check daemon health: `systemctl status firewalld` (D-Bus may be stuck)"
        }
        FirewallError::Parse(_) => {
            "possibly an unsupported firewalld version — check the log file and report"
        }
        FirewallError::CommandFailed { .. } | FirewallError::Process(_) => {
            "inspect ~/.local/state/fwdeck/fwdeck.log for the full command context"
        }
        FirewallError::ReadOnlyMode => "restart fwdeck without --read-only to allow mutations",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::domain::mock;

    #[test]
    fn zone_details_include_drift_and_rules() {
        let snapshot = mock::sample().unwrap();
        let zone = snapshot.default_zone.clone();
        let content = for_zone(&snapshot, &zone).unwrap();
        assert!(content.title.contains("public"));
        let state_line = content.lines.iter().find(|(k, _)| k == "state").unwrap();
        assert!(state_line.1.contains("DIFFERENT"));
        assert!(content.lines.iter().any(|(k, _)| k == "rich rule"));
    }

    #[test]
    fn rich_rule_row_resolves_to_the_full_rule() {
        let snapshot = mock::sample().unwrap();
        let zone = snapshot.default_zone.clone();
        let raw = snapshot.runtime[&zone].rich_rules[0].as_str().to_owned();
        let rows = crate::ui::views::rows(
            ViewId::RichRules,
            &snapshot,
            &zone,
            crate::domain::ConfigurationTarget::Runtime,
        );
        let row = rows
            .iter()
            .find(|row| matches!(&row.id, RowId::RichRule { rule, .. } if rule.as_str() == raw))
            .unwrap();
        let content = for_row(ViewId::RichRules, &snapshot, &zone, row).unwrap();
        let rule_line = content.lines.iter().find(|(k, _)| k == "rule").unwrap();
        assert_eq!(rule_line.1, raw);
    }

    #[test]
    fn service_row_details_show_ports_and_protocols_not_a_placeholder() {
        let snapshot = mock::sample().unwrap();
        let zone = snapshot.default_zone.clone();
        let rows = crate::ui::views::rows(
            ViewId::Services,
            &snapshot,
            &zone,
            crate::domain::ConfigurationTarget::Runtime,
        );
        let row = rows.iter().find(|row| row[0] == "https").unwrap();
        let content = for_row(ViewId::Services, &snapshot, &zone, row).unwrap();
        let ports = content.lines.iter().find(|(k, _)| k == "ports").unwrap();
        assert_eq!(ports.1, "443/tcp");
        assert!(content.lines.iter().any(|(k, _)| k == "protocols"));
        assert!(
            !content.lines.iter().any(|(_, v)| v.contains("not shown")),
            "service detail must render real data, never a placeholder"
        );
    }

    #[test]
    fn drift_workspace_lists_runtime_only_drift() {
        let snapshot = mock::sample().unwrap();
        let content = drift_workspace(&snapshot);
        assert!(content.title.starts_with("Drift ("));
        assert!(content.lines.iter().any(|(key, value)| {
            key == "public · service" && value.contains("http") && value.contains("runtime only")
        }));
    }

    #[test]
    fn drift_workspace_flags_permanent_only_zone() {
        let mut snapshot = mock::sample().unwrap();
        let staging = ZoneName::parse("staging").unwrap();
        snapshot
            .permanent
            .insert(staging.clone(), crate::domain::ZoneDetails::empty(staging));
        let content = drift_workspace(&snapshot);
        assert!(content.lines.iter().any(|(key, value)| {
            key == "zone" && value.contains("staging — permanent only (reload to activate)")
        }));
    }

    #[test]
    fn drift_workspace_includes_ipset_entry_drift() {
        let mut snapshot = mock::sample().unwrap();
        let blocklist = crate::domain::IpSetName::parse("blocklist").unwrap();
        snapshot
            .ipsets
            .permanent
            .get_mut(&blocklist)
            .unwrap()
            .entries
            .clear();
        let content = drift_workspace(&snapshot);
        assert!(content.lines.iter().any(|(key, value)| {
            key == "ipset" && value.contains("blocklist") && value.contains("runtime")
        }));
    }

    #[test]
    fn drift_workspace_reports_sync_when_identical() {
        let mut snapshot = mock::sample().unwrap();
        snapshot.permanent = snapshot.runtime.clone();
        let content = drift_workspace(&snapshot);
        assert_eq!(content.title, "Drift (0 differences)");
        assert_eq!(
            content.lines,
            vec![(
                String::new(),
                "runtime and permanent are in sync".to_owned()
            )]
        );
    }

    #[test]
    fn error_details_carry_recovery_hints() {
        let content = for_error(&FirewallError::DaemonNotRunning);
        let hint = content
            .lines
            .iter()
            .find(|(k, _)| k == "suggested")
            .unwrap();
        assert!(hint.1.contains("systemctl start firewalld"));
    }

    #[test]
    fn policy_row_details_show_flow_state_and_dependencies() {
        let snapshot = mock::sample().unwrap();
        let zone = snapshot.default_zone.clone();
        let rows = crate::ui::views::rows(
            ViewId::Policies,
            &snapshot,
            &zone,
            crate::domain::ConfigurationTarget::Runtime,
        );
        let row = rows.first().unwrap();
        let content = for_row(ViewId::Policies, &snapshot, &zone, row).unwrap();

        assert_eq!(content.title, "Policy `mypolicy`");
        assert!(
            content
                .lines
                .iter()
                .any(|(key, value)| { key == "flow" && value == "public → ANY" })
        );
        assert!(
            content
                .lines
                .iter()
                .any(|(key, value)| { key == "dependencies" && value.contains("all referenced") })
        );
    }
}
