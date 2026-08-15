//! The single place `firewall-cmd` invocations are constructed. Arguments are
//! static or come from validated domain newtypes — never raw user input.

use std::time::Duration;

use crate::domain::{ConfigurationTarget, DirectPolicyMigration, FirewallOperation};
use crate::infrastructure::process::{CommandRequest, DEFAULT_TIMEOUT};

/// The firewalld client binary (resolved from trusted dirs at spawn time).
pub const PROGRAM: &str = "firewall-cmd";
/// The offline client — edits permanent config without a running daemon.
pub const OFFLINE_PROGRAM: &str = "firewall-offline-cmd";

/// Live daemon vs offline (`firewall-offline-cmd`, permanent config only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendMode {
    /// Talk to the running daemon via `firewall-cmd`.
    Live,
    /// No daemon: `firewall-offline-cmd`, permanent config only.
    Offline,
}

impl BackendMode {
    /// The client binary this mode invokes.
    #[must_use]
    pub const fn program(self) -> &'static str {
        match self {
            Self::Live => PROGRAM,
            Self::Offline => OFFLINE_PROGRAM,
        }
    }
}

/// Export format for a staged plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// Runnable `firewall-cmd` bash script, shell-quoted per argument.
    Script,
    /// JSON array of `{description, target, commands}` entries.
    Json,
    /// Ansible playbook: `ansible.posix.firewalld` tasks where the module can
    /// express the operation, exact `firewall-cmd` command tasks otherwise.
    Ansible,
}

impl ExportFormat {
    /// File extension for this format (`sh` / `json` / `yml`).
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Script => "sh",
            Self::Json => "json",
            Self::Ansible => "yml",
        }
    }

    /// Renders `operations` in this format (see the per-format exporters).
    #[must_use]
    pub fn render(self, operations: &[crate::domain::FirewallOperation]) -> String {
        match self {
            Self::Script => export_script(operations),
            Self::Json => export_json(operations),
            Self::Ansible => export_ansible(operations),
        }
    }
}

/// Builds a `firewall-cmd` invocation with the given args and timeout.
#[must_use]
pub fn request(args: &[&str], timeout: Duration) -> CommandRequest {
    request_with(PROGRAM, args, timeout)
}

/// Builds an invocation for an explicit program (live or offline client).
#[must_use]
pub fn request_with(program: &'static str, args: &[&str], timeout: Duration) -> CommandRequest {
    CommandRequest {
        program,
        args: args.iter().map(|&a| a.to_owned()).collect(),
        timeout,
    }
}

/// One step of an operation plan: which configuration it touches plus the
/// exact invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedCommand {
    /// Which configuration the step touches: `"runtime"`, `"permanent"`,
    /// `"global"`, or `"offline"`.
    pub target: &'static str,
    /// The exact invocation to execute.
    pub request: CommandRequest,
}

/// Translates a typed operation into firewall-cmd invocations. Live mode issues
/// runtime-first (ADR-3); offline mode issues a single permanent-only command
/// via `firewall-offline-cmd` (there is no runtime when the daemon is down).
#[allow(clippy::too_many_lines)] // one arm per operation
#[must_use]
pub fn plan(operation: &FirewallOperation, timeout: Duration) -> Vec<PlannedCommand> {
    plan_in(operation, timeout, BackendMode::Live)
}

/// [`plan`] with an explicit [`BackendMode`]. Offline plans that come back
/// empty mean "no offline equivalent" — the backend reports that as a failed
/// step rather than executing nothing silently.
#[allow(clippy::too_many_lines)] // one arm per operation
#[must_use]
pub fn plan_in(
    operation: &FirewallOperation,
    timeout: Duration,
    mode: BackendMode,
) -> Vec<PlannedCommand> {
    if mode == BackendMode::Offline {
        return offline_plan(operation, timeout);
    }
    match operation {
        FirewallOperation::AddTemporaryService {
            zone,
            service,
            seconds,
        } => vec![PlannedCommand {
            target: "runtime",
            request: request(
                &[
                    &format!("--zone={zone}"),
                    &format!("--add-service={service}"),
                    &format!("--timeout={seconds}s"),
                ],
                timeout,
            ),
        }],
        FirewallOperation::AddService {
            zone,
            service,
            target,
        } => zone_op(
            zone.as_str(),
            &format!("--add-service={service}"),
            *target,
            timeout,
        ),
        FirewallOperation::RemoveService {
            zone,
            service,
            target,
        } => zone_op(
            zone.as_str(),
            &format!("--remove-service={service}"),
            *target,
            timeout,
        ),
        FirewallOperation::AddPort { zone, port, target } => zone_op(
            zone.as_str(),
            &format!("--add-port={port}"),
            *target,
            timeout,
        ),
        FirewallOperation::RemovePort { zone, port, target } => zone_op(
            zone.as_str(),
            &format!("--remove-port={port}"),
            *target,
            timeout,
        ),
        FirewallOperation::SetMasquerade {
            zone,
            enabled,
            target,
        } => zone_op(
            zone.as_str(),
            if *enabled {
                "--add-masquerade"
            } else {
                "--remove-masquerade"
            },
            *target,
            timeout,
        ),
        FirewallOperation::SetForward {
            zone,
            enabled,
            target,
        } => zone_op(
            zone.as_str(),
            if *enabled {
                "--add-forward"
            } else {
                "--remove-forward"
            },
            *target,
            timeout,
        ),
        FirewallOperation::SetIcmpBlockInversion {
            zone,
            enabled,
            target,
        } => zone_op(
            zone.as_str(),
            if *enabled {
                "--add-icmp-block-inversion"
            } else {
                "--remove-icmp-block-inversion"
            },
            *target,
            timeout,
        ),
        FirewallOperation::AddSourcePort { zone, port, target } => zone_op(
            zone.as_str(),
            &format!("--add-source-port={port}"),
            *target,
            timeout,
        ),
        FirewallOperation::RemoveSourcePort { zone, port, target } => zone_op(
            zone.as_str(),
            &format!("--remove-source-port={port}"),
            *target,
            timeout,
        ),
        FirewallOperation::AddProtocol {
            zone,
            protocol,
            target,
        } => zone_op(
            zone.as_str(),
            &format!("--add-protocol={protocol}"),
            *target,
            timeout,
        ),
        FirewallOperation::RemoveProtocol {
            zone,
            protocol,
            target,
        } => zone_op(
            zone.as_str(),
            &format!("--remove-protocol={protocol}"),
            *target,
            timeout,
        ),
        FirewallOperation::SetZoneTarget { zone, zone_target } => permanent_op(
            &[
                &format!("--zone={zone}"),
                &format!("--set-target={}", zone_target.as_str()),
            ],
            timeout,
        ),
        FirewallOperation::AddForwardPort {
            zone,
            forward,
            target,
        } => zone_op(
            zone.as_str(),
            &format!("--add-forward-port={}", forward.spec_string()),
            *target,
            timeout,
        ),
        FirewallOperation::RemoveForwardPort {
            zone,
            forward,
            target,
        } => zone_op(
            zone.as_str(),
            &format!("--remove-forward-port={}", forward.spec_string()),
            *target,
            timeout,
        ),
        FirewallOperation::AddRichRule { zone, rule, target } => zone_op(
            zone.as_str(),
            &format!("--add-rich-rule={}", rule.as_str()),
            *target,
            timeout,
        ),
        FirewallOperation::RemoveRichRule { zone, rule, target } => zone_op(
            zone.as_str(),
            &format!("--remove-rich-rule={}", rule.as_str()),
            *target,
            timeout,
        ),
        FirewallOperation::AddInterface {
            zone,
            interface,
            target,
        } => zone_op(
            zone.as_str(),
            &format!("--add-interface={interface}"),
            *target,
            timeout,
        ),
        FirewallOperation::RemoveInterface {
            zone,
            interface,
            target,
        } => zone_op(
            zone.as_str(),
            &format!("--remove-interface={interface}"),
            *target,
            timeout,
        ),
        FirewallOperation::AddSource {
            zone,
            source,
            target,
        } => zone_op(
            zone.as_str(),
            &format!("--add-source={source}"),
            *target,
            timeout,
        ),
        FirewallOperation::RemoveSource {
            zone,
            source,
            target,
        } => zone_op(
            zone.as_str(),
            &format!("--remove-source={source}"),
            *target,
            timeout,
        ),
        FirewallOperation::CreateService { service } => {
            permanent_op(&[&format!("--new-service={service}")], timeout)
        }
        FirewallOperation::DeleteService { service } => {
            permanent_op(&[&format!("--delete-service={service}")], timeout)
        }
        FirewallOperation::AddServicePort { service, port } => permanent_op(
            &[
                &format!("--service={service}"),
                &format!("--add-port={port}"),
            ],
            timeout,
        ),
        FirewallOperation::RemoveServicePort { service, port } => permanent_op(
            &[
                &format!("--service={service}"),
                &format!("--remove-port={port}"),
            ],
            timeout,
        ),
        FirewallOperation::CreatePolicy { policy } => {
            permanent_op(&[&format!("--new-policy={policy}")], timeout)
        }
        FirewallOperation::MigrateDirectRule { migration } => {
            direct_policy_migration(migration, timeout)
        }
        FirewallOperation::DeletePolicy { policy } => {
            permanent_op(&[&format!("--delete-policy={policy}")], timeout)
        }
        FirewallOperation::SetPolicyTarget {
            policy,
            policy_target,
        } => permanent_op(
            &[
                &format!("--policy={policy}"),
                &format!("--set-target={}", policy_target.as_str()),
            ],
            timeout,
        ),
        FirewallOperation::AddPolicyIngressZone { policy, zone } => permanent_op(
            &[
                &format!("--policy={policy}"),
                &format!("--add-ingress-zone={zone}"),
            ],
            timeout,
        ),
        FirewallOperation::AddPolicyEgressZone { policy, zone } => permanent_op(
            &[
                &format!("--policy={policy}"),
                &format!("--add-egress-zone={zone}"),
            ],
            timeout,
        ),
        FirewallOperation::AddPolicyService {
            policy,
            service,
            target,
        } => policy_op(
            policy.as_str(),
            &format!("--add-service={service}"),
            *target,
            timeout,
        ),
        FirewallOperation::RemovePolicyService {
            policy,
            service,
            target,
        } => policy_op(
            policy.as_str(),
            &format!("--remove-service={service}"),
            *target,
            timeout,
        ),
        FirewallOperation::SetPolicySetEnabled {
            policy_set,
            enabled,
            target,
        } => policy_set_op(
            policy_set.as_str(),
            if *enabled {
                "--remove-disable"
            } else {
                "--add-disable"
            },
            *target,
            timeout,
        ),
        FirewallOperation::CreateIpSet { name, kind } => permanent_op(
            &[&format!("--new-ipset={name}"), &format!("--type={kind}")],
            timeout,
        ),
        FirewallOperation::DeleteIpSet { name } => {
            permanent_op(&[&format!("--delete-ipset={name}")], timeout)
        }
        FirewallOperation::AddIpSetEntry {
            name,
            entry,
            target,
        } => ipset_entry_op(
            name.as_str(),
            &format!("--add-entry={entry}"),
            *target,
            timeout,
        ),
        FirewallOperation::RemoveIpSetEntry {
            name,
            entry,
            target,
        } => ipset_entry_op(
            name.as_str(),
            &format!("--remove-entry={entry}"),
            *target,
            timeout,
        ),
        FirewallOperation::CreateZone { zone } => {
            permanent_op(&[&format!("--new-zone={zone}")], timeout)
        }
        FirewallOperation::DeleteZone { zone } => {
            permanent_op(&[&format!("--delete-zone={zone}")], timeout)
        }
        FirewallOperation::AddIcmpBlock { zone, icmp, target } => zone_op(
            zone.as_str(),
            &format!("--add-icmp-block={icmp}"),
            *target,
            timeout,
        ),
        FirewallOperation::RemoveIcmpBlock { zone, icmp, target } => zone_op(
            zone.as_str(),
            &format!("--remove-icmp-block={icmp}"),
            *target,
            timeout,
        ),
        FirewallOperation::SetPanicMode { enabled } => vec![PlannedCommand {
            target: "runtime",
            request: request(
                &[if *enabled {
                    "--panic-on"
                } else {
                    "--panic-off"
                }],
                timeout,
            ),
        }],
        FirewallOperation::RuntimeToPermanent => vec![PlannedCommand {
            target: "permanent",
            request: request(&["--runtime-to-permanent"], timeout),
        }],
        FirewallOperation::SetLogDenied { value } => vec![PlannedCommand {
            target: "global",
            request: request(&[&format!("--set-log-denied={}", value.as_str())], timeout),
        }],
        FirewallOperation::SetDefaultZone { zone } => vec![PlannedCommand {
            target: "global",
            request: request(&[&format!("--set-default-zone={zone}")], timeout),
        }],
        FirewallOperation::Reload => vec![PlannedCommand {
            target: "global",
            request: request(&["--reload"], timeout),
        }],
    }
}

/// Renders operations as a runnable `firewall-cmd` script (the exact argv each
/// operation would issue). Deterministic and shell-safe: every argument is a
/// separate single-quoted token, so embedded quotes in rich rules survive.
#[must_use]
pub fn export_script(operations: &[FirewallOperation]) -> String {
    use std::fmt::Write as _;
    let mut out = String::from("#!/usr/bin/env bash\n");
    out.push_str("# Generated by fwdeck — review before running.\nset -euo pipefail\n\n");
    for operation in operations {
        let _ = writeln!(out, "# {}", operation.describe());
        for step in plan(operation, DEFAULT_TIMEOUT) {
            out.push_str(PROGRAM);
            for arg in &step.request.args {
                out.push(' ');
                out.push_str(&shell_quote(arg));
            }
            out.push('\n');
        }
        out.push('\n');
    }
    out
}

/// Renders operations as a JSON array of `{description, target, commands}`.
#[must_use]
pub fn export_json(operations: &[FirewallOperation]) -> String {
    let entries: Vec<serde_json::Value> = operations
        .iter()
        .map(|operation| {
            let commands: Vec<Vec<String>> = plan(operation, DEFAULT_TIMEOUT)
                .into_iter()
                .map(|step| {
                    std::iter::once(PROGRAM.to_owned())
                        .chain(step.request.args)
                        .collect()
                })
                .collect();
            serde_json::json!({
                "description": operation.describe(),
                "target": operation.target().label(),
                "commands": commands,
            })
        })
        .collect();
    serde_json::to_string_pretty(&entries).unwrap_or_else(|_| "[]".to_owned())
}

/// Renders operations as an Ansible playbook. Operations
/// `ansible.posix.firewalld` can express become module tasks; every other
/// operation becomes an `ansible.builtin.command` task carrying the exact
/// `firewall-cmd` argv from [`plan`], so the export is lossless — nothing
/// degrades to a comment.
#[must_use]
pub fn export_ansible(operations: &[FirewallOperation]) -> String {
    use std::fmt::Write as _;
    let mut out = String::from(
        "# Generated by fwdeck — review before running.\n\
# The play targets `hosts: all` with `become: true`; narrow it to your inventory.\n\
- name: Apply fwdeck firewall plan\n  hosts: all\n  become: true\n  tasks:\n",
    );
    for operation in operations {
        match ansible_task(operation) {
            Some(task) => {
                let _ = writeln!(out, "    - name: {}", yaml_quote(&operation.describe()));
                out.push_str(&task);
            }
            None => ansible_command_tasks(operation, &mut out),
        }
    }
    out
}

/// The `ansible.posix.firewalld` module body for one operation, or `None` when
/// the module cannot express it (those fall back to [`ansible_command_tasks`]).
/// `permanent:`/`immediate:` derive from the operation's target; `state:` is
/// `enabled`/`disabled` for rule edits and `present`/`absent` for zone
/// lifecycle.
fn ansible_task(operation: &FirewallOperation) -> Option<String> {
    use std::fmt::Write as _;
    let target = operation.target();
    let permanent = matches!(
        target,
        ConfigurationTarget::Permanent | ConfigurationTarget::RuntimeAndPermanent
    );
    let immediate = matches!(
        target,
        ConfigurationTarget::Runtime | ConfigurationTarget::RuntimeAndPermanent
    );
    let mut body = String::from("      ansible.posix.firewalld:\n");
    let mut kv = |key: &str, value: &str| {
        let _ = writeln!(body, "        {key}: {value}");
    };
    let (field, value, state) = match operation {
        FirewallOperation::AddService { zone, service, .. } => {
            kv("zone", zone.as_str());
            ("service", service.to_string(), "enabled")
        }
        FirewallOperation::RemoveService { zone, service, .. } => {
            kv("zone", zone.as_str());
            ("service", service.to_string(), "disabled")
        }
        FirewallOperation::AddPort { zone, port, .. } => {
            kv("zone", zone.as_str());
            ("port", port.to_string(), "enabled")
        }
        FirewallOperation::RemovePort { zone, port, .. } => {
            kv("zone", zone.as_str());
            ("port", port.to_string(), "disabled")
        }
        FirewallOperation::AddSource { zone, source, .. } => {
            kv("zone", zone.as_str());
            ("source", source.to_string(), "enabled")
        }
        FirewallOperation::RemoveSource { zone, source, .. } => {
            kv("zone", zone.as_str());
            ("source", source.to_string(), "disabled")
        }
        FirewallOperation::AddInterface {
            zone, interface, ..
        } => {
            kv("zone", zone.as_str());
            ("interface", interface.to_string(), "enabled")
        }
        FirewallOperation::RemoveInterface {
            zone, interface, ..
        } => {
            kv("zone", zone.as_str());
            ("interface", interface.to_string(), "disabled")
        }
        FirewallOperation::AddRichRule { zone, rule, .. } => {
            kv("zone", zone.as_str());
            ("rich_rule", yaml_quote(rule.as_str()), "enabled")
        }
        FirewallOperation::RemoveRichRule { zone, rule, .. } => {
            kv("zone", zone.as_str());
            ("rich_rule", yaml_quote(rule.as_str()), "disabled")
        }
        FirewallOperation::AddIcmpBlock { zone, icmp, .. } => {
            kv("zone", zone.as_str());
            ("icmp_block", icmp.to_string(), "enabled")
        }
        FirewallOperation::RemoveIcmpBlock { zone, icmp, .. } => {
            kv("zone", zone.as_str());
            ("icmp_block", icmp.to_string(), "disabled")
        }
        FirewallOperation::SetMasquerade { zone, enabled, .. } => {
            kv("zone", zone.as_str());
            (
                "masquerade",
                "yes".to_owned(),
                if *enabled { "enabled" } else { "disabled" },
            )
        }
        FirewallOperation::CreateZone { zone } => ("zone", zone.to_string(), "present"),
        FirewallOperation::DeleteZone { zone } => ("zone", zone.to_string(), "absent"),
        _ => return None,
    };
    kv(field, &value);
    kv("state", state);
    kv("permanent", if permanent { "true" } else { "false" });
    kv("immediate", if immediate { "true" } else { "false" });
    Some(body)
}

/// Lossless fallback for operations `ansible.posix.firewalld` cannot express
/// (ipsets, policies, service definitions, global switches): one
/// `ansible.builtin.command` task per planned invocation, with the exact argv
/// from [`plan`] so the export can never drift from the live backend. Names
/// carry a `# review:` prefix to flag raw commands for operator review.
fn ansible_command_tasks(operation: &FirewallOperation, out: &mut String) {
    use std::fmt::Write as _;
    for step in plan(operation, DEFAULT_TIMEOUT) {
        let name = format!("# review: {} ({})", operation.describe(), step.target);
        let _ = writeln!(out, "    - name: {}", yaml_quote(&name));
        out.push_str("      ansible.builtin.command:\n        argv:\n");
        let _ = writeln!(out, "          - {PROGRAM}");
        for arg in &step.request.args {
            let _ = writeln!(out, "          - {}", yaml_quote(arg));
        }
        out.push_str("      changed_when: true\n");
    }
}

/// YAML single-quoted scalar: wraps in `'…'`, doubling embedded single quotes.
/// Keeps colons, backticks, and rich-rule quotes from breaking the document.
fn yaml_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// POSIX single-quote quoting: wrap in `'…'`, escaping embedded quotes as `'\''`.
fn shell_quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'=' | b'.' | b'/' | b':')
        })
    {
        return arg.to_owned();
    }
    format!("'{}'", arg.replace('\'', "'\\''"))
}

/// Offline plan: reuse the live plan's argv, then rewrite each step to the
/// offline program and strip the `--permanent` prefix (offline is inherently
/// permanent). Runtime-only operations (panic mode) have no offline meaning and
/// yield an empty plan, which the backend reports as unsupported.
fn offline_plan(operation: &FirewallOperation, timeout: Duration) -> Vec<PlannedCommand> {
    // Daemon-only operations: panic mode toggles kernel state, reload and
    // runtime-to-permanent need a running daemon. No offline equivalent.
    if matches!(
        operation,
        FirewallOperation::SetPanicMode { .. }
            | FirewallOperation::Reload
            | FirewallOperation::RuntimeToPermanent
    ) {
        return Vec::new();
    }
    // There is no runtime when the daemon is down: an explicitly
    // runtime-targeted edit must fail loudly, not silently become a permanent
    // change the operator never asked for.
    if operation.target() == ConfigurationTarget::Runtime {
        return Vec::new();
    }
    // Take the permanent variant of the live plan (last step is permanent when
    // both are issued), then strip `--permanent`.
    let live = plan_in(operation, timeout, BackendMode::Live);
    let Some(step) = live.into_iter().next_back() else {
        return Vec::new();
    };
    let args: Vec<String> = step
        .request
        .args
        .into_iter()
        .filter(|arg| arg != "--permanent")
        .collect();
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    vec![PlannedCommand {
        target: "offline",
        request: request_with(OFFLINE_PROGRAM, &arg_refs, timeout),
    }]
}

/// A single permanent-only invocation (`--permanent <args>`), for object
/// lifecycle operations that firewalld only accepts in the permanent config
/// (new/delete zone, service, ipset, policy — reload activates them).
fn permanent_op(args: &[&str], timeout: Duration) -> Vec<PlannedCommand> {
    let mut full = vec!["--permanent"];
    full.extend_from_slice(args);
    vec![PlannedCommand {
        target: "permanent",
        request: request(&full, timeout),
    }]
}

/// Builds the runtime/permanent invocation pair for any scoped firewalld
/// object (`--zone=`, `--policy=`, `--ipset=`). The runtime step always comes
/// first (ADR-3); this is the single place that planning rule lives.
fn scoped_op(
    scope_arg: &str,
    argument: &str,
    target: ConfigurationTarget,
    timeout: Duration,
) -> Vec<PlannedCommand> {
    let runtime = PlannedCommand {
        target: "runtime",
        request: request(&[scope_arg, argument], timeout),
    };
    let permanent = PlannedCommand {
        target: "permanent",
        request: request(&["--permanent", scope_arg, argument], timeout),
    };
    match target {
        ConfigurationTarget::Runtime => vec![runtime],
        ConfigurationTarget::Permanent => vec![permanent],
        ConfigurationTarget::RuntimeAndPermanent => vec![runtime, permanent],
    }
}

/// Zone-scoped operation (`--zone=<zone> <argument>`).
fn zone_op(
    zone: &str,
    argument: &str,
    target: ConfigurationTarget,
    timeout: Duration,
) -> Vec<PlannedCommand> {
    scoped_op(&format!("--zone={zone}"), argument, target, timeout)
}

/// Policy-scoped operation (`--policy=<name> <argument>`).
fn policy_op(
    policy: &str,
    argument: &str,
    target: ConfigurationTarget,
    timeout: Duration,
) -> Vec<PlannedCommand> {
    scoped_op(&format!("--policy={policy}"), argument, target, timeout)
}

/// Policy-set operation (`--policy-set=<name> <argument>`).
fn policy_set_op(
    policy_set: &str,
    argument: &str,
    target: ConfigurationTarget,
    timeout: Duration,
) -> Vec<PlannedCommand> {
    scoped_op(
        &format!("--policy-set={policy_set}"),
        argument,
        target,
        timeout,
    )
}

/// Additive direct-rule migration: build the complete permanent policy while
/// leaving the legacy rule in place for post-reload verification.
fn direct_policy_migration(
    migration: &DirectPolicyMigration,
    timeout: Duration,
) -> Vec<PlannedCommand> {
    [
        vec![format!("--new-policy={}", migration.policy())],
        vec![
            format!("--policy={}", migration.policy()),
            format!("--add-ingress-zone={}", migration.ingress_zone()),
        ],
        vec![
            format!("--policy={}", migration.policy()),
            format!("--add-egress-zone={}", migration.egress_zone()),
        ],
        vec![
            format!("--policy={}", migration.policy()),
            format!("--add-rich-rule={}", migration.rich_rule().as_str()),
        ],
    ]
    .into_iter()
    .map(|args| PlannedCommand {
        target: "permanent",
        request: request_with_owned(PROGRAM, "--permanent", args, timeout),
    })
    .collect()
}

fn request_with_owned(
    program: &'static str,
    prefix: &str,
    args: Vec<String>,
    timeout: Duration,
) -> CommandRequest {
    CommandRequest {
        program,
        args: std::iter::once(prefix.to_owned()).chain(args).collect(),
        timeout,
    }
}

/// IP-set-scoped operation (`--ipset=<name> <argument>`).
fn ipset_entry_op(
    name: &str,
    argument: &str,
    target: ConfigurationTarget,
    timeout: Duration,
) -> Vec<PlannedCommand> {
    scoped_op(&format!("--ipset={name}"), argument, target, timeout)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::domain::{PolicyName, PolicySetName, ServiceName, ZoneName, translate_direct_rule};
    use crate::infrastructure::process::DEFAULT_TIMEOUT;

    fn args_of(planned: &[PlannedCommand]) -> Vec<Vec<String>> {
        planned.iter().map(|p| p.request.args.clone()).collect()
    }

    #[test]
    fn both_target_plans_runtime_then_permanent() {
        let operation = FirewallOperation::AddService {
            zone: ZoneName::parse("public").unwrap(),
            service: ServiceName::parse("https").unwrap(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        let planned = plan(&operation, DEFAULT_TIMEOUT);
        assert_eq!(
            args_of(&planned),
            vec![
                vec!["--zone=public".to_owned(), "--add-service=https".to_owned()],
                vec![
                    "--permanent".to_owned(),
                    "--zone=public".to_owned(),
                    "--add-service=https".to_owned(),
                ],
            ]
        );
        assert_eq!(planned[0].target, "runtime");
        assert_eq!(planned[1].target, "permanent");
    }

    #[test]
    fn single_targets_plan_one_command() {
        let operation = FirewallOperation::RemovePort {
            zone: ZoneName::parse("dmz").unwrap(),
            port: "8080/tcp".parse().unwrap(),
            target: ConfigurationTarget::Runtime,
        };
        let planned = plan(&operation, DEFAULT_TIMEOUT);
        assert_eq!(
            args_of(&planned),
            vec![vec![
                "--zone=dmz".to_owned(),
                "--remove-port=8080/tcp".to_owned()
            ]]
        );
    }

    #[test]
    fn policy_set_plans_runtime_then_permanent_with_documented_argv() {
        let operation = FirewallOperation::SetPolicySetEnabled {
            policy_set: PolicySetName::parse("gateway").unwrap(),
            enabled: true,
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        assert_eq!(
            args_of(&plan(&operation, DEFAULT_TIMEOUT)),
            vec![
                vec![
                    "--policy-set=gateway".to_owned(),
                    "--remove-disable".to_owned(),
                ],
                vec![
                    "--permanent".to_owned(),
                    "--policy-set=gateway".to_owned(),
                    "--remove-disable".to_owned(),
                ],
            ]
        );

        let disable = FirewallOperation::SetPolicySetEnabled {
            policy_set: PolicySetName::parse("gateway").unwrap(),
            enabled: false,
            target: ConfigurationTarget::Permanent,
        };
        assert_eq!(
            args_of(&plan(&disable, DEFAULT_TIMEOUT)),
            vec![vec![
                "--permanent".to_owned(),
                "--policy-set=gateway".to_owned(),
                "--add-disable".to_owned(),
            ]]
        );
    }

    #[test]
    fn direct_migration_plans_complete_additive_policy() {
        let migration = translate_direct_rule("ipv4 filter INPUT 9 -p tcp --dport 12345 -j ACCEPT")
            .unwrap()
            .into_migration(PolicyName::parse_user_created("direct-web").unwrap());
        let operation = FirewallOperation::MigrateDirectRule { migration };
        assert_eq!(
            args_of(&plan(&operation, DEFAULT_TIMEOUT)),
            vec![
                vec![
                    "--permanent".to_owned(),
                    "--new-policy=direct-web".to_owned()
                ],
                vec![
                    "--permanent".to_owned(),
                    "--policy=direct-web".to_owned(),
                    "--add-ingress-zone=ANY".to_owned(),
                ],
                vec![
                    "--permanent".to_owned(),
                    "--policy=direct-web".to_owned(),
                    "--add-egress-zone=HOST".to_owned(),
                ],
                vec![
                    "--permanent".to_owned(),
                    "--policy=direct-web".to_owned(),
                    concat!(
                        "--add-rich-rule=rule priority=\"9\" family=\"ipv4\" ",
                        "port port=\"12345\" protocol=\"tcp\" accept"
                    )
                    .to_owned(),
                ],
            ]
        );
    }

    #[test]
    fn parity_operations_build_correct_argv() {
        use crate::domain::{IpProtocol, ZoneTarget};
        let zone = || ZoneName::parse("public").unwrap();
        let rt = ConfigurationTarget::Runtime;

        // Zone target is permanent-only.
        assert_eq!(
            args_of(&plan(
                &FirewallOperation::SetZoneTarget {
                    zone: zone(),
                    zone_target: ZoneTarget::Drop,
                },
                DEFAULT_TIMEOUT,
            )),
            vec![vec![
                "--permanent".to_owned(),
                "--zone=public".to_owned(),
                "--set-target=DROP".to_owned(),
            ]]
        );
        // Source-port and protocol mirror the port/service shape.
        assert_eq!(
            args_of(&plan(
                &FirewallOperation::AddSourcePort {
                    zone: zone(),
                    port: "68/udp".parse().unwrap(),
                    target: rt,
                },
                DEFAULT_TIMEOUT,
            )),
            vec![vec![
                "--zone=public".to_owned(),
                "--add-source-port=68/udp".to_owned(),
            ]]
        );
        assert_eq!(
            args_of(&plan(
                &FirewallOperation::AddProtocol {
                    zone: zone(),
                    protocol: IpProtocol::parse("gre").unwrap(),
                    target: rt,
                },
                DEFAULT_TIMEOUT,
            )),
            vec![vec![
                "--zone=public".to_owned(),
                "--add-protocol=gre".to_owned(),
            ]]
        );
        // Toggles map to add/remove flags.
        assert_eq!(
            args_of(&plan(
                &FirewallOperation::SetForward {
                    zone: zone(),
                    enabled: true,
                    target: rt,
                },
                DEFAULT_TIMEOUT,
            )),
            vec![vec!["--zone=public".to_owned(), "--add-forward".to_owned()]]
        );
        assert_eq!(
            args_of(&plan(
                &FirewallOperation::SetIcmpBlockInversion {
                    zone: zone(),
                    enabled: false,
                    target: rt,
                },
                DEFAULT_TIMEOUT,
            )),
            vec![vec![
                "--zone=public".to_owned(),
                "--remove-icmp-block-inversion".to_owned(),
            ]]
        );
    }

    #[test]
    fn rich_rule_stays_one_argv_element_verbatim() {
        use crate::domain::RichRule;
        let operation = FirewallOperation::AddRichRule {
            zone: ZoneName::parse("public").unwrap(),
            rule: RichRule::parse(r#"rule family="ipv4" source address="1.2.3.0/24" reject"#)
                .unwrap(),
            target: ConfigurationTarget::Runtime,
        };
        let planned = plan(&operation, DEFAULT_TIMEOUT);
        assert_eq!(
            planned[0].request.args,
            vec![
                "--zone=public".to_owned(),
                r#"--add-rich-rule=rule family="ipv4" source address="1.2.3.0/24" reject"#
                    .to_owned(),
            ],
            "no shell → embedded quotes need no escaping"
        );
    }

    #[test]
    fn export_script_is_shell_safe() {
        use crate::domain::RichRule;
        let ops = vec![FirewallOperation::AddRichRule {
            zone: ZoneName::parse("public").unwrap(),
            rule: RichRule::parse(r#"rule family="ipv4" source address="1.2.3.0/24" reject"#)
                .unwrap(),
            target: ConfigurationTarget::Runtime,
        }];
        let script = export_script(&ops);
        assert!(script.starts_with("#!/usr/bin/env bash"));
        // The rich rule (with spaces + quotes) must be one quoted token.
        assert!(script.contains(
            r#"'--add-rich-rule=rule family="ipv4" source address="1.2.3.0/24" reject'"#
        ));
    }

    #[test]
    fn export_ansible_maps_module_ops_including_zone_lifecycle() {
        let ops = vec![
            FirewallOperation::AddService {
                zone: ZoneName::parse("public").unwrap(),
                service: ServiceName::parse("https").unwrap(),
                target: ConfigurationTarget::RuntimeAndPermanent,
            },
            FirewallOperation::CreateZone {
                zone: ZoneName::parse("staging").unwrap(),
            },
            FirewallOperation::DeleteZone {
                zone: ZoneName::parse("legacy").unwrap(),
            },
        ];
        let yaml = export_ansible(&ops);
        assert!(yaml.contains("ansible.posix.firewalld"));
        assert!(yaml.contains("service: https"));
        assert!(yaml.contains("state: enabled"));
        assert!(yaml.contains("zone: staging"));
        assert!(
            yaml.contains("state: present"),
            "create zone is a real task"
        );
        assert!(yaml.contains("zone: legacy"));
        assert!(yaml.contains("state: absent"), "delete zone is a real task");
        assert!(!yaml.contains("# unsupported"), "no comment-only fallbacks");
    }

    #[test]
    fn export_ansible_scopes_permanent_and_immediate_by_target() {
        let add = |target| FirewallOperation::AddService {
            zone: ZoneName::parse("public").unwrap(),
            service: ServiceName::parse("https").unwrap(),
            target,
        };
        let runtime = export_ansible(&[add(ConfigurationTarget::Runtime)]);
        assert!(runtime.contains("permanent: false"));
        assert!(runtime.contains("immediate: true"));
        let both = export_ansible(&[add(ConfigurationTarget::RuntimeAndPermanent)]);
        assert!(both.contains("permanent: true"));
        assert!(both.contains("immediate: true"));
        let permanent = export_ansible(&[add(ConfigurationTarget::Permanent)]);
        assert!(permanent.contains("permanent: true"));
        assert!(permanent.contains("immediate: false"));
    }

    #[test]
    fn export_ansible_falls_back_to_command_tasks_with_exact_argv() {
        use crate::domain::IpSetName;
        let ops = vec![
            FirewallOperation::CreateIpSet {
                name: IpSetName::parse("blocklist").unwrap(),
                kind: "hash:ip".to_owned(),
            },
            FirewallOperation::SetLogDenied {
                value: crate::domain::LogDenied::All,
            },
        ];
        let yaml = export_ansible(&ops);
        assert!(yaml.contains("ansible.builtin.command"));
        assert!(yaml.contains("- firewall-cmd"));
        assert!(yaml.contains("- '--permanent'"));
        assert!(yaml.contains("- '--new-ipset=blocklist'"));
        assert!(yaml.contains("- '--type=hash:ip'"));
        assert!(yaml.contains("- '--set-log-denied=all'"));
        assert!(yaml.contains("changed_when: true"));
        assert!(yaml.contains("'# review:"), "raw commands are flagged");
        assert!(!yaml.contains("# unsupported"));
    }

    #[test]
    fn export_ansible_is_lossless_and_structurally_sound() {
        use crate::domain::{IpSetName, PolicyName};
        let ops = vec![
            FirewallOperation::AddService {
                zone: ZoneName::parse("public").unwrap(),
                service: ServiceName::parse("https").unwrap(),
                target: ConfigurationTarget::RuntimeAndPermanent,
            },
            FirewallOperation::CreatePolicy {
                policy: PolicyName::parse("edge-to-dmz").unwrap(),
            },
            FirewallOperation::CreateService {
                service: ServiceName::parse("myapp").unwrap(),
            },
            FirewallOperation::DeleteIpSet {
                name: IpSetName::parse("blocklist").unwrap(),
            },
            FirewallOperation::SetDefaultZone {
                zone: ZoneName::parse("home").unwrap(),
            },
            FirewallOperation::SetPanicMode { enabled: true },
            FirewallOperation::RuntimeToPermanent,
            FirewallOperation::Reload,
        ];
        let yaml = export_ansible(&ops);
        assert!(yaml.starts_with("# Generated by fwdeck"));
        assert!(yaml.contains("hosts: all"));
        assert!(yaml.contains("become: true"));
        assert!(yaml.contains("  tasks:\n"));
        // Every operation above plans exactly one invocation (or maps to one
        // module task), so tasks must match operations one-to-one.
        assert_eq!(
            yaml.matches("    - name: ").count(),
            ops.len(),
            "every operation renders as a real task"
        );
        assert!(
            !yaml.contains("# unsupported"),
            "nothing is lost to comments"
        );
    }

    #[test]
    fn export_ansible_command_fallback_emits_one_task_per_planned_step() {
        use crate::domain::{IpSetEntry, IpSetName};
        // AddIpSetEntry has no module mapping; with Both it plans two commands.
        let op = FirewallOperation::AddIpSetEntry {
            name: IpSetName::parse("blocklist").unwrap(),
            entry: IpSetEntry::parse("198.51.100.44").unwrap(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        let yaml = export_ansible(&[op]);
        assert_eq!(yaml.matches("ansible.builtin.command").count(), 2);
        assert!(yaml.contains("(runtime)"), "step scope is in the task name");
        assert!(yaml.contains("(permanent)"));
        assert!(yaml.contains("- '--ipset=blocklist'"));
        assert!(yaml.contains("- '--add-entry=198.51.100.44'"));
    }

    #[test]
    fn export_ansible_quotes_rich_rule_task_names_and_values() {
        use crate::domain::RichRule;
        let op = FirewallOperation::AddRichRule {
            zone: ZoneName::parse("public").unwrap(),
            rule: RichRule::parse(r#"rule family="ipv4" source address="1.2.3.0/24" reject"#)
                .unwrap(),
            target: ConfigurationTarget::Runtime,
        };
        let yaml = export_ansible(&[op]);
        // describe() contains `: ` — the name must be quoted to stay valid YAML.
        assert!(yaml.contains("    - name: 'add rich rule"));
        assert!(
            yaml.contains(r#"rich_rule: 'rule family="ipv4" source address="1.2.3.0/24" reject'"#)
        );
    }

    #[test]
    fn export_json_lists_commands() {
        let ops = vec![FirewallOperation::Reload];
        let json = export_json(&ops);
        assert!(json.contains("\"reload firewalld\""));
        assert!(json.contains("--reload"));
    }

    #[test]
    fn offline_plan_uses_offline_program_without_permanent() {
        use crate::domain::ServiceName;
        let op = FirewallOperation::AddService {
            zone: ZoneName::parse("public").unwrap(),
            service: ServiceName::parse("https").unwrap(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        let planned = plan_in(&op, DEFAULT_TIMEOUT, BackendMode::Offline);
        assert_eq!(planned.len(), 1, "offline is a single command");
        assert_eq!(planned[0].request.program, OFFLINE_PROGRAM);
        assert_eq!(
            planned[0].request.args,
            vec!["--zone=public".to_owned(), "--add-service=https".to_owned()],
            "no --permanent in offline mode"
        );
    }

    #[test]
    fn offline_rejects_runtime_targeted_edits() {
        use crate::domain::ServiceName;
        let op = FirewallOperation::AddService {
            zone: ZoneName::parse("public").unwrap(),
            service: ServiceName::parse("https").unwrap(),
            target: ConfigurationTarget::Runtime,
        };
        assert!(
            plan_in(&op, DEFAULT_TIMEOUT, BackendMode::Offline).is_empty(),
            "a runtime edit must not silently become permanent offline"
        );
    }

    #[test]
    fn daemon_only_operations_have_no_offline_plan() {
        for op in [
            FirewallOperation::SetPanicMode { enabled: true },
            FirewallOperation::Reload,
            FirewallOperation::RuntimeToPermanent,
        ] {
            let planned = plan_in(&op, DEFAULT_TIMEOUT, BackendMode::Offline);
            assert!(planned.is_empty(), "{op:?} has no offline meaning");
        }
    }

    #[test]
    fn ipset_plans() {
        use crate::domain::{IpSetEntry, IpSetName};
        let create = FirewallOperation::CreateIpSet {
            name: IpSetName::parse("blocklist").unwrap(),
            kind: "hash:ip".to_owned(),
        };
        assert_eq!(
            plan(&create, DEFAULT_TIMEOUT)[0].request.args,
            vec![
                "--permanent".to_owned(),
                "--new-ipset=blocklist".to_owned(),
                "--type=hash:ip".to_owned(),
            ]
        );
        let add = FirewallOperation::AddIpSetEntry {
            name: IpSetName::parse("blocklist").unwrap(),
            entry: IpSetEntry::parse("198.51.100.44").unwrap(),
            target: ConfigurationTarget::RuntimeAndPermanent,
        };
        let planned = plan(&add, DEFAULT_TIMEOUT);
        assert_eq!(
            planned[0].request.args,
            vec![
                "--ipset=blocklist".to_owned(),
                "--add-entry=198.51.100.44".to_owned()
            ]
        );
        assert_eq!(planned[1].request.args[0], "--permanent");
    }

    #[test]
    fn zone_lifecycle_plans_are_permanent_only() {
        let create = FirewallOperation::CreateZone {
            zone: ZoneName::parse("staging").unwrap(),
        };
        assert_eq!(
            plan(&create, DEFAULT_TIMEOUT)[0].request.args,
            vec!["--permanent".to_owned(), "--new-zone=staging".to_owned()]
        );
        let delete = FirewallOperation::DeleteZone {
            zone: ZoneName::parse("staging").unwrap(),
        };
        let planned = plan(&delete, DEFAULT_TIMEOUT);
        assert_eq!(planned.len(), 1, "no auto-reload — deliberate");
        assert_eq!(
            planned[0].request.args,
            vec!["--permanent".to_owned(), "--delete-zone=staging".to_owned()]
        );
    }

    #[test]
    fn panic_and_log_denied_plans() {
        assert_eq!(
            plan(
                &FirewallOperation::SetPanicMode { enabled: true },
                DEFAULT_TIMEOUT
            )[0]
            .request
            .args,
            vec!["--panic-on".to_owned()]
        );
        assert_eq!(
            plan(
                &FirewallOperation::SetLogDenied {
                    value: crate::domain::LogDenied::All
                },
                DEFAULT_TIMEOUT
            )[0]
            .request
            .args,
            vec!["--set-log-denied=all".to_owned()]
        );
    }

    #[test]
    fn global_operations_have_single_invocations() {
        assert_eq!(
            args_of(&plan(&FirewallOperation::Reload, DEFAULT_TIMEOUT)),
            vec![vec!["--reload".to_owned()]]
        );
        let set_default = FirewallOperation::SetDefaultZone {
            zone: ZoneName::parse("home").unwrap(),
        };
        assert_eq!(
            args_of(&plan(&set_default, DEFAULT_TIMEOUT)),
            vec![vec!["--set-default-zone=home".to_owned()]]
        );
    }
}
