//! Command palette: typed commands with metadata, context-aware availability,
//! and fuzzy ranking. Every entry carries the `UiAction` it dispatches — there
//! are no display-only strings disconnected from behavior.

use strum::IntoEnumIterator;

use crate::domain::{FirewallOperation, LogDenied};
use crate::infrastructure::firewalld::command::ExportFormat;

use super::action::UiAction;
use super::fuzzy;
use super::overlays::FormKind;
use super::state::UiState;
use super::views::ViewId;

/// Grouping label shown next to each palette entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// View switching and perspective toggles.
    Views,
    /// Commands that read or mutate firewalld itself.
    Firewall,
    /// Application-level commands (help, filters, snapshots, plans).
    App,
}

impl Category {
    /// Short label rendered in the palette row.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Views => "view",
            Self::Firewall => "firewall",
            Self::App => "app",
        }
    }
}

/// Whether a command can execute in the current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    /// The command can be executed.
    Enabled,
    /// The command is blocked, with a human-readable reason.
    Disabled(&'static str),
}

/// A single palette entry: the action it dispatches plus display metadata.
#[derive(Debug, Clone)]
pub struct PaletteCommand {
    /// The action dispatched when this command executes (guarded by
    /// `availability` first).
    pub action: UiAction,
    /// Title shown in the palette list.
    pub title: String,
    /// One-line explanation shown next to the title.
    pub description: &'static str,
    /// Extra fuzzy-match terms beyond the title.
    pub keywords: &'static [&'static str],
    /// Grouping label.
    pub category: Category,
    /// Context-aware availability for the current state.
    pub availability: Availability,
}

/// Palette overlay state (query + selection into the filtered list).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PaletteState {
    /// Current fuzzy-search query.
    pub query: String,
    /// Selected index into the filtered command list.
    pub selected: usize,
}

/// Positional constructor for a catalog entry.
fn cmd(
    action: UiAction,
    title: impl Into<String>,
    description: &'static str,
    keywords: &'static [&'static str],
    category: Category,
    availability: Availability,
) -> PaletteCommand {
    PaletteCommand {
        action,
        title: title.into(),
        description,
        keywords,
        category,
        availability,
    }
}

/// `Enabled` when the condition holds, otherwise `Disabled(reason)`.
const fn gate(enabled: bool, reason: &'static str) -> Availability {
    if enabled {
        Availability::Enabled
    } else {
        Availability::Disabled(reason)
    }
}

/// Context-aware command catalog for the current state.
#[allow(clippy::too_many_lines)] // a flat data table, one call per command
#[must_use]
pub fn catalog(state: &UiState) -> Vec<PaletteCommand> {
    let zone = state
        .effective_zone()
        .map_or_else(|| "-".to_owned(), |z| z.to_string());
    let has_snapshot = state.snapshot.is_some();
    let has_rows = !state.visible_rows().is_empty();

    // One gate for every mutating command.
    let mutable = if state.read_only {
        Availability::Disabled("read-only mode")
    } else if has_snapshot {
        Availability::Enabled
    } else {
        Availability::Disabled("no data yet")
    };
    let with_data = gate(has_snapshot, "no data yet");
    let has_filter = gate(!state.view_state().filter.is_empty(), "no active filter");
    let has_error = gate(state.backend_error.is_some(), "no backend error");
    let staged = gate(!state.staged.is_empty(), "no staged operations");
    // Applying additionally requires write access; report the true blocker.
    let staged_mutable = if state.read_only {
        Availability::Disabled("read-only mode")
    } else {
        staged
    };
    let row_bound = |required_view: ViewId, reason: &'static str| match mutable {
        Availability::Enabled if state.view == required_view && has_rows => Availability::Enabled,
        Availability::Enabled => Availability::Disabled(reason),
        disabled @ Availability::Disabled(_) => disabled,
    };

    let mut commands = vec![
        cmd(
            UiAction::RefreshRequested,
            "Refresh now",
            "Re-read the complete firewalld state",
            &["reload", "update", "sync"],
            Category::Firewall,
            Availability::Enabled,
        ),
        cmd(
            UiAction::InspectZone,
            format!("Inspect zone `{zone}`"),
            "Full details of the selected zone (runtime vs permanent)",
            &["details", "show", "zone"],
            Category::Firewall,
            with_data,
        ),
        cmd(
            UiAction::OpenGlobalSearch,
            "Global search",
            "Fuzzy-search rows across every view at once (ctrl-f)",
            &["find", "search", "all", "global"],
            Category::App,
            Availability::Enabled,
        ),
        cmd(
            UiAction::OpenAbout,
            "About FWDeck",
            "Version, description, developer, and links",
            &["about", "version", "info", "credits", "author"],
            Category::App,
            Availability::Enabled,
        ),
        cmd(
            UiAction::ClearFilter,
            "Clear filter",
            "Remove the active row filter",
            &["search", "reset"],
            Category::App,
            has_filter,
        ),
        cmd(
            UiAction::ShowErrorDetails,
            "Show error details",
            "Inspect the last backend error and how to fix it",
            &["diagnostics", "why", "failed"],
            Category::App,
            has_error,
        ),
        cmd(
            UiAction::OpenHelp,
            "Show help",
            "Keybinding reference",
            &["keys", "bindings", "?"],
            Category::App,
            Availability::Enabled,
        ),
        cmd(
            UiAction::Quit,
            "Quit",
            "Exit fwdeck",
            &["exit", "close", "q"],
            Category::App,
            Availability::Enabled,
        ),
        cmd(
            UiAction::ReloadRequested,
            "Reload firewalld",
            "Reload permanent configuration into runtime",
            &["restart", "apply"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::OpenForm(FormKind::AddService),
            format!("Add service to `{zone}`"),
            "Allow a service in the selected zone",
            &["allow", "enable", "open"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::DeleteEntry,
            "Remove selected service",
            "Remove the selected service from the zone (confirmed)",
            &["deny", "disable", "close", "delete"],
            Category::Firewall,
            row_bound(ViewId::Services, "select a row in the Services view"),
        ),
        cmd(
            UiAction::OpenForm(FormKind::AddPort),
            format!("Add port to `{zone}`"),
            "Open a port or port range in the selected zone",
            &["allow", "open", "tcp", "udp"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::DeleteEntry,
            "Remove selected port",
            "Close the selected port in the zone (confirmed)",
            &["deny", "close", "delete"],
            Category::Firewall,
            row_bound(ViewId::Ports, "select a row in the Ports view"),
        ),
        cmd(
            UiAction::SetDefaultZoneRequested,
            "Set default zone",
            "Make the selected zone the default",
            &["default"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::ToggleMasqueradeRequested,
            "Toggle masquerade",
            "Enable or disable masquerading in the selected zone",
            &["nat", "snat"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::OpenForm(FormKind::SetZoneTarget),
            format!("Set target of `{zone}`"),
            "Set the zone's default policy for unmatched packets (permanent)",
            &["policy", "drop", "reject", "accept", "default"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::ToggleForwardRequested,
            "Toggle intra-zone forwarding",
            "Enable or disable forwarding between this zone's interfaces/sources",
            &["forward", "route"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::ToggleIcmpBlockInversionRequested,
            "Toggle icmp-block inversion",
            "Block all ICMP except the listed types (or revert)",
            &["icmp", "invert", "inversion"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::OpenForm(FormKind::AddSourcePort),
            format!("Add source-port to `{zone}`"),
            "Match traffic by its source port in the selected zone",
            &["source", "sport", "allow"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::OpenForm(FormKind::RemoveSourcePort),
            format!("Remove source-port from `{zone}`"),
            "Remove a source-port match from the selected zone (confirmed)",
            &["source", "sport", "delete"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::OpenForm(FormKind::AddProtocol),
            format!("Allow protocol in `{zone}`"),
            "Allow an IP protocol (gre, esp, igmp, …) in the selected zone",
            &["protocol", "gre", "esp", "vpn"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::OpenForm(FormKind::RemoveProtocol),
            format!("Remove protocol from `{zone}`"),
            "Stop allowing an IP protocol in the selected zone (confirmed)",
            &["protocol", "delete"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::OpenForm(FormKind::AddForwardPort),
            format!("Add forward port to `{zone}`"),
            "Forward a port to another port and/or address",
            &["dnat", "redirect", "portforward"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::DeleteEntry,
            "Remove selected forward port",
            "Remove the selected forward rule (confirmed)",
            &["dnat", "delete"],
            Category::Firewall,
            row_bound(ViewId::Forwarding, "select a row in the Forward view"),
        ),
        cmd(
            UiAction::OpenForm(FormKind::AddRichRule),
            format!("Add rich rule to `{zone}`"),
            "Add a firewalld rich language rule",
            &["rule", "rich"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::OpenRichBuilder,
            format!("Build rich rule for `{zone}` (guided)"),
            "Assemble a rich rule step by step instead of typing raw syntax",
            &["rich", "rule", "wizard", "builder", "guided"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::DeleteEntry,
            "Remove selected rich rule",
            "Remove the selected rich rule (confirmed)",
            &["rule", "delete"],
            Category::Firewall,
            row_bound(ViewId::RichRules, "select a row in the Rich Rules view"),
        ),
        cmd(
            UiAction::OpenForm(FormKind::AddInterface),
            format!("Bind interface to `{zone}`"),
            "Assign a network interface to the selected zone",
            &["nic", "eth"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::DeleteEntry,
            "Unbind selected interface",
            "Remove the selected interface binding (confirmed)",
            &["nic", "delete"],
            Category::Firewall,
            row_bound(ViewId::Interfaces, "select a row in the Interfaces view"),
        ),
        cmd(
            UiAction::OpenForm(FormKind::AddSource),
            format!("Bind source to `{zone}`"),
            "Assign a source address/network to the selected zone",
            &["cidr", "network"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::DeleteEntry,
            "Unbind selected source",
            "Remove the selected source binding (confirmed)",
            &["cidr", "delete"],
            Category::Firewall,
            row_bound(ViewId::Sources, "select a row in the Sources view"),
        ),
        cmd(
            UiAction::OpenForm(FormKind::CreateZone),
            "Create zone",
            "Create a new zone (permanent-only; reload to activate)",
            &["new", "zone"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::DeleteEntry,
            "Delete selected zone",
            "Delete the selected zone (permanent-only, confirmed)",
            &["remove", "zone"],
            Category::Firewall,
            row_bound(ViewId::Zones, "select a row in the Zones view"),
        ),
        cmd(
            UiAction::OpenForm(FormKind::CreateIpSet),
            "Create ipset",
            "Create an IP set (permanent-only; reload to activate)",
            &["ipset", "blocklist", "new"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::DeleteEntry,
            "Delete selected ipset",
            "Delete the selected IP set (permanent-only, confirmed)",
            &["ipset", "remove"],
            Category::Firewall,
            row_bound(ViewId::IpSets, "select a row in the IPSets view"),
        ),
        cmd(
            UiAction::OpenForm(FormKind::AddIpSetEntry),
            "Add entry to selected ipset",
            "Add an address to the selected IP set",
            &["ipset", "entry", "block"],
            Category::Firewall,
            row_bound(ViewId::IpSets, "select a row in the IPSets view"),
        ),
        cmd(
            UiAction::OpenForm(FormKind::RemoveIpSetEntry),
            "Remove entry from selected ipset",
            "Remove an address from the selected IP set",
            &["ipset", "entry", "unblock"],
            Category::Firewall,
            row_bound(ViewId::IpSets, "select a row in the IPSets view"),
        ),
        cmd(
            UiAction::SaveSnapshot,
            "Save configuration snapshot",
            "Write the current firewall state to a JSON snapshot",
            &["snapshot", "backup", "save", "record"],
            Category::App,
            with_data,
        ),
        cmd(
            UiAction::BrowseSnapshots,
            "Browse saved snapshots",
            "List configuration snapshots saved this and prior sessions",
            &["snapshot", "backup", "list"],
            Category::App,
            Availability::Enabled,
        ),
        cmd(
            UiAction::OpenForm(FormKind::RestoreSnapshot),
            "Restore from snapshot",
            "Diff a saved snapshot against the current state and stage a plan",
            &["snapshot", "restore", "revert", "rollback"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::ShowSnapshotDiff,
            "Diff against snapshot",
            "Show a read-only diff of the current state against a saved snapshot",
            &["snapshot", "diff", "compare", "changes"],
            Category::App,
            with_data,
        ),
        cmd(
            UiAction::ShowSessionDiff,
            "Session diff (since startup)",
            "Show what has changed since this session's first snapshot",
            &["diff", "session", "changes", "since"],
            Category::App,
            with_data,
        ),
        cmd(
            UiAction::ShowCounters,
            "Rule-hit counters (live)",
            "Read live nftables per-chain packet/byte counters",
            &["counters", "hits", "traffic", "nft", "stats"],
            Category::Firewall,
            Availability::Enabled,
        ),
        cmd(
            UiAction::OpenForm(FormKind::ExplainTraffic),
            "Explain this traffic",
            "Trace how firewalld treats ingress from <ip> to <port>/<proto>",
            &["explain", "why", "traffic", "blocked", "allowed"],
            Category::Firewall,
            with_data,
        ),
        cmd(
            UiAction::ShowAudit,
            "Show audit log",
            "Operations performed this session (also in audit.jsonl)",
            &["history", "log", "trail"],
            Category::App,
            Availability::Enabled,
        ),
        cmd(
            UiAction::ShowStagedPlan,
            "Show staged plan",
            "Operations staged with `s` in the confirmation dialog",
            &["plan", "staged", "batch"],
            Category::App,
            staged,
        ),
        cmd(
            UiAction::ApplyStagedPlan,
            "Apply staged plan",
            "Execute every staged operation in order",
            &["plan", "commit", "batch"],
            Category::Firewall,
            staged_mutable,
        ),
        cmd(
            UiAction::DiscardStagedPlan,
            "Discard staged plan",
            "Drop every staged operation without applying",
            &["plan", "clear"],
            Category::App,
            staged,
        ),
        cmd(
            UiAction::ExportStagedPlan(ExportFormat::Script),
            "Export staged plan (firewall-cmd)",
            "Write the staged plan as a runnable firewall-cmd script",
            &["export", "script", "save"],
            Category::App,
            staged,
        ),
        cmd(
            UiAction::ExportStagedPlan(ExportFormat::Json),
            "Export staged plan (JSON)",
            "Write the staged plan as a JSON document",
            &["export", "json"],
            Category::App,
            staged,
        ),
        cmd(
            UiAction::ExportStagedPlan(ExportFormat::Ansible),
            "Export staged plan (Ansible)",
            "Write the staged plan as an ansible.posix.firewalld playbook",
            &["export", "ansible", "playbook", "yaml"],
            Category::App,
            staged,
        ),
        cmd(
            UiAction::BrowseServices,
            "Browse service catalog",
            "List every service firewalld knows about, with ports",
            &["catalog", "services", "list", "discover"],
            Category::App,
            with_data,
        ),
        cmd(
            UiAction::OpenForm(FormKind::CreateService),
            "Create custom service",
            "Define a new service (permanent-only; reload to activate)",
            &["custom", "service", "new"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::OpenForm(FormKind::AddServicePort),
            "Add port to a service",
            "Add a port to a custom service definition (permanent)",
            &["service", "port"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::BrowsePolicies,
            "Browse policies",
            "List policy objects (ingress/egress zones, target, rules)",
            &["policy", "policies", "list"],
            Category::App,
            with_data,
        ),
        cmd(
            UiAction::ShowPolicyDependencies,
            "Policy dependency graph",
            "Show scoped zone/service edges and dangling references",
            &["policy", "graph", "dependency", "impact", "reference"],
            Category::Firewall,
            with_data,
        ),
        cmd(
            UiAction::ShowDrift,
            "Drift workspace",
            "Every runtime vs permanent difference across all zones",
            &["drift", "sync", "diff", "reload"],
            Category::Firewall,
            with_data,
        ),
        cmd(
            UiAction::OpenForm(FormKind::AddTemporaryService),
            "Add temporary service (auto-expires)",
            "Allow a service in runtime only, removed automatically after N seconds",
            &["temporary", "timeout", "expire", "service", "trial"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::UndoLastOperation,
            "Undo last operation",
            "Request the inverse of the last verified change (with confirmation)",
            &["undo", "revert", "inverse", "rollback"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::StageDriftSync,
            "Stage drift sync (runtime → permanent)",
            "Stage per-attribute repairs that make permanent match runtime",
            &["drift", "sync", "repair", "persist", "runtime", "permanent"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::OpenForm(FormKind::CreatePolicy),
            "Create policy",
            "Define a new policy object (permanent-only; reload to activate)",
            &["policy", "new"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::OpenForm(FormKind::AddPolicyService),
            "Add service to policy",
            "Allow a service in a policy object",
            &["policy", "service"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::OpenForm(FormKind::AddIcmpBlock),
            format!("Block ICMP type in `{zone}`"),
            "Block an ICMP type (e.g. echo-request) in the selected zone",
            &["icmp", "ping", "block"],
            Category::Firewall,
            mutable,
        ),
        cmd(
            UiAction::ToggleConfigView,
            "Toggle runtime/permanent view",
            "Flip the perspective for zone attributes and bindings (t)",
            &["perspective", "view", "permanent", "runtime"],
            Category::Views,
            Availability::Enabled,
        ),
        cmd(
            UiAction::RequestOperation(FirewallOperation::RuntimeToPermanent),
            "Runtime to permanent",
            "Persist the current runtime configuration",
            &["save", "persist", "sync"],
            Category::Firewall,
            mutable,
        ),
        {
            let panic_on = state
                .snapshot
                .as_deref()
                .is_some_and(|snapshot| snapshot.status.panic_mode);
            cmd(
                UiAction::RequestOperation(FirewallOperation::SetPanicMode { enabled: !panic_on }),
                if panic_on {
                    "Panic mode OFF"
                } else {
                    "Panic mode ON"
                },
                "Emergency switch: drops every packet (runtime only)",
                &["emergency", "lockdown"],
                Category::Firewall,
                mutable,
            )
        },
        {
            let current = state
                .snapshot
                .as_deref()
                .map_or(LogDenied::Off, |snapshot| snapshot.status.log_denied);
            let next = if current == LogDenied::Off {
                // Unicast skips broadcast/multicast noise — the sane default for
                // surfacing denied inbound flows.
                LogDenied::Unicast
            } else {
                LogDenied::Off
            };
            cmd(
                UiAction::RequestOperation(FirewallOperation::SetLogDenied { value: next }),
                format!("Set LogDenied to `{}`", next.as_str()),
                "Toggle kernel logging of denied packets (feeds the Logs view)",
                &["logdenied", "logging", "denied"],
                Category::Firewall,
                mutable,
            )
        },
        cmd(
            UiAction::SwitchView(ViewId::Logs),
            "Open logs",
            "Live tail of accepted and denied traffic",
            &["journal", "denied", "tail"],
            Category::Views,
            Availability::Enabled,
        ),
    ];

    for view in ViewId::iter() {
        commands.push(cmd(
            UiAction::SwitchView(view),
            format!("Go to {}", view.title()),
            "Switch view",
            &["view", "goto", "show"],
            Category::Views,
            Availability::Enabled,
        ));
    }
    commands
}

/// Catalog filtered and ranked against the open palette's query.
#[must_use]
pub fn filtered(state: &UiState) -> Vec<PaletteCommand> {
    let query = state.palette().map_or("", |palette| palette.query.as_str());
    let mut ranked: Vec<(i32, usize, PaletteCommand)> = catalog(state)
        .into_iter()
        .enumerate()
        .filter_map(|(index, command)| {
            let best = std::iter::once(command.title.as_str())
                .chain(command.keywords.iter().copied())
                .filter_map(|text| fuzzy::score(query, text))
                .max()?;
            Some((best, index, command))
        })
        .collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    ranked.into_iter().map(|(_, _, command)| command).collect()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::ui::overlays::Overlay;

    fn state_with_palette(query: &str) -> UiState {
        let mut state = UiState::new(&Config::default(), "test".into(), false, None);
        state.overlays.push(Overlay::Palette(PaletteState {
            query: query.to_owned(),
            selected: 0,
        }));
        state
    }

    #[test]
    fn empty_query_lists_the_full_catalog() {
        let state = state_with_palette("");
        assert_eq!(filtered(&state).len(), catalog(&state).len());
    }

    #[test]
    fn query_narrows_and_ranks_title_matches_first() {
        let state = state_with_palette("refresh");
        let commands = filtered(&state);
        assert!(!commands.is_empty());
        assert_eq!(commands[0].action, UiAction::RefreshRequested);
    }

    #[test]
    fn keywords_match_too() {
        let state = state_with_palette("nat");
        assert!(
            filtered(&state)
                .iter()
                .any(|c| c.action == UiAction::ToggleMasqueradeRequested)
        );
    }

    #[test]
    fn dependency_graph_is_discoverable_by_impact_keyword() {
        let state = state_with_palette("impact");
        assert!(
            filtered(&state)
                .iter()
                .any(|command| command.action == UiAction::ShowPolicyDependencies)
        );
    }

    #[test]
    fn mutations_are_gated_without_data_and_in_read_only() {
        // No snapshot yet → disabled with a reason.
        let state = state_with_palette("add service");
        let command = &filtered(&state)[0];
        assert_eq!(command.action, UiAction::OpenForm(FormKind::AddService));
        assert!(matches!(command.availability, Availability::Disabled(_)));

        // Read-only dominates even with data.
        let mut state = state_with_palette("add service");
        state.snapshot = Some(std::sync::Arc::new(
            crate::domain::mock::sample().expect("mock"),
        ));
        state.read_only = true;
        let command = &filtered(&state)[0];
        assert_eq!(
            command.availability,
            Availability::Disabled("read-only mode")
        );
    }

    #[test]
    fn apply_staged_plan_reports_read_only_as_the_blocker() {
        let mut state = state_with_palette("apply staged");
        state.snapshot = Some(std::sync::Arc::new(
            crate::domain::mock::sample().expect("mock"),
        ));
        state.staged.push(FirewallOperation::RuntimeToPermanent);
        state.read_only = true;
        let command = filtered(&state)
            .into_iter()
            .find(|c| c.action == UiAction::ApplyStagedPlan)
            .expect("apply command present");
        assert_eq!(
            command.availability,
            Availability::Disabled("read-only mode")
        );
    }
}
