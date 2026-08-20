//! Central UI state. Mutated only by `update::update` (reducer) plus the
//! per-frame `TableState` scroll offsets owned by the render pass.

use std::sync::Arc;

use ratatui::widgets::TableState;

use crate::application::ports::FirewallError;
use crate::application::{PlanId, RefreshId, RefreshOverview, RefreshPriority, SnapshotIdentity};
use crate::config::Config;
use crate::domain::LogEntry;
use crate::domain::{
    ConfigurationTarget, FirewallOperation, FirewallSnapshot, InterfaceName, RefreshObservation,
    ZoneName,
};

use super::overlays::Overlay;
use super::palette::PaletteState;
use super::views::{self, RowId, VIEW_COUNT, ViewId, ViewRow};

/// How long a toast stays visible, in ticks (250 ms each).
const TOAST_TTL_TICKS: u64 = 16;
/// Bounded toast queue: oldest entries drop first.
const MAX_TOASTS: usize = 4;
/// Bounded log ring buffer: memory stays flat under log storms.
const MAX_LOG_ENTRIES: usize = 1000;
/// Bounded session audit history.
const MAX_AUDIT_ENTRIES: usize = 200;

/// Per-view UI state: selection, filter, marks, and scroll offset.
#[derive(Debug, Default)]
pub struct ViewState {
    /// Index into the *filtered* row list.
    pub selected: usize,
    /// Live substring filter (`/`); empty = no filtering.
    pub filter: String,
    /// Multi-select set keyed by typed, zone-aware row identity.
    pub marked: std::collections::BTreeSet<RowId>,
    /// Scroll offset persistence for ratatui's stateful table render.
    pub table: TableState,
}

/// Where keystrokes go: normal navigation or the live-filter input line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputMode {
    /// Keys are navigation/commands.
    #[default]
    Normal,
    /// Keys edit the current view's filter.
    Filter,
}

/// Severity of a toast notification (drives symbol and color).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    /// Operation succeeded.
    Success,
    /// Operation failed.
    Error,
    /// Something needs attention but did not fail.
    Warning,
    /// Neutral informational note.
    Info,
}

/// One executed operation, kept for the session audit view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// UI tick at which the operation finished.
    pub tick: u64,
    /// Human-readable description of the operation.
    pub description: String,
    /// Configuration target the operation was applied to.
    pub target: &'static str,
    /// Outcome label (e.g. "applied", "failed", "partial").
    pub status: &'static str,
    /// First error message, if the operation did not fully apply.
    pub error: Option<String>,
}

/// An armed dead-man's switch: unless kept, `inverse` fires at `deadline_tick`.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingRollback {
    /// Unique lifecycle identity; duplicate operations never share a guard.
    pub id: crate::application::ports::RollbackGuardId,
    /// The risky operation itself — becomes the undo candidate once the
    /// countdown is resolved by "Keep changes".
    pub forward: FirewallOperation,
    /// The operation that undoes the risky change.
    pub inverse: FirewallOperation,
    /// UI tick at which the rollback fires automatically.
    pub deadline_tick: u64,
    /// Description of the change at risk, shown in the countdown bar.
    pub description: String,
    /// systemd transient unit pre-armed to run the inverse even if this
    /// process dies (crash / SSH loss). `None` when the watchdog could not
    /// be armed — the in-process countdown still protects a live session.
    pub watchdog_unit: Option<String>,
}

/// Reservation progress for the one sequential mutation plan currently
/// submitted to the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PlanRollbackReservations {
    /// Identity of the only plan allowed to consume this reservation set.
    pub(crate) id: PlanId,
    /// Risky operations reserved before the plan was submitted.
    pub(crate) total: usize,
    /// Risky forward outcomes already received for this plan.
    pub(crate) consumed: usize,
}

/// A transient notification rendered in the toast stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toast {
    /// Severity (drives symbol and color).
    pub kind: ToastKind,
    /// Message text.
    pub text: String,
    /// UI tick after which the toast is pruned.
    pub expires_at_tick: u64,
}

/// Preview owned by one exact in-flight refresh lifecycle.
#[derive(Debug, Clone)]
pub struct RefreshOverviewState {
    /// Identity used to reject stale overview and completion events.
    pub id: RefreshId,
    /// Preview-only overview; never used as a mutation precondition.
    pub overview: Arc<RefreshOverview>,
}

/// The whole UI state tree: current view, data snapshot, overlays, and
/// operator-facing toggles.
// Independent operator-facing toggles mirrored from config; a state machine
// would obscure, not clarify.
#[allow(clippy::struct_excessive_bools)]
pub struct UiState {
    /// The view the main table currently shows.
    pub view: ViewId,
    /// Zone explicitly selected by the operator, if any.
    pub selected_zone: Option<ZoneName>,
    /// Per-view state, indexed by `ViewId::index`.
    pub views: [ViewState; VIEW_COUNT],
    /// Current keyboard input mode.
    pub mode: InputMode,
    /// Overlay stack; the last element is rendered on top.
    pub overlays: Vec<Overlay>,
    /// Vertical scroll offset (in rows) for the topmost scrollable modal
    /// (Help / Details). The renderer clamps it to the content and writes the
    /// clamped value back, so it can never scroll past the end.
    pub overlay_scroll: u16,
    /// Latest firewall snapshot, if a refresh has succeeded yet.
    pub snapshot: Option<Arc<FirewallSnapshot>>,
    /// Identity of the exact authoritative snapshot currently displayed.
    pub snapshot_identity: Option<SnapshotIdentity>,
    /// The first successful snapshot of the session — the baseline the
    /// "session diff" compares the current state against.
    pub session_baseline: Option<Arc<FirewallSnapshot>>,
    /// Exact refresh lifecycle currently in flight, if any.
    pub active_refresh: Option<RefreshId>,
    /// Matching low-latency overview shown while full hydration continues.
    pub refresh_overview: Option<RefreshOverviewState>,
    /// Last backend failure; cleared by the next successful refresh.
    pub backend_error: Option<FirewallError>,
    /// Denied packets seen this session (from the log tailer).
    pub denied_session: u64,
    /// Bounded ring buffer of kernel/netfilter log entries, newest last.
    log_buffer: std::collections::VecDeque<LogEntry>,
    /// Session-unique sequence aligned one-to-one with [`Self::log_buffer`].
    log_sequences: std::collections::VecDeque<u64>,
    /// Next sequence assigned to an incoming log entry.
    next_log_sequence: u64,
    /// SSH session detected at startup (`SSH_CONNECTION` / `SSH_CLIENT` / `SSH_TTY`).
    pub ssh_session: bool,
    /// The interface carrying the SSH session, if resolved — enables a precise
    /// per-zone warning instead of a blanket one.
    pub ssh_interface: Option<InterfaceName>,
    /// Bounded queue of active toast notifications, oldest first.
    pub toasts: std::collections::VecDeque<Toast>,
    /// Session audit history (the JSONL file is the durable trail).
    pub audit: Vec<AuditEntry>,
    /// Operations staged via `s` in the confirmation modal.
    pub staged: Vec<FirewallOperation>,
    /// Exact telemetry for the last completed refresh attempt.
    pub last_refresh: Option<RefreshObservation>,
    /// Stack of applied-and-verified reversible operations, oldest first. Undo
    /// pops the most recent; capped by [`UiState::push_undo`] so it can't grow
    /// without bound.
    pub undo_stack: Vec<crate::domain::FirewallOperation>,
    /// Fully-applied operations awaiting postcondition verification against the
    /// next snapshot refresh. A list, not a slot: every operation in a
    /// multi-step plan must be verified, not just the last one.
    pub verify_next_refresh: Vec<crate::domain::FirewallOperation>,
    /// Armed dead-man's-switch rollbacks, oldest first. A stack, not a slot:
    /// a second risky change must never silently overwrite the first inverse.
    pub pending_rollback: Vec<PendingRollback>,
    /// Whether the shell's single normal-priority engine-outbox slot is full.
    pub engine_normal_backpressured: bool,
    /// Rollback-priority requests waiting in the shell outbox.
    pub rollback_outbox_pending: usize,
    /// Capacity reserved by submitted risky operations awaiting outcomes.
    pub rollback_reservations: usize,
    /// Risky single-operation reservations submitted before any active plan.
    pub(crate) single_rollback_reservations: usize,
    /// Exact reservation progress for the active sequential plan.
    pub(crate) in_flight_plan_rollback: Option<PlanRollbackReservations>,
    /// Next process-local staged-plan identity; IDs are never reused.
    next_plan_id: u64,
    /// Dead-man's switch window in ticks; 0 = disabled.
    pub rollback_ticks: u64,
    /// Monotonic UI clock, incremented every 250 ms tick.
    pub tick: u64,
    /// Mutations are refused when set (`--read-only`).
    pub read_only: bool,
    /// Why read-only is in effect, for a visible reason line (`None` when
    /// mutations are allowed).
    pub read_only_reason: Option<String>,
    /// The SSH client's IP address, when running inside an SSH session.
    pub ssh_client_ip: Option<std::net::IpAddr>,
    /// True when driving `firewall-offline-cmd` (permanent config, no daemon).
    pub offline: bool,
    /// Destructive actions require a confirmation modal.
    pub confirm_destructive: bool,
    /// Default configuration target for mutations.
    pub target: ConfigurationTarget,
    /// Which configuration perspective zone attributes and bindings show
    /// (`t` toggles). Entry rows always list the union — drift is never hidden.
    pub config_view: ConfigurationTarget,
    /// Show the key-hint bar in the header.
    pub show_help_bar: bool,
    /// Sidebar width in columns.
    pub sidebar_width: u16,
    /// Hostname shown in the context header.
    pub hostname: String,
    /// Last known terminal size (width, height).
    pub size: (u16, u16),
}

impl UiState {
    /// Builds the initial state from config plus startup-detected host facts.
    #[must_use]
    pub fn new(
        config: &Config,
        hostname: String,
        ssh_session: bool,
        ssh_interface: Option<InterfaceName>,
    ) -> Self {
        let offline = config.offline;
        let selected_zone = config
            .initial_zone
            .as_deref()
            .and_then(|z| ZoneName::parse(z).ok());
        Self {
            view: ViewId::Zones,
            selected_zone,
            views: std::array::from_fn(|_| ViewState::default()),
            mode: InputMode::Normal,
            overlays: Vec::new(),
            overlay_scroll: 0,
            snapshot: None,
            snapshot_identity: None,
            session_baseline: None,
            active_refresh: None,
            refresh_overview: None,
            backend_error: None,
            denied_session: 0,
            log_buffer: std::collections::VecDeque::new(),
            log_sequences: std::collections::VecDeque::new(),
            next_log_sequence: 1,
            ssh_session,
            ssh_interface,
            toasts: std::collections::VecDeque::new(),
            audit: Vec::new(),
            staged: Vec::new(),
            undo_stack: Vec::new(),
            last_refresh: None,
            verify_next_refresh: Vec::new(),
            pending_rollback: Vec::new(),
            engine_normal_backpressured: false,
            rollback_outbox_pending: 0,
            rollback_reservations: 0,
            single_rollback_reservations: 0,
            in_flight_plan_rollback: None,
            next_plan_id: 1,
            rollback_ticks: config.rollback_timeout.as_secs() * 4, // 250 ms ticks
            tick: 0,
            read_only: config.read_only,
            read_only_reason: config.read_only_reason.clone(),
            ssh_client_ip: crate::bootstrap::ssh_client_ip(),
            offline,
            confirm_destructive: config.confirm_destructive,
            target: config.target,
            config_view: ConfigurationTarget::Runtime,
            show_help_bar: config.show_help_bar,
            sidebar_width: config.sidebar_width,
            hostname,
            size: (0, 0),
        }
    }

    /// Allocates the next plan identity, failing closed before numeric reuse.
    pub(crate) fn allocate_plan_id(&mut self) -> Option<PlanId> {
        let next = self.next_plan_id.checked_add(1)?;
        let id = PlanId::new(self.next_plan_id);
        self.next_plan_id = next;
        Some(id)
    }

    /// The current view's state.
    #[must_use]
    pub fn view_state(&self) -> &ViewState {
        &self.views[self.view.index()]
    }

    /// Mutable access to the current view's state.
    pub fn view_state_mut(&mut self) -> &mut ViewState {
        &mut self.views[self.view.index()]
    }

    /// The zone context used by zone-scoped views; falls back to the default zone.
    #[must_use]
    pub fn effective_zone(&self) -> Option<ZoneName> {
        self.selected_zone
            .clone()
            .or_else(|| self.snapshot.as_ref().map(|s| s.default_zone.clone()))
    }

    /// Matching preview for the active lifecycle, if one has arrived.
    #[must_use]
    pub fn matching_refresh_overview(&self) -> Option<&RefreshOverview> {
        self.refresh_overview
            .as_ref()
            .filter(|preview| Some(preview.id) == self.active_refresh)
            .map(|preview| preview.overview.as_ref())
    }

    /// Whether the active preview can render this view without inventing details.
    #[must_use]
    pub fn matching_overview_supports(&self, view: ViewId) -> bool {
        self.matching_refresh_overview().is_some() && views::overview_supports(view)
    }

    fn display_zone(&self) -> Option<ZoneName> {
        self.selected_zone
            .clone()
            .or_else(|| {
                self.matching_refresh_overview()
                    .map(|overview| overview.default_zone.clone())
            })
            .or_else(|| {
                self.snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.default_zone.clone())
            })
    }

    /// Latest UI selection that staged hydration should fetch first.
    #[must_use]
    pub fn refresh_priority(&self) -> RefreshPriority {
        let mut priority = RefreshPriority {
            zone: self.display_zone(),
            service: None,
            policy: None,
        };
        let rows = self.visible_rows();
        let Some(row) = rows.get(self.view_state().selected) else {
            return priority;
        };
        match &row.id {
            RowId::Zone(zone) => priority.zone = Some(zone.clone()),
            RowId::Service { zone, service } => {
                priority.zone = Some(zone.clone());
                priority.service = Some(service.clone());
            }
            RowId::Policy { name } => priority.policy = Some(name.clone()),
            RowId::Port { .. }
            | RowId::Forwarding { .. }
            | RowId::RichRule { .. }
            | RowId::Interface { .. }
            | RowId::Source { .. }
            | RowId::IpSet { .. }
            | RowId::Direct { .. }
            | RowId::Log { .. } => {}
        }
        priority
    }

    /// Unfiltered rows for a view.
    // rows are recomputed per keystroke/frame; snapshot scale (dozens of
    // zones) makes this free — add caching only if profiling ever disagrees.
    #[must_use]
    pub fn all_rows(&self, view: ViewId) -> Vec<ViewRow> {
        if view == ViewId::Logs {
            // Newest first: tailing UX without chasing the scroll position.
            return self
                .log_sequences
                .iter()
                .rev()
                .zip(self.log_buffer.iter().rev())
                .map(|(&sequence, entry)| {
                    ViewRow::new(
                        RowId::Log {
                            sequence,
                            entry: entry.clone(),
                        },
                        vec![
                            entry.time.clone(),
                            entry.action.as_str().to_owned(),
                            entry.src.clone(),
                            entry.dst.clone(),
                            entry.dport.clone(),
                            entry.proto.clone(),
                            entry.iface.clone(),
                        ],
                    )
                })
                .collect();
        }
        if let Some(overview) = self.matching_refresh_overview() {
            let zone = self
                .selected_zone
                .clone()
                .unwrap_or_else(|| overview.default_zone.clone());
            if let Some(rows) = views::overview_rows(view, overview, &zone, self.config_view) {
                return rows;
            }
        }
        let Some(snapshot) = &self.snapshot else {
            return Vec::new();
        };
        let Some(zone) = self.effective_zone() else {
            return Vec::new();
        };
        views::rows(view, snapshot, &zone, self.config_view)
    }

    /// Rows of the current view with the live filter applied.
    #[must_use]
    pub fn visible_rows(&self) -> Vec<ViewRow> {
        let rows = self.all_rows(self.view);
        let filter = &self.views[self.view.index()].filter;
        if filter.is_empty() {
            return rows;
        }
        let needle = filter.to_lowercase();
        rows.into_iter()
            .filter(|row| row.iter().any(|cell| cell.to_lowercase().contains(&needle)))
            .collect()
    }

    /// Unfiltered row count for a view (sidebar badges).
    #[must_use]
    pub fn view_count(&self, view: ViewId) -> usize {
        self.all_rows(view).len()
    }

    /// Records a reversible operation as undoable, capping the stack so a long
    /// session can't grow it without bound (oldest is dropped).
    pub fn push_undo(&mut self, operation: crate::domain::FirewallOperation) {
        const UNDO_CAP: usize = 25;
        self.undo_stack.push(operation);
        if self.undo_stack.len() > UNDO_CAP {
            self.undo_stack.remove(0);
        }
    }

    /// Appends to the session audit history, dropping the oldest at capacity.
    pub fn push_audit(&mut self, entry: AuditEntry) {
        if self.audit.len() >= MAX_AUDIT_ENTRIES {
            self.audit.remove(0);
        }
        self.audit.push(entry);
    }

    /// Appends log entries to the bounded ring buffer and counts denials.
    pub fn push_log_entries(&mut self, entries: Vec<LogEntry>) {
        for entry in entries {
            if entry.action.is_denied() {
                self.denied_session += 1;
            }
            if self.log_buffer.len() >= MAX_LOG_ENTRIES {
                self.log_buffer.pop_front();
                self.log_sequences.pop_front();
            }
            let sequence = self.next_log_sequence;
            self.next_log_sequence = self.next_log_sequence.saturating_add(1);
            self.log_buffer.push_back(entry);
            self.log_sequences.push_back(sequence);
        }
    }

    /// Queues a toast notification, dropping the oldest at capacity.
    pub fn toast(&mut self, kind: ToastKind, text: impl Into<String>) {
        if self.toasts.len() >= MAX_TOASTS {
            self.toasts.pop_front();
        }
        self.toasts.push_back(Toast {
            kind,
            text: text.into(),
            expires_at_tick: self.tick + TOAST_TTL_TICKS,
        });
    }

    /// Drops expired toasts; called from the tick handler.
    pub fn prune_toasts(&mut self) {
        let now = self.tick;
        self.toasts.retain(|toast| toast.expires_at_tick > now);
    }

    /// The zone that actually protects the SSH session, following firewalld's
    /// dispatch precedence: a source/ipset binding matching the client IP wins
    /// over the interface binding; the default zone catches the rest.
    #[must_use]
    pub fn ssh_zone(&self) -> Option<ZoneName> {
        self.ssh_zone_with_reason().map(|(zone, _)| zone)
    }

    /// [`Self::ssh_zone`] plus a human explanation of *why* that zone applies
    /// — named in confirmation warnings so the operator sees the exact path.
    #[must_use]
    pub fn ssh_zone_with_reason(&self) -> Option<(ZoneName, String)> {
        let snapshot = self.snapshot.as_deref()?;
        // 1. Source binding covering the client IP (highest precedence).
        if let Some(ip) = self.ssh_client_ip
            && let Some(zone) = crate::domain::explain::zone_for_source_ip(snapshot, ip)
        {
            return Some((zone, format!("source binding matches your client {ip}")));
        }
        // 2. Interface binding.
        if let Some(iface) = self.ssh_interface.as_ref()
            && let Some((zone, _)) = snapshot
                .active
                .iter()
                .find(|(_, active)| active.interfaces.contains(iface))
        {
            return Some((
                zone.clone(),
                format!("your SSH interface `{iface}` is bound to it"),
            ));
        }
        // 3. Unbound traffic lands in the default zone.
        self.ssh_session.then(|| {
            (
                snapshot.default_zone.clone(),
                "it is the default zone (your SSH interface is unbound)".to_owned(),
            )
        })
    }

    /// The open palette's state, if the topmost overlay is the palette.
    #[must_use]
    pub fn palette(&self) -> Option<&PaletteState> {
        match self.overlays.last() {
            Some(Overlay::Palette(palette)) => Some(palette),
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod plan_identity_tests {
    use super::*;

    #[test]
    fn plan_ids_are_monotonic_and_fail_before_reuse() {
        let mut state = UiState::new(&Config::default(), "test".to_owned(), false, None);
        assert_eq!(state.allocate_plan_id().unwrap(), PlanId::new(1));
        assert_eq!(state.allocate_plan_id().unwrap(), PlanId::new(2));

        state.next_plan_id = u64::MAX;
        assert_eq!(state.allocate_plan_id(), None);
        assert_eq!(state.next_plan_id, u64::MAX);
    }
}
