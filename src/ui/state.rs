//! Central UI state. Mutated only by `update::update` (reducer) plus the
//! per-frame `TableState` scroll offsets owned by the render pass.

use std::sync::Arc;

use ratatui::widgets::TableState;

use crate::application::ports::FirewallError;
use crate::config::Config;
use crate::domain::{
    ConfigurationTarget, FirewallOperation, FirewallSnapshot, InterfaceName, ZoneName,
};
use crate::infrastructure::logs::LogEntry;

use super::overlays::Overlay;
use super::palette::PaletteState;
use super::views::{self, VIEW_COUNT, ViewId};

/// How long a toast stays visible, in ticks (250 ms each).
const TOAST_TTL_TICKS: u64 = 16;
/// Bounded toast queue: oldest entries drop first.
const MAX_TOASTS: usize = 4;
/// Bounded log ring buffer: memory stays flat under log storms.
const MAX_LOG_ENTRIES: usize = 1000;
/// Bounded session audit history.
const MAX_AUDIT_ENTRIES: usize = 200;

/// Stable identity of a table row: every cell joined on a separator that
/// cannot appear in cell text. Used as the multi-select key.
#[must_use]
pub fn row_key(row: &[String]) -> String {
    row.join("\u{1f}")
}

/// Per-view UI state: selection, filter, marks, and scroll offset.
#[derive(Debug, Default)]
pub struct ViewState {
    /// Index into the *filtered* row list.
    pub selected: usize,
    /// Live substring filter (`/`); empty = no filtering.
    pub filter: String,
    /// Multi-select set, keyed by the full row (`row_key`) — first cells are
    /// not unique (e.g. 8080/tcp vs 8080/udp share "8080"; rich rules share a
    /// family), so marking by first cell would select unrelated rows.
    pub marked: std::collections::BTreeSet<String>,
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
    /// The first successful snapshot of the session — the baseline the
    /// "session diff" compares the current state against.
    pub session_baseline: Option<Arc<FirewallSnapshot>>,
    /// A refresh is in flight (engine sent `RefreshStarted`).
    pub refreshing: bool,
    /// Last backend failure; cleared by the next successful refresh.
    pub backend_error: Option<FirewallError>,
    /// Denied packets seen this session (from the log tailer).
    pub denied_session: u64,
    /// Bounded ring buffer of kernel/netfilter log entries, newest last.
    pub log_buffer: std::collections::VecDeque<LogEntry>,
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
    /// Tick at which the in-flight refresh started (for the duration metric).
    pub refresh_started_tick: Option<u64>,
    /// Duration of the last completed refresh, in milliseconds (tick-derived).
    pub last_refresh_ms: Option<u64>,
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
            session_baseline: None,
            refreshing: false,
            backend_error: None,
            denied_session: 0,
            log_buffer: std::collections::VecDeque::new(),
            ssh_session,
            ssh_interface,
            toasts: std::collections::VecDeque::new(),
            audit: Vec::new(),
            staged: Vec::new(),
            undo_stack: Vec::new(),
            refresh_started_tick: None,
            last_refresh_ms: None,
            verify_next_refresh: Vec::new(),
            pending_rollback: Vec::new(),
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

    /// Unfiltered rows for a view.
    // rows are recomputed per keystroke/frame; snapshot scale (dozens of
    // zones) makes this free — add caching only if profiling ever disagrees.
    #[must_use]
    pub fn all_rows(&self, view: ViewId) -> Vec<Vec<String>> {
        if view == ViewId::Logs {
            // Newest first: tailing UX without chasing the scroll position.
            return self
                .log_buffer
                .iter()
                .rev()
                .map(|entry| {
                    vec![
                        entry.time.clone(),
                        entry.action.as_str().to_owned(),
                        entry.src.clone(),
                        entry.dst.clone(),
                        entry.dport.clone(),
                        entry.proto.clone(),
                        entry.iface.clone(),
                    ]
                })
                .collect();
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
    pub fn visible_rows(&self) -> Vec<Vec<String>> {
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
            }
            self.log_buffer.push_back(entry);
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
