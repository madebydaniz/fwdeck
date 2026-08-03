//! Semantic UI actions (produced by the keymap and the event loop) and the
//! effects a reducer step can request from the outer loop.

use std::sync::Arc;

use crate::application::ports::FirewallError;
use crate::domain::LogEntry;
use crate::domain::{FirewallOperation, FirewallSnapshot};

use super::overlays::FormKind;
use super::views::ViewId;

/// A semantic UI event fed to the reducer (`update::update`).
#[derive(Debug, Clone, PartialEq)]
pub enum UiAction {
    /// Advance the 250 ms clock: expire toasts, fire due rollbacks.
    Tick,
    /// The terminal was resized to (width, height).
    Resize(u16, u16),
    /// Switch the main table to the given view.
    SwitchView(ViewId),
    /// Move the selection by a relative number of rows.
    MoveSelection(i32),
    /// Jump the selection to the first row.
    SelectFirst,
    /// Jump the selection to the last row.
    SelectLast,
    /// Move the selection by whole pages (positive = down).
    Page(i32),
    // Command palette (`:`)
    /// Open the command palette overlay.
    OpenPalette,
    /// Append a character to the palette query.
    PaletteInput(char),
    /// Delete the last character of the palette query.
    PaletteBackspace,
    /// Move the palette selection by a relative offset.
    PaletteMove(i32),
    /// Run the selected palette command.
    PaletteExecute,
    // Global search (`ctrl-f`)
    /// Open the global-search overlay (fuzzy match across all views).
    OpenGlobalSearch,
    /// Append a character to the global-search query.
    GlobalSearchInput(char),
    /// Delete the last character of the global-search query.
    GlobalSearchBackspace,
    /// Move the global-search selection by a relative offset.
    GlobalSearchMove(i32),
    /// Jump to the selected search hit (switches view and selects the row).
    GlobalSearchExecute,
    // Live filter (`/`)
    /// Enter filter-input mode for the current view.
    EnterFilterMode,
    /// Append a character to the live filter.
    InputChar(char),
    /// Delete the last character of the live filter.
    InputBackspace,
    /// Keep the filter and return to normal mode.
    InputSubmit,
    /// Clear the filter and return to normal mode.
    InputCancel,
    // Overlays
    /// Open the help overlay.
    OpenHelp,
    /// Open the About overlay (version, description, developer, links).
    OpenAbout,
    /// Close the topmost overlay.
    CloseOverlay,
    /// Scroll the topmost scrollable modal (Help / Details) by a signed number
    /// of rows; positive scrolls down. Clamped to the content by the renderer.
    ScrollOverlay(i32),
    /// `y` on a confirmation modal: dispatches the carried action.
    ConfirmAccept,
    /// `s` on a confirmation modal: stages the operation instead of applying.
    ConfirmStage,
    /// Enter on a row: zone selection on Zones, details elsewhere.
    ActivateRow,
    /// Open the zone-overview details for the effective zone.
    InspectZone,
    /// Open the diagnostics overlay for the last backend error.
    ShowErrorDetails,
    /// Clear the current view's live filter.
    ClearFilter,
    // Mutations
    /// `a`: contextual add (service form on Services, port form on Ports).
    AddEntry,
    /// `d`: contextual remove of the selected row, behind a confirmation.
    DeleteEntry,
    /// space: toggle the selected row into the multi-select set.
    ToggleMark,
    /// palette / `m`: toggle masquerade for the selected/effective zone.
    ToggleMasqueradeRequested,
    /// palette: toggle intra-zone forwarding for the selected/effective zone.
    ToggleForwardRequested,
    /// palette: toggle icmp-block inversion for the selected/effective zone.
    ToggleIcmpBlockInversionRequested,
    /// Make the selected zone the default zone (behind a confirmation).
    SetDefaultZoneRequested,
    /// Open an empty single-field input form.
    OpenForm(FormKind),
    /// Open a form pre-filled with a value (used by clone).
    OpenFormPrefilled(FormKind, String),
    /// `c`: clone the selected row into a prefilled add form.
    CloneEntry,
    /// Append a character to the open form's buffer.
    FormInput(char),
    /// Delete the last character of the open form's buffer.
    FormBackspace,
    /// Submit the open form: validate and request the operation.
    FormSubmit,
    /// Open the guided rich-rule builder overlay.
    OpenRichBuilder,
    /// Append a character to the rich builder's current field.
    RichBuilderInput(char),
    /// Delete the last character of the rich builder's current field.
    RichBuilderBackspace,
    /// Commit the rich builder's current field; the last commit assembles the rule.
    RichBuilderCommit,
    /// Validates and opens the confirmation modal for an operation.
    RequestOperation(FirewallOperation),
    /// Dispatched by the confirmation modal: hands the operation to the engine.
    ApplyOperation(FirewallOperation),
    /// Dispatched by the plan confirmation modal: arms the dead-man's switch for
    /// the batch, then hands the whole staged plan to the engine.
    ApplyPlanConfirmed(Vec<FirewallOperation>),
    /// The engine finished an operation; toast, audit, and maybe arm rollback.
    OperationFinished(Box<crate::application::api::OperationResult>),
    /// A staged plan finished; `remaining` are unexecuted operations to re-stage.
    PlanFinished {
        /// How many operations applied fully before the plan ended.
        applied: usize,
        /// Operations never executed (plan halted on a failure).
        remaining: Vec<FirewallOperation>,
    },
    /// `y` in normal mode: keep the changes of an armed rollback countdown.
    KeepChanges,
    /// `u` in normal mode: roll back the last risky operation immediately.
    RollbackNow,
    /// Open the session audit history overlay.
    ShowAudit,
    /// Open the service catalog (all available services) overlay.
    BrowseServices,
    /// Open the policy objects overlay.
    BrowsePolicies,
    /// Open the scoped policy-to-zone/service dependency graph.
    ShowPolicyDependencies,
    /// Open the drift workspace: every runtime vs permanent difference
    /// across all zones.
    ShowDrift,
    /// Show a read-only diff of the current state against the session baseline
    /// (the first snapshot of this session) — "what changed since startup".
    ShowSessionDiff,
    /// Show a read-only diff of the current state against a saved snapshot
    /// (loaded off-thread; the overlay opens on `SnapshotDiffLoaded`).
    ShowSnapshotDiff,
    /// Read live nftables rule-hit counters off-thread; the overlay opens on
    /// `CountersLoaded`.
    ShowCounters,
    /// The counter read finished (result of `Effect::LoadCounters`).
    CountersLoaded(Result<Vec<crate::domain::ChainCounter>, String>),
    /// Request the inverse of the last verified operation (reviewed like any
    /// other mutation).
    UndoLastOperation,
    /// Stage permanent-scoped operations that make the permanent config match
    /// the current runtime (per-attribute drift repair, reviewable).
    StageDriftSync,
    /// Persist the current snapshot to the snapshot store.
    SaveSnapshot,
    /// Open the saved-snapshots overlay.
    BrowseSnapshots,
    /// The snapshot store finished listing (result of `Effect::ListSnapshots`).
    SnapshotsListed(Vec<crate::infrastructure::snapshot_store::SnapshotEntry>),
    /// A snapshot finished loading for restore (result of
    /// `Effect::LoadSnapshotForRestore`).
    SnapshotLoaded {
        /// The requested snapshot file name (for messages).
        name: String,
        /// The parsed snapshot, or the load/validation error text.
        result: Result<Box<FirewallSnapshot>, String>,
    },
    /// A snapshot finished loading for a read-only diff (result of
    /// `Effect::LoadSnapshotForDiff`).
    SnapshotDiffLoaded {
        /// The requested snapshot file name (for the title/messages).
        name: String,
        /// The parsed snapshot, or the load/validation error text.
        result: Result<Box<FirewallSnapshot>, String>,
    },
    /// Open the staged-plan overlay listing pending operations.
    ShowStagedPlan,
    /// Send the staged plan to the engine as one sequential transaction.
    ApplyStagedPlan,
    /// Drop all staged operations without applying them.
    DiscardStagedPlan,
    /// Export the staged plan to a file in the given format.
    ExportStagedPlan(crate::infrastructure::firewalld::command::ExportFormat),
    /// `y` (yank) in normal mode: copy the selected row to the clipboard.
    YankRow,
    // Backend
    /// `r`: ask the engine for a fresh snapshot.
    RefreshRequested,
    /// `ctrl-r`: firewalld reload (confirmed mutation).
    ReloadRequested,
    /// `t`: flip the zone-attribute/binding perspective (runtime ⇄ permanent).
    ToggleConfigView,
    /// The engine started a refresh; show the spinner.
    RefreshStarted,
    /// The engine finished a refresh: a new snapshot or a backend error.
    RefreshCompleted(Result<Arc<FirewallSnapshot>, FirewallError>),
    /// New kernel/netfilter log entries from the log tailer.
    LogsReceived(Vec<LogEntry>),
    /// Exit the application. Asks first when quitting would fire an armed
    /// rollback or discard staged changes; otherwise exits immediately.
    Quit,
    /// Exit unconditionally (the quit confirmation's accept, and ctrl-c).
    QuitConfirmed,
}

/// Side effects the reducer asks the event loop to perform.
#[derive(Debug, Clone, PartialEq)]
pub enum Effect {
    /// Tear down the terminal and exit.
    Quit,
    /// Ask the engine for a fresh snapshot.
    Refresh,
    /// Hand a single operation to the engine for execution.
    Apply(FirewallOperation),
    /// Execute an armed inverse. The engine applies first and only then
    /// attempts the bounded watchdog disarm.
    ApplyRollback {
        /// Unique rollback lifecycle id.
        id: crate::application::ports::RollbackGuardId,
        /// Connectivity-restoring inverse operation.
        operation: FirewallOperation,
        /// External watchdog associated with this inverse.
        watchdog_unit: Option<String>,
    },
    /// Copy text to the terminal clipboard via OSC 52 (works over SSH).
    CopyToClipboard(String),
    /// Persist the snapshot to the snapshot store (result toasted by the shell).
    SaveSnapshot(std::sync::Arc<crate::domain::FirewallSnapshot>),
    /// Append the outcome to the durable JSONL audit log, keyed by the shared
    /// correlation id.
    RecordAudit {
        /// Correlation id (joins `fwdeck.log` and `audit.jsonl`).
        op_id: u64,
        /// The outcome to record.
        outcome: crate::application::ports::OperationOutcome,
    },
    /// Write an already-rendered plan export to the exports directory.
    ExportPlan(
        crate::infrastructure::firewalld::command::ExportFormat,
        String,
    ),
    /// Send a whole staged plan to the engine as one sequential transaction.
    ApplyPlan(Vec<FirewallOperation>),
    /// List the snapshot store (off the event-loop thread); result returns as
    /// `UiAction::SnapshotsListed`.
    ListSnapshots,
    /// Load a snapshot by name for restore (off the event-loop thread); result
    /// returns as `UiAction::SnapshotLoaded`.
    LoadSnapshotForRestore(String),
    /// Load a snapshot by name for a read-only diff (off the event-loop
    /// thread); result returns as `UiAction::SnapshotDiffLoaded`.
    LoadSnapshotForDiff(String),
    /// Read live nftables rule-hit counters (off the event-loop thread);
    /// result returns as `UiAction::CountersLoaded`.
    LoadCounters,
    /// Cancel a previously armed watchdog after the operator keeps changes.
    DisarmWatchdog {
        /// Transient unit name to stop.
        unit: String,
    },
}
