//! Key-event → semantic-action translation, plus the help-overlay catalog.
//!
//! `HELP` is the single source of truth for normal-mode bindings: each entry
//! carries the key codes it translates *and* the help text, so the overlay
//! can never drift from the live bindings. Only genuinely special keys
//! (digit views, state-gated `esc`, ctrl chords, overlay-local keys) live in
//! explicit match arms — and each of those has an informational `HELP` entry.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use super::action::UiAction;
use super::overlays::Overlay;
use super::state::{InputMode, UiState};
use super::views::ViewId;

/// Translate a raw terminal key event into a semantic [`UiAction`],
/// honouring the active overlay and input mode. Returns `None` for keys
/// that have no meaning in the current context.
#[must_use]
pub fn translate(state: &UiState, key: KeyEvent) -> Option<UiAction> {
    if key.kind != KeyEventKind::Press {
        return None;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return match key.code {
            // Ctrl-c is the emergency exit: always immediate, no questions.
            KeyCode::Char('c') => Some(UiAction::QuitConfirmed),
            KeyCode::Char('r') => Some(UiAction::ReloadRequested),
            KeyCode::Char('f') => Some(UiAction::OpenGlobalSearch),
            _ => None,
        };
    }
    if let Some(overlay) = state.overlays.last() {
        return overlay_key(overlay, key.code);
    }
    match state.mode {
        InputMode::Filter => match key.code {
            KeyCode::Esc => Some(UiAction::InputCancel),
            KeyCode::Enter => Some(UiAction::InputSubmit),
            KeyCode::Backspace => Some(UiAction::InputBackspace),
            KeyCode::Char(c) => Some(UiAction::InputChar(c)),
            _ => None,
        },
        InputMode::Normal => normal_key(state, key.code),
    }
}

/// Overlays are modal: they swallow everything except their own keys.
fn overlay_key(overlay: &Overlay, code: KeyCode) -> Option<UiAction> {
    match overlay {
        Overlay::Help | Overlay::About | Overlay::Details(_) => match code {
            KeyCode::Esc | KeyCode::Char('q' | '?') | KeyCode::Enter => {
                Some(UiAction::CloseOverlay)
            }
            // Scrollable so a long modal never overflows a small terminal.
            KeyCode::Down | KeyCode::Char('j') => Some(UiAction::ScrollOverlay(1)),
            KeyCode::Up | KeyCode::Char('k') => Some(UiAction::ScrollOverlay(-1)),
            KeyCode::PageDown | KeyCode::Char(' ') => Some(UiAction::ScrollOverlay(10)),
            KeyCode::PageUp => Some(UiAction::ScrollOverlay(-10)),
            KeyCode::Home => Some(UiAction::ScrollOverlay(i32::MIN)),
            KeyCode::End => Some(UiAction::ScrollOverlay(i32::MAX)),
            _ => None,
        },
        Overlay::Palette(_) => match code {
            KeyCode::Esc => Some(UiAction::CloseOverlay),
            KeyCode::Enter => Some(UiAction::PaletteExecute),
            KeyCode::Down => Some(UiAction::PaletteMove(1)),
            KeyCode::Up => Some(UiAction::PaletteMove(-1)),
            KeyCode::Backspace => Some(UiAction::PaletteBackspace),
            KeyCode::Char(c) => Some(UiAction::PaletteInput(c)),
            _ => None,
        },
        Overlay::GlobalSearch(_) => match code {
            KeyCode::Esc => Some(UiAction::CloseOverlay),
            KeyCode::Enter => Some(UiAction::GlobalSearchExecute),
            KeyCode::Down => Some(UiAction::GlobalSearchMove(1)),
            KeyCode::Up => Some(UiAction::GlobalSearchMove(-1)),
            KeyCode::Backspace => Some(UiAction::GlobalSearchBackspace),
            KeyCode::Char(c) => Some(UiAction::GlobalSearchInput(c)),
            _ => None,
        },
        Overlay::Confirm(_) => match code {
            KeyCode::Char('y') => Some(UiAction::ConfirmAccept),
            KeyCode::Char('s') => Some(UiAction::ConfirmStage),
            KeyCode::Char('n') | KeyCode::Esc => Some(UiAction::CloseOverlay),
            _ => None,
        },
        Overlay::Form(_) => match code {
            KeyCode::Esc => Some(UiAction::CloseOverlay),
            KeyCode::Enter => Some(UiAction::FormSubmit),
            KeyCode::Backspace => Some(UiAction::FormBackspace),
            KeyCode::Char(c) => Some(UiAction::FormInput(c)),
            _ => None,
        },
        Overlay::RichBuilder(_) => match code {
            KeyCode::Esc => Some(UiAction::CloseOverlay),
            KeyCode::Enter => Some(UiAction::RichBuilderCommit),
            KeyCode::Backspace => Some(UiAction::RichBuilderBackspace),
            KeyCode::Char(c) => Some(UiAction::RichBuilderInput(c)),
            _ => None,
        },
    }
}

/// Normal-mode translation: special-cased keys first, then the `HELP` table.
fn normal_key(state: &UiState, code: KeyCode) -> Option<UiAction> {
    if state.view == ViewId::TrafficTests {
        match code {
            KeyCode::Char('e') => return Some(UiAction::TrafficEvaluate),
            KeyCode::Char('r') => return Some(UiAction::TrafficReload),
            KeyCode::Char('t') => return Some(UiAction::TrafficToggleTarget),
            _ => {}
        }
    }
    match code {
        // Special cases a static table cannot express: the action is
        // computed from the digit / gated on view state.
        KeyCode::Char(d) if d.is_ascii_digit() => d
            .to_digit(10)
            .and_then(|d| ViewId::from_digit(d as usize))
            .map(UiAction::SwitchView),
        KeyCode::Esc if !state.view_state().filter.is_empty() => Some(UiAction::ClearFilter),
        _ => HELP
            .iter()
            .flat_map(|(_, entries)| entries.iter())
            .find(|entry| entry.codes.contains(&code))
            .and_then(|entry| entry.action.clone()),
    }
}

/// One help-overlay row that doubles as a normal-mode binding definition.
///
/// Entries with a non-empty `codes` list are live bindings resolved by
/// [`translate`]; entries with an empty list are informational only and
/// document keys handled by explicit match arms (digits, `esc`, ctrl
/// chords, dialog-local keys).
pub struct HelpEntry {
    /// Key label rendered in the help overlay (e.g. `"j / ↓"`).
    pub keys: &'static str,
    /// Short description rendered next to the key label.
    pub desc: &'static str,
    /// Key codes this entry translates in normal mode; empty when the
    /// entry only documents a special-cased key.
    pub codes: &'static [KeyCode],
    /// Action produced when one of `codes` is pressed in normal mode.
    pub action: Option<UiAction>,
}

/// Contextual short label for the normal-mode reload key.
#[must_use]
pub const fn reload_hint(view: ViewId) -> &'static str {
    if matches!(view, ViewId::TrafficTests) {
        "reload suite"
    } else {
        "refresh"
    }
}

/// Description of the binding actually active in this view.
#[must_use]
pub fn help_description(view: ViewId, entry: &HelpEntry) -> &'static str {
    if view == ViewId::TrafficTests && matches!(entry.action, Some(UiAction::RefreshRequested)) {
        "reload default traffic suite"
    } else {
        entry.desc
    }
}

/// Grouped catalog of key bindings: the single source of truth for both the
/// normal-mode key translation and the help overlay.
pub const HELP: &[(&str, &[HelpEntry])] = &[
    (
        "Navigation",
        &[
            HelpEntry {
                keys: "j / ↓",
                desc: "move selection down",
                codes: &[KeyCode::Char('j'), KeyCode::Down],
                action: Some(UiAction::MoveSelection(1)),
            },
            HelpEntry {
                keys: "k / ↑",
                desc: "move selection up",
                codes: &[KeyCode::Char('k'), KeyCode::Up],
                action: Some(UiAction::MoveSelection(-1)),
            },
            HelpEntry {
                keys: "g / Home",
                desc: "first row",
                codes: &[KeyCode::Char('g'), KeyCode::Home],
                action: Some(UiAction::SelectFirst),
            },
            HelpEntry {
                keys: "G / End",
                desc: "last row",
                codes: &[KeyCode::Char('G'), KeyCode::End],
                action: Some(UiAction::SelectLast),
            },
            HelpEntry {
                keys: "PgDn",
                desc: "page down",
                codes: &[KeyCode::PageDown],
                action: Some(UiAction::Page(1)),
            },
            HelpEntry {
                keys: "PgUp",
                desc: "page up",
                codes: &[KeyCode::PageUp],
                action: Some(UiAction::Page(-1)),
            },
            HelpEntry {
                keys: "0-9",
                desc: "switch view (clears filter)",
                codes: &[],
                action: None,
            },
            HelpEntry {
                keys: "p",
                desc: "open policy workspace",
                codes: &[KeyCode::Char('p')],
                action: Some(UiAction::SwitchView(ViewId::Policies)),
            },
        ],
    ),
    (
        "Actions",
        &[
            HelpEntry {
                keys: "enter",
                desc: "select zone / row details",
                codes: &[KeyCode::Enter],
                action: Some(UiAction::ActivateRow),
            },
            HelpEntry {
                keys: "i",
                desc: "inspect selected zone",
                codes: &[KeyCode::Char('i')],
                action: Some(UiAction::InspectZone),
            },
            HelpEntry {
                keys: "t",
                desc: "runtime ⇄ permanent view",
                codes: &[KeyCode::Char('t')],
                action: Some(UiAction::ToggleConfigView),
            },
            HelpEntry {
                keys: ":",
                desc: "command palette",
                codes: &[KeyCode::Char(':')],
                action: Some(UiAction::OpenPalette),
            },
            HelpEntry {
                keys: "/",
                desc: "filter rows",
                codes: &[KeyCode::Char('/')],
                action: Some(UiAction::EnterFilterMode),
            },
            HelpEntry {
                keys: "ctrl-f",
                desc: "global search (all views)",
                codes: &[],
                action: None,
            },
            HelpEntry {
                keys: "r",
                desc: "refresh data now",
                codes: &[KeyCode::Char('r')],
                action: Some(UiAction::RefreshRequested),
            },
            HelpEntry {
                keys: "ctrl-r",
                desc: "reload firewalld",
                codes: &[],
                action: None,
            },
        ],
    ),
    (
        "Mutations",
        &[
            HelpEntry {
                keys: "a",
                desc: "add entry (contextual)",
                codes: &[KeyCode::Char('a')],
                action: Some(UiAction::AddEntry),
            },
            HelpEntry {
                keys: "c",
                desc: "clone row into add form",
                codes: &[KeyCode::Char('c')],
                action: Some(UiAction::CloneEntry),
            },
            HelpEntry {
                keys: "d",
                desc: "delete entry (confirmed)",
                codes: &[KeyCode::Char('d')],
                action: Some(UiAction::DeleteEntry),
            },
            HelpEntry {
                keys: "space",
                desc: "mark / unmark row",
                codes: &[KeyCode::Char(' ')],
                action: Some(UiAction::ToggleMark),
            },
            HelpEntry {
                keys: "m",
                desc: "toggle masquerade",
                codes: &[KeyCode::Char('m')],
                action: Some(UiAction::ToggleMasqueradeRequested),
            },
            HelpEntry {
                keys: "Y",
                desc: "yank row to clipboard",
                codes: &[KeyCode::Char('Y')],
                action: Some(UiAction::YankRow),
            },
            HelpEntry {
                keys: "y",
                desc: "keep changes (cancel rollback)",
                codes: &[KeyCode::Char('y')],
                action: Some(UiAction::KeepChanges),
            },
            HelpEntry {
                keys: "u",
                desc: "roll back last change now (during a countdown)",
                codes: &[KeyCode::Char('u')],
                action: Some(UiAction::RollbackNow),
            },
            HelpEntry {
                keys: "U",
                desc: "undo the last applied change",
                codes: &[KeyCode::Char('U')],
                action: Some(UiAction::UndoLastOperation),
            },
        ],
    ),
    (
        "General",
        &[
            HelpEntry {
                keys: "?",
                desc: "toggle this help",
                codes: &[KeyCode::Char('?')],
                action: Some(UiAction::OpenHelp),
            },
            HelpEntry {
                keys: "esc",
                desc: "close / cancel / clear filter",
                codes: &[],
                action: None,
            },
            HelpEntry {
                keys: "y / n",
                desc: "confirm / cancel dialogs",
                codes: &[],
                action: None,
            },
            HelpEntry {
                keys: "q · ctrl-c",
                desc: "quit",
                codes: &[KeyCode::Char('q')],
                action: Some(UiAction::Quit),
            },
        ],
    ),
];

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::domain::mock;
    use crate::ui::palette::PaletteState;

    fn state() -> UiState {
        let mut state = UiState::new(&Config::default(), "test".into(), false, None);
        state.snapshot = Some(std::sync::Arc::new(mock::sample().unwrap()));
        state
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn digits_switch_views() {
        let s = state();
        assert_eq!(
            translate(&s, press(KeyCode::Char('1'))),
            Some(UiAction::SwitchView(ViewId::Services))
        );
        assert_eq!(
            translate(&s, press(KeyCode::Char('9'))),
            Some(UiAction::SwitchView(ViewId::Logs))
        );
    }

    #[test]
    fn p_opens_policy_workspace() {
        let s = state();
        assert_eq!(
            translate(&s, press(KeyCode::Char('p'))),
            Some(UiAction::SwitchView(ViewId::Policies))
        );
    }

    #[test]
    fn colon_opens_palette() {
        let s = state();
        assert_eq!(
            translate(&s, press(KeyCode::Char(':'))),
            Some(UiAction::OpenPalette)
        );
    }

    #[test]
    fn ctrl_c_always_quits() {
        let mut s = state();
        s.mode = InputMode::Filter;
        let key = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        // Unconditional: the emergency exit never routes through the quit
        // confirmation (that's `q`'s job).
        assert_eq!(translate(&s, key), Some(UiAction::QuitConfirmed));
    }

    #[test]
    fn typing_in_filter_mode_produces_input() {
        let mut s = state();
        s.mode = InputMode::Filter;
        assert_eq!(
            translate(&s, press(KeyCode::Char('q'))),
            Some(UiAction::InputChar('q')),
            "q must type into the filter, not quit"
        );
    }

    #[test]
    fn typing_in_palette_produces_palette_input() {
        let mut s = state();
        s.overlays.push(Overlay::Palette(PaletteState::default()));
        assert_eq!(
            translate(&s, press(KeyCode::Char('q'))),
            Some(UiAction::PaletteInput('q'))
        );
        assert_eq!(
            translate(&s, press(KeyCode::Enter)),
            Some(UiAction::PaletteExecute)
        );
        assert_eq!(
            translate(&s, press(KeyCode::Esc)),
            Some(UiAction::CloseOverlay)
        );
    }

    #[test]
    fn confirm_overlay_only_accepts_y_n_esc() {
        use crate::ui::overlays::Confirmation;
        let mut s = state();
        s.overlays.push(Overlay::Confirm(Confirmation {
            title: "t".into(),
            body: vec![],
            on_confirm: UiAction::Quit,
        }));
        assert_eq!(
            translate(&s, press(KeyCode::Char('y'))),
            Some(UiAction::ConfirmAccept)
        );
        assert_eq!(
            translate(&s, press(KeyCode::Char('n'))),
            Some(UiAction::CloseOverlay)
        );
        assert_eq!(translate(&s, press(KeyCode::Char('j'))), None);
    }

    #[test]
    fn space_marks_and_m_masquerades() {
        let s = state();
        assert_eq!(
            translate(&s, press(KeyCode::Char(' '))),
            Some(UiAction::ToggleMark)
        );
        assert_eq!(
            translate(&s, press(KeyCode::Char('m'))),
            Some(UiAction::ToggleMasqueradeRequested)
        );
    }

    #[test]
    fn help_table_is_the_live_binding_table() {
        let s = state();
        let mut seen = Vec::new();
        for entry in HELP.iter().flat_map(|(_, entries)| entries.iter()) {
            assert_eq!(
                entry.codes.is_empty(),
                entry.action.is_none(),
                "`{}`: live bindings need codes AND an action; informational entries neither",
                entry.keys
            );
            for code in entry.codes {
                assert!(
                    !seen.contains(code),
                    "{code:?} bound twice — lookup would shadow"
                );
                seen.push(*code);
                // Every table binding must translate to its own action.
                assert_eq!(translate(&s, press(*code)), entry.action.clone());
            }
        }
    }

    #[test]
    fn overlay_swallows_view_switching_but_scrolls() {
        let mut s = state();
        s.overlays.push(Overlay::Help);
        // View-switch / mutation keys are swallowed by the modal...
        assert_eq!(translate(&s, press(KeyCode::Char('1'))), None);
        assert_eq!(translate(&s, press(KeyCode::Char('a'))), None);
        // ...but j/k and arrows scroll the (possibly overflowing) modal.
        assert_eq!(
            translate(&s, press(KeyCode::Char('j'))),
            Some(UiAction::ScrollOverlay(1))
        );
        assert_eq!(
            translate(&s, press(KeyCode::Up)),
            Some(UiAction::ScrollOverlay(-1))
        );
        assert_eq!(
            translate(&s, press(KeyCode::Esc)),
            Some(UiAction::CloseOverlay)
        );
    }
}
