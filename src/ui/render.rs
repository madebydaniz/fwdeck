//! Top-level frame composition. Pure relative to application state: nothing in
//! here executes commands or mutates domain data (only per-view scroll offsets).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::widgets::Block;

use super::components;
use super::overlays;
use super::state::UiState;
use super::theme::Theme;

/// Draws one full frame: chrome regions, sidebar, table, toasts, and the
/// topmost overlay.
pub fn render(f: &mut Frame, state: &mut UiState, theme: &Theme) {
    let area = f.area();
    f.render_widget(Block::new().style(theme.base()), area);

    let [header, breadcrumb, body, command_line] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(area);

    components::render_header(f, header, state, theme);
    components::render_breadcrumb(f, breadcrumb, state, theme);

    // Drop the sidebar on very narrow terminals instead of crushing the table.
    if body.width >= state.sidebar_width + 40 {
        let [sidebar, main] =
            Layout::horizontal([Constraint::Length(state.sidebar_width), Constraint::Min(20)])
                .areas(body);
        components::render_sidebar(f, sidebar, state, theme);
        components::render_table(f, main, state, theme);
    } else {
        components::render_table(f, body, state, theme);
    }

    components::render_command_line(f, command_line, state, theme);
    components::render_toasts(f, area, state, theme);

    if !state.overlays.is_empty() {
        overlays::render(f, state, theme, area);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::domain::mock;
    use crate::ui::action::UiAction;
    use crate::ui::update::update;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn draw(state: &mut UiState, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let theme = Theme::new(crate::ui::theme::Variant::Dracula, true, true);
        terminal.draw(|f| render(f, state, &theme)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect()
    }

    fn state() -> UiState {
        let mut state = UiState::new(&Config::default(), "testhost".into(), false, None);
        state.snapshot = Some(std::sync::Arc::new(mock::sample().unwrap()));
        state
    }

    #[test]
    fn renders_all_chrome_regions() {
        let mut s = state();
        let content = draw(&mut s, 120, 32);
        assert!(content.contains("FWDECK"));
        assert!(content.contains("Context:"));
        assert!(content.contains("Views"));
        assert!(content.contains("Zones"));
        assert!(content.contains("public"));
        assert!(content.contains("different")); // mock has runtime/permanent drift
    }

    #[test]
    fn narrow_terminal_drops_sidebar_without_panic() {
        let mut s = state();
        let content = draw(&mut s, 50, 20);
        assert!(content.contains("Zones"));
    }

    #[test]
    fn tiny_terminal_does_not_panic() {
        let mut s = state();
        let _ = draw(&mut s, 10, 4);
    }

    #[test]
    fn palette_overlay_renders_commands() {
        let mut s = state();
        update(&mut s, UiAction::OpenPalette);
        let content = draw(&mut s, 120, 32);
        assert!(content.contains("Commands"));
        assert!(content.contains("Refresh now"));
    }

    #[test]
    fn zone_overview_shows_drift_per_attribute() {
        let mut s = state();
        update(&mut s, UiAction::InspectZone);
        let content = draw(&mut s, 120, 40);
        assert!(content.contains("overview"));
        assert!(content.contains("masquerade"));
        // public has runtime-only http → services drift into rt/perm lines.
        assert!(content.contains("services (rt)") || content.contains("services (perm)"));
    }

    #[test]
    fn enter_on_zone_opens_overview() {
        use crate::ui::overlays::Overlay;
        let mut s = state();
        update(&mut s, UiAction::ActivateRow);
        assert!(matches!(s.overlays.last(), Some(Overlay::Details(_))));
    }

    #[test]
    fn toasts_are_visible() {
        use crate::ui::state::ToastKind;
        let mut s = state();
        s.toast(ToastKind::Success, "service added");
        let content = draw(&mut s, 120, 32);
        assert!(content.contains("service added"));
    }

    #[test]
    fn help_overlay_renders() {
        let mut s = state();
        update(&mut s, UiAction::OpenHelp);
        let content = draw(&mut s, 120, 32);
        assert!(content.contains("Help"));
        assert!(content.contains("Navigation"));
    }

    #[test]
    fn help_overlay_scrolls_on_a_tiny_terminal() {
        let mut s = state();
        update(&mut s, UiAction::OpenHelp);
        // A short terminal cannot show the whole help — it must scroll, not
        // overflow or panic, and the title must advertise that it scrolls.
        let top = draw(&mut s, 80, 12);
        assert!(top.contains("scroll"), "small help shows a scroll hint");
        assert!(top.contains("Navigation"), "starts at the top");

        // Scroll to the end; later categories become visible and the offset is
        // clamped by the renderer (never past the content).
        update(&mut s, UiAction::ScrollOverlay(i32::MAX));
        let bottom = draw(&mut s, 80, 12);
        assert!(bottom.contains("General"), "end of the help is reachable");
        assert!(s.overlay_scroll > 0 && s.overlay_scroll < u16::MAX);

        // Closing resets the offset.
        update(&mut s, UiAction::CloseOverlay);
        assert_eq!(s.overlay_scroll, 0);
    }

    #[test]
    fn startup_without_snapshot_shows_loading() {
        let mut s = UiState::new(&Config::default(), "testhost".into(), false, None);
        let content = draw(&mut s, 120, 32);
        assert!(content.contains("loading firewall state"));
    }

    #[test]
    fn offline_mode_shows_in_the_header() {
        let config = Config {
            offline: true,
            ..Config::default()
        };
        let mut s = UiState::new(&config, "host".into(), false, None);
        s.snapshot = Some(std::sync::Arc::new(mock::sample().unwrap()));
        let content = draw(&mut s, 120, 32);
        assert!(content.contains("offline"));
    }

    #[test]
    fn backend_error_is_surfaced() {
        use crate::application::ports::FirewallError;
        let mut s = UiState::new(&Config::default(), "testhost".into(), false, None);
        s.backend_error = Some(FirewallError::DaemonNotRunning);
        let content = draw(&mut s, 120, 32);
        assert!(content.contains("firewalld daemon is not running"));
    }

    #[test]
    fn logs_view_hints_when_log_denied_is_off() {
        let mut s = state();
        update(&mut s, UiAction::SwitchView(crate::ui::views::ViewId::Logs));
        let content = draw(&mut s, 120, 32);
        assert!(content.contains("LogDenied is off"));
    }

    #[test]
    fn logs_view_renders_entries() {
        use crate::infrastructure::logs::{LogAction, LogEntry};
        let mut s = state();
        update(
            &mut s,
            UiAction::LogsReceived(vec![LogEntry {
                time: "10:00:00".into(),
                action: LogAction::Reject,
                src: "203.0.113.7".into(),
                dst: "172.17.0.2".into(),
                dport: "23".into(),
                proto: "TCP".into(),
                iface: "eth0".into(),
            }]),
        );
        update(&mut s, UiAction::SwitchView(crate::ui::views::ViewId::Logs));
        let content = draw(&mut s, 120, 32);
        assert!(content.contains("203.0.113.7"));
        assert!(content.contains("REJECT"));
    }

    #[test]
    fn add_hint_is_never_truncated() {
        let mut s = state();
        update(
            &mut s,
            UiAction::SwitchView(crate::ui::views::ViewId::Ports),
        );
        let content = draw(&mut s, 120, 32);
        assert_eq!(
            content.matches("+ add").count(),
            1,
            "hint must render once (border title), never as a truncated row"
        );
        assert!(content.contains("+ add port (a)"));
        update(
            &mut s,
            UiAction::SwitchView(crate::ui::views::ViewId::Forwarding),
        );
        let content = draw(&mut s, 120, 32);
        assert!(content.contains("+ add forward port (a)"));
    }

    #[test]
    fn form_modal_fits_its_label() {
        use crate::ui::overlays::{FormKind, FormState, Overlay};
        let mut s = state();
        s.overlays.push(Overlay::Form(FormState {
            kind: FormKind::AddRichRule,
            buffer: String::new(),
        }));
        let content = draw(&mut s, 160, 40);
        // The long rich-rule example must be visible to its end.
        assert!(content.contains("accept)"), "label must not be truncated");
    }

    #[test]
    fn form_input_keeps_cursor_visible_on_long_input() {
        use crate::ui::overlays::{FormKind, FormState, Overlay};
        let mut s = state();
        let long_rule = format!(
            "rule family=\"ipv4\" source address=\"203.0.113.0/24\" port port=\"{}\" protocol=\"tcp\" reject",
            "8".repeat(60)
        );
        s.overlays.push(Overlay::Form(FormState {
            kind: FormKind::AddRichRule,
            buffer: long_rule,
        }));
        let content = draw(&mut s, 100, 30);
        // The tail of the input (with the closing word) must be on screen.
        assert!(content.contains("reject"), "input tail must stay visible");
        assert!(content.contains('…'), "truncation must be explicit");
    }

    #[test]
    fn service_catalog_overlay_renders() {
        let mut s = state();
        update(&mut s, UiAction::BrowseServices);
        let content = draw(&mut s, 120, 36);
        assert!(content.contains("Service catalog"));
        assert!(content.contains("mysql"));
    }

    #[test]
    fn policy_browse_overlay_renders() {
        let mut s = state();
        update(&mut s, UiAction::BrowsePolicies);
        let content = draw(&mut s, 120, 36);
        assert!(content.contains("Policies"));
        assert!(content.contains("mypolicy"));
        assert!(content.contains("ingress"));
    }

    #[test]
    fn direct_view_shows_deprecation_warning() {
        let mut s = state();
        update(
            &mut s,
            UiAction::SwitchView(crate::ui::views::ViewId::Direct),
        );
        let content = draw(&mut s, 120, 32);
        assert!(content.contains("deprecated"));
        assert!(content.contains("12345"));
    }
}
