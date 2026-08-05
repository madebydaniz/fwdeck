//! Widget builders for the four fixed chrome regions: context header,
//! breadcrumb, sidebar, main table, and the bottom command line.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, Cell, Paragraph, Row, Table};
use strum::IntoEnumIterator;

use super::state::{InputMode, ToastKind, UiState};
use super::theme::Theme;
use super::views::ViewId;

/// Top header: context block, optional key hints, and the brand block.
pub fn render_header(f: &mut Frame, area: Rect, state: &UiState, theme: &Theme) {
    let [context, keys, brand] = Layout::horizontal([
        Constraint::Length(46),
        Constraint::Min(20),
        Constraint::Length(24),
    ])
    .areas(area);

    render_context_block(f, context, state, theme);
    if state.show_help_bar {
        render_key_hints(f, keys, theme);
    }
    render_brand_block(f, brand, state, theme);
}

fn kv(key: &str, value: Span<'static>, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!(" {key:<11}"), theme.muted()),
        value,
    ])
}

fn render_context_block(f: &mut Frame, area: Rect, state: &UiState, theme: &Theme) {
    let snapshot = state.snapshot.as_deref();
    let zone_text = state.effective_zone().map_or_else(
        || "-".to_owned(),
        |zone| {
            let mut markers = Vec::new();
            if let Some(snap) = snapshot {
                if snap.is_active(&zone) {
                    markers.push("active");
                }
                if zone == snap.default_zone {
                    markers.push("default");
                }
            }
            if markers.is_empty() {
                zone.to_string()
            } else {
                format!("{zone} ({})", markers.join(", "))
            }
        },
    );
    let synced = snapshot.is_some_and(crate::domain::FirewallSnapshot::all_synced);
    let panic_mode = snapshot.is_some_and(|s| s.status.panic_mode);
    let state_span = if state.offline {
        Span::styled("offline · permanent config only".to_owned(), theme.warn())
    } else if panic_mode {
        Span::styled(
            "PANIC MODE — all packets dropped".to_owned(),
            theme.danger(),
        )
    } else if snapshot.is_none() {
        Span::styled("no data".to_owned(), theme.muted())
    } else if synced {
        Span::styled("runtime + permanent · synced".to_owned(), theme.ok())
    } else {
        Span::styled("runtime + permanent · different".to_owned(), theme.warn())
    };

    let lines = vec![
        kv(
            "Context:",
            Span::styled(state.hostname.clone(), theme.info()),
            theme,
        ),
        kv(
            "Backend:",
            Span::styled(
                snapshot
                    .map_or("-", |s| s.status.backend.as_str())
                    .to_owned(),
                theme.info(),
            ),
            theme,
        ),
        kv("Zone:", Span::styled(zone_text, theme.info()), theme),
        kv("State:", state_span, theme),
        kv(
            "LogDenied:",
            Span::styled(
                snapshot
                    .map_or("-", |s| s.status.log_denied.as_str())
                    .to_owned(),
                theme.info(),
            ),
            theme,
        ),
    ];
    f.render_widget(Paragraph::new(lines), area);
}

fn hint(key: &'static str, desc: &'static str, theme: &Theme) -> Vec<Span<'static>> {
    vec![
        Span::styled(
            format!("{key:<8}", key = format!("<{key}>")),
            theme.hotkey(),
        ),
        Span::styled(format!("{desc:<12}"), theme.muted()),
    ]
}

fn render_key_hints(f: &mut Frame, area: Rect, theme: &Theme) {
    let pairs: [[(&str, &str); 2]; 5] = [
        [("0-9", "view"), ("j/k", "move")],
        [(":", "command"), ("g/G", "first/last")],
        [("/", "filter"), ("enter", "select")],
        [("?", "help"), ("r", "refresh")],
        [("q", "quit"), ("esc", "back")],
    ];
    let lines: Vec<Line> = pairs
        .iter()
        .map(|pair| {
            let mut spans = Vec::new();
            for (key, desc) in pair {
                spans.extend(hint(key, desc, theme));
            }
            Line::from(spans)
        })
        .collect();
    f.render_widget(Paragraph::new(lines).alignment(Alignment::Center), area);
}

fn render_brand_block(f: &mut Frame, area: Rect, state: &UiState, theme: &Theme) {
    let (zones, active) = state
        .snapshot
        .as_deref()
        .map_or((0, 0), |s| (s.zone_names().len(), s.active.len()));
    let denied = state.denied_session.to_string();
    let lines = vec![
        Line::from(vec![
            Span::styled("FWDECK ", theme.brand()),
            Span::styled(format!("v{} ", env!("CARGO_PKG_VERSION")), theme.accent()),
            Span::styled("· firewalld ", theme.muted()),
        ]),
        Line::from(Span::styled(format!("zones: {zones} "), theme.text())),
        Line::from(Span::styled(format!("active: {active} "), theme.ok())),
        Line::from(vec![
            Span::styled("denied (session): ".to_owned(), theme.muted()),
            Span::styled(format!("{denied} "), theme.danger()),
        ]),
        Line::from(Span::styled(
            state.last_refresh.as_ref().map_or_else(
                || "refresh: — ".to_owned(),
                |observation| {
                    observation.process_count.map_or_else(
                        || format!("refresh: {}ms ", observation.elapsed.as_millis()),
                        |count| {
                            format!(
                                "refresh: {}ms · {count} cmd ",
                                observation.elapsed.as_millis()
                            )
                        },
                    )
                },
            ),
            theme.muted(),
        )),
    ];
    f.render_widget(Paragraph::new(lines).alignment(Alignment::Right), area);
}

/// One-line breadcrumb: zone › view, filter, target, perspective, and status chips.
pub fn render_breadcrumb(f: &mut Frame, area: Rect, state: &UiState, theme: &Theme) {
    let zone = state
        .effective_zone()
        .map_or_else(|| "-".to_owned(), |z| z.to_string());
    let count = state.visible_rows().len();
    let filter = &state.view_state().filter;

    let mut spans = vec![
        Span::styled(" <fw> ", theme.brand()),
        Span::styled(zone, theme.info()),
        Span::styled(" › ", theme.muted()),
        Span::styled(state.view.title(), theme.text()),
        Span::styled(format!(" ({count})"), theme.muted()),
    ];
    if !filter.is_empty() {
        spans.push(Span::styled(format!("  /{filter}"), theme.warn()));
    }
    spans.push(Span::styled(
        format!("  · {}", state.target.label()),
        theme.muted(),
    ));
    if state.config_view == crate::domain::ConfigurationTarget::Permanent {
        spans.push(Span::styled("  [viewing: permanent]", theme.warn()));
    } else {
        spans.push(Span::styled("  [viewing: runtime]", theme.muted()));
    }
    let marked = state.view_state().marked.len();
    if marked > 0 {
        spans.push(Span::styled(format!("  ✓ {marked} marked"), theme.accent()));
    }
    if let Some(snapshot) = &state.snapshot
        && !snapshot.degraded.is_empty()
    {
        // Honest-state chip: these observations are unknown, not empty.
        spans.push(Span::styled(
            format!("  ⚠ {} observation warning(s)", snapshot.degraded.len()),
            theme.warn(),
        ));
    }
    if !state.staged.is_empty() {
        spans.push(Span::styled(
            format!("  ⊕ {} staged", state.staged.len()),
            theme.accent(),
        ));
    }
    if !state.undo_stack.is_empty() {
        spans.push(Span::styled(
            format!("  ↩ {} undoable", state.undo_stack.len()),
            theme.accent(),
        ));
    }
    if state.refreshing {
        spans.push(Span::styled("  ⟳ refreshing", theme.info()));
    }
    f.render_widget(Paragraph::new(Line::from(spans)).style(theme.panel()), area);
}

/// Sidebar listing every view with its hotkey and row count.
pub fn render_sidebar(f: &mut Frame, area: Rect, state: &UiState, theme: &Theme) {
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme.border())
        .title(Span::styled(" Views ", theme.muted()));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let name_width = usize::from(inner.width.saturating_sub(10));
    let lines: Vec<Line> = ViewId::iter()
        .map(|view| {
            let is_current = view == state.view;
            let count = state.view_count(view).to_string();
            let marker = if is_current { "▸" } else { " " };
            let spans = vec![
                Span::styled(format!("{marker} "), theme.accent()),
                Span::styled(format!("<{}> ", view.shortcut()), theme.hotkey()),
                Span::styled(
                    format!("{title:<name_width$}", title = view.title()),
                    if is_current {
                        theme.text()
                    } else {
                        theme.muted()
                    },
                ),
                Span::styled(format!("{count:>3}"), theme.info()),
            ];
            let line = Line::from(spans);
            if is_current {
                line.style(theme.selected())
            } else {
                line
            }
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

/// Colors a cell by its semantic value (accept/drop/runtime/…).
fn value_cell<'a>(text: String, theme: &Theme) -> Cell<'a> {
    let style = match text.as_str() {
        "yes" | "both" | "accept" | "ACCEPT" => theme.ok(),
        "DROP" | "%%REJECT%%" | "REJECT" | "DENIED" | "reject" | "drop" | "broken" => {
            theme.danger()
        }
        "runtime" | "permanent" | "disabled" | "inactive" | "?" => theme.warn(),
        _ => theme.text(),
    };
    Cell::from(Span::styled(text, style))
}

/// The main table for the current view, or a placeholder when there is no
/// data / no matching rows. Mutates only the view's scroll offset.
pub fn render_table(f: &mut Frame, area: Rect, state: &mut UiState, theme: &Theme) {
    let view = state.view;
    let rows_data = state.visible_rows();
    let filter = state.view_state().filter.clone();
    let count = rows_data.len();

    let title = if view == ViewId::Direct {
        format!(" {}({count}) — deprecated ", view.title())
    } else {
        format!(" {}({count}) ", view.title())
    };
    let mut block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme.border_focused())
        .title(Span::styled(
            title,
            if view == ViewId::Direct {
                theme.warn()
            } else {
                theme.info()
            },
        ));
    // Discoverability hint on the bottom border — column widths can't truncate it.
    if let Some(hint) = add_hint(view) {
        block = block.title_bottom(Span::styled(format!(" {hint} "), theme.muted()));
    }

    if state.snapshot.is_none() && view != ViewId::Logs {
        let (message, style) = state.backend_error.as_ref().map_or_else(
            || {
                (
                    "loading firewall state…\n\npress ? for keys · : for commands".to_owned(),
                    theme.muted(),
                )
            },
            |error| (error.to_string(), theme.danger()),
        );
        render_placeholder(f, area, block, message, style);
        return;
    }
    if rows_data.is_empty() {
        let message = if filter.is_empty() {
            empty_message(view, state)
        } else {
            format!("no rows match `/{filter}`")
        };
        render_placeholder(f, area, block, message, theme.muted());
        return;
    }

    let header = Row::new(
        view.columns()
            .iter()
            .map(|c| Cell::from(Span::styled(*c, theme.header()))),
    );
    // Zones view: dim rows that are neither active nor the default zone
    // (SYNC=1, ACTIVE=2, DEFAULT=3 after the name column).
    let is_dim = |row: &[String]| {
        view == ViewId::Zones
            && row.get(2).is_none_or(String::is_empty)
            && row.get(3).is_none_or(String::is_empty)
    };
    let marked = &state.view_state().marked;
    let rows: Vec<Row> = rows_data
        .iter()
        .map(|row| {
            let is_marked = marked.contains(&row.id);
            if is_dim(row) {
                return Row::new(
                    row.iter()
                        .map(|text| Cell::from(Span::styled(text.clone(), theme.muted()))),
                );
            }
            Row::new(row.iter().enumerate().map(|(i, text)| {
                if i == 0 {
                    // Prefix a check mark on the identity column when marked.
                    let label = if is_marked {
                        format!("✓ {text}")
                    } else {
                        text.clone()
                    };
                    let style = if is_marked {
                        theme.accent()
                    } else {
                        theme.text()
                    };
                    Cell::from(Span::styled(label, style))
                } else {
                    value_cell(text.clone(), theme)
                }
            }))
        })
        .collect();

    let selected = state.view_state().selected.min(count - 1);
    let view_state = &mut state.views[view.index()];
    view_state.table.select(Some(selected));

    let table = Table::new(rows, view.widths())
        .header(header)
        .column_spacing(2)
        .block(block)
        .row_highlight_style(theme.selected())
        .highlight_symbol("▸ ");
    f.render_stateful_widget(table, area, &mut view_state.table);
}

fn render_placeholder(
    f: &mut Frame,
    area: Rect,
    block: Block,
    message: String,
    style: ratatui::style::Style,
) {
    let text = Text::from(vec![
        Line::default(),
        Line::default(),
        Line::styled(message, style),
    ]);
    f.render_widget(
        Paragraph::new(text)
            .alignment(Alignment::Center)
            .block(block),
        area,
    );
}

/// Bottom-border hint advertising the view's `a` (add) action.
const fn add_hint(view: ViewId) -> Option<&'static str> {
    match view {
        ViewId::Zones => Some("+ create zone (a)"),
        ViewId::Services => Some("+ add service (a)"),
        ViewId::Ports => Some("+ add port (a)"),
        ViewId::Forwarding => Some("+ add forward port (a)"),
        ViewId::RichRules => Some("+ add rich rule (a)"),
        ViewId::Interfaces => Some("+ bind interface (a)"),
        ViewId::Sources => Some("+ bind source (a)"),
        ViewId::IpSets => Some("+ add entry / create ipset (a)"),
        ViewId::Policies => Some("+ add service / create policy (a)"),
        ViewId::Direct => Some("+ migrate eligible rule (a)"),
        ViewId::Logs => None,
    }
}

/// View-specific message for an empty (unfiltered) table.
fn empty_message(view: ViewId, state: &UiState) -> String {
    let zone = state
        .effective_zone()
        .map_or_else(|| "-".to_owned(), |z| z.to_string());
    match view {
        ViewId::Zones => "no zones reported".to_owned(),
        ViewId::Services => format!("no services in zone `{zone}`"),
        ViewId::Ports => format!("no ports in zone `{zone}`"),
        ViewId::Forwarding => format!("no forward ports in zone `{zone}`"),
        ViewId::RichRules => format!("no rich rules in zone `{zone}`"),
        ViewId::Interfaces => "no active interfaces".to_owned(),
        ViewId::Sources => "no sources bound to any zone".to_owned(),
        ViewId::IpSets => "no ipsets defined — `a` creates one (permanent, then reload)".to_owned(),
        ViewId::Policies => {
            "no policies defined — `a` creates one (permanent, then reload)".to_owned()
        }
        ViewId::Direct => "no direct rules (deprecated feature — prefer rich rules)".to_owned(),
        ViewId::Logs => {
            let log_denied_off = state
                .snapshot
                .as_deref()
                .is_none_or(|snapshot| snapshot.status.log_denied == crate::domain::LogDenied::Off);
            if log_denied_off {
                "LogDenied is off — enable it via the palette (`set logdenied`) to see denied packets"
                    .to_owned()
            } else {
                "waiting for kernel log entries… press `a` on a denied row to propose an allow rule"
                    .to_owned()
            }
        }
    }
}

/// Bottom command line: filter input, rollback countdown, backend error, or
/// the target/sync summary — plus a right-aligned hint.
pub fn render_command_line(f: &mut Frame, area: Rect, state: &UiState, theme: &Theme) {
    let (left, right_hint): (Line, &str) = match state.mode {
        InputMode::Filter => (
            Line::from(vec![
                Span::styled(" /", theme.warn()),
                Span::styled(state.view_state().filter.clone(), theme.text()),
                Span::styled("█", theme.warn()),
            ]),
            "enter keep · esc clear ",
        ),
        InputMode::Normal => {
            // Only countdowns that actually started: u64::MAX is the arming
            // placeholder while the operation is still applying (a real
            // deadline is set on OperationFinished) — rendering it would show
            // a nonsense number of seconds.
            let started = state
                .pending_rollback
                .iter()
                .filter(|pending| pending.deadline_tick != u64::MAX)
                .min_by_key(|pending| pending.deadline_tick);
            let line = if let Some(pending) = started {
                let remaining = pending.deadline_tick.saturating_sub(state.tick).div_ceil(4);
                Line::from(vec![
                    Span::styled(
                        format!(" ⏱ auto-rollback in {remaining}s: {} ", pending.description),
                        theme.danger(),
                    ),
                    Span::styled("· ", theme.muted()),
                    Span::styled("y", theme.ok()),
                    Span::styled(" keep · ", theme.muted()),
                    Span::styled("u", theme.warn()),
                    Span::styled(" undo now", theme.muted()),
                ])
            } else if let Some(pending) = state.pending_rollback.first() {
                // Armed, still applying — no meaningful ETA yet.
                Line::from(Span::styled(
                    format!(" ⏱ rollback armed — applying: {} ", pending.description),
                    theme.warn(),
                ))
            } else if let Some(error) = &state.backend_error {
                Line::from(Span::styled(format!(" {error}"), theme.danger()))
            } else {
                let synced = state
                    .snapshot
                    .as_deref()
                    .is_some_and(crate::domain::FirewallSnapshot::all_synced);
                let mut spans = vec![
                    Span::styled(format!(" {}", state.target.label()), theme.text()),
                    Span::styled(" · ", theme.muted()),
                    if synced {
                        Span::styled("synced", theme.ok())
                    } else {
                        Span::styled("different", theme.warn())
                    },
                ];
                if state.read_only {
                    let label = state.read_only_reason.as_deref().map_or_else(
                        || " · read-only".to_owned(),
                        |reason| format!(" · read-only ({reason})"),
                    );
                    spans.push(Span::styled(label, theme.danger()));
                }
                Line::from(spans)
            };
            (line, ": palette · / filter · ? help ")
        }
    };

    let hint_width = u16::try_from(right_hint.len()).unwrap_or(0).min(area.width);
    let [left_area, right_area] =
        Layout::horizontal([Constraint::Min(10), Constraint::Length(hint_width)]).areas(area);
    f.render_widget(Paragraph::new(left).style(theme.deep()), left_area);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(right_hint, theme.muted())))
            .style(theme.deep())
            .alignment(Alignment::Right),
        right_area,
    );
}

/// Floating toast stack, top-right under the breadcrumb. Newest last.
pub fn render_toasts(f: &mut Frame, screen: Rect, state: &UiState, theme: &Theme) {
    let visible = state.toasts.iter().rev().take(3).rev();
    for (index, toast) in visible.enumerate() {
        let (symbol, style) = match toast.kind {
            ToastKind::Success => ("✓", theme.ok()),
            ToastKind::Error => ("✗", theme.danger()),
            ToastKind::Warning => ("!", theme.warn()),
            ToastKind::Info => ("·", theme.info()),
        };
        let text = format!(" {symbol} {} ", toast.text);
        let width = u16::try_from(text.chars().count())
            .unwrap_or(u16::MAX)
            .min(screen.width.saturating_sub(2));
        let y = screen.y + 7 + u16::try_from(index).unwrap_or(0);
        if y >= screen.y + screen.height.saturating_sub(1) {
            break;
        }
        let area = Rect {
            x: screen.x + screen.width.saturating_sub(width + 1),
            y,
            width,
            height: 1,
        };
        f.render_widget(ratatui::widgets::Clear, area);
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(text, style))).style(theme.panel()),
            area,
        );
    }
}
