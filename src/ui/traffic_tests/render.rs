//! Adaptive configuration-evaluation rows with a variable-height viewport.

use crate::{
    application::SuiteState,
    ui::{state::UiState, theme::Theme, views::ViewId},
};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Cell, Paragraph, Row, Table, Wrap},
};

pub(in crate::ui) fn render(frame: &mut Frame, area: Rect, state: &mut UiState, theme: &Theme) {
    let count = match &state.traffic.suite {
        SuiteState::Available(suite) => suite.scenarios.len(),
        _ => 0,
    };
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .title(Span::styled(
            format!(" Traffic Tests({count}) "),
            theme.info(),
        ))
        .title_bottom(Span::styled(border_hint(area.width), theme.muted()))
        .border_style(theme.border_focused());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let audit_error = state
        .traffic
        .audit
        .failure
        .map(|error| error.to_string())
        .or_else(|| {
            state.traffic.audit.backpressure.then(|| {
                "Traffic audit backlog full; evaluation paused until persistence progresses".into()
            })
        });
    let [audit_area, error_area, body] = Layout::vertical([
        Constraint::Length(u16::from(audit_error.is_some())),
        Constraint::Length(u16::from(state.traffic.error.is_some())),
        Constraint::Min(1),
    ])
    .areas(inner);
    if let Some(error) = audit_error {
        frame.render_widget(
            Paragraph::new(error)
                .style(theme.danger())
                .wrap(Wrap { trim: false }),
            audit_area,
        );
    }
    if let Some(error) = &state.traffic.error {
        frame.render_widget(
            Paragraph::new(error.as_str())
                .style(theme.danger())
                .wrap(Wrap { trim: false }),
            error_area,
        );
    }
    let rows = state.visible_rows();
    if rows.is_empty() {
        render_empty(frame, body, state, theme);
        return;
    }
    let wide = body.width >= 105;
    let widths: Vec<u16> = if wide {
        vec![body.width.saturating_sub(76), 9, 8, 8, 22, 9, 9]
    } else {
        vec![body.width.saturating_sub(2)]
    };
    let rendered = rows.iter().map(|row| {
        let strings = if wide {
            row.cells().to_vec()
        } else {
            vec![
                row.cells()
                    .iter()
                    .zip(ViewId::TrafficTests.columns())
                    .map(|(value, label)| format!("{label}: {value}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ]
        };
        let cells: Vec<Vec<Line<'static>>> = strings
            .iter()
            .zip(&widths)
            .map(|(text, width)| wrap(text, usize::from(*width)))
            .collect();
        let height = cells.iter().map(Vec::len).max().unwrap_or(1);
        Row::new(cells.into_iter().map(|lines| Cell::from(Text::from(lines))))
            .height(u16::try_from(height).unwrap_or(u16::MAX))
    });
    let mut table = Table::new(rendered, widths.iter().copied().map(Constraint::Length))
        .column_spacing(u16::from(wide))
        .row_highlight_style(theme.selected())
        .highlight_symbol("▸ ");
    if wide {
        table = table
            .header(Row::new(ViewId::TrafficTests.columns().iter().copied()).style(theme.header()));
    }
    let selected = state.view_state().selected;
    state.view_state_mut().table.select(Some(selected));
    frame.render_stateful_widget(table, body, &mut state.view_state_mut().table);
}

fn border_hint(width: u16) -> &'static str {
    let full = " + add test / template (a) · run (e) · reload (r) · target (t) · edit (E) · delete (d) · toggle (Space) ";
    if Line::from(full).width() <= usize::from(width.saturating_sub(2)) {
        full
    } else {
        " + add test / template (a) · run (e) · : more "
    }
}

fn render_empty(frame: &mut Frame, area: Rect, state: &UiState, theme: &Theme) {
    if matches!(
        state.traffic.suite,
        SuiteState::Missing | SuiteState::Available(_)
    ) {
        super::super::components::render_placeholder(
            frame,
            area,
            Block::default(),
            empty_message(state),
            theme.muted(),
        );
    } else {
        frame.render_widget(
            Paragraph::new(empty_message(state))
                .style(theme.muted())
                .wrap(Wrap { trim: false }),
            area,
        );
    }
}

fn empty_message(state: &UiState) -> String {
    if !state.view_state().filter.is_empty() {
        return "No matching scenarios. Clear filter (Esc).".to_owned();
    }
    match state.traffic.suite {
        SuiteState::Missing | SuiteState::Available(_) => "No traffic tests".to_owned(),
        _ => state.traffic.message(),
    }
}

fn wrap(text: &str, width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        let mut line = String::new();
        let mut used = 0;
        for character in paragraph.chars() {
            let columns = Line::from(character.to_string()).width();
            if used + columns > width.max(1) && !line.is_empty() {
                lines.push(Line::from(std::mem::take(&mut line)));
                used = 0;
            }
            line.push(character);
            used += columns;
        }
        lines.push(Line::from(line));
    }
    lines
}
