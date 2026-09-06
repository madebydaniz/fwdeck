//! Adaptive configuration-evaluation rows with a variable-height viewport.

use crate::ui::{state::UiState, theme::Theme, views::ViewId};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::{Line, Text},
    widgets::{Block, Cell, Paragraph, Row, Table, Wrap},
};

pub(in crate::ui) fn render(frame: &mut Frame, area: Rect, state: &mut UiState, theme: &Theme) {
    let block = Block::bordered()
        .title(" Traffic Tests ")
        .border_style(theme.border_focused());
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let [header, error_area, body] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Length(u16::from(state.traffic.error.is_some())),
        Constraint::Min(1),
    ])
    .areas(inner);
    frame.render_widget(Paragraph::new("Configuration evaluation\nLive connectivity: NOT VERIFIED\nRequired safety gates: not enforced in Phase 2\ne evaluate · r reload · t target · Enter details").wrap(Wrap { trim: false }), header);
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
        let message = if state.view_state().filter.is_empty() {
            state.traffic.message()
        } else {
            "No matching scenarios. Clear filter (Esc).".to_owned()
        };
        frame.render_widget(
            Paragraph::new(format!(
                "{message}\n{}",
                state.traffic.error.as_deref().unwrap_or("")
            ))
            .wrap(Wrap { trim: false }),
            body,
        );
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
        .row_highlight_style(theme.info())
        .highlight_symbol("> ");
    if wide {
        table = table.header(Row::new(ViewId::TrafficTests.columns().iter().copied()));
    }
    let selected = state.view_state().selected;
    state.view_state_mut().table.select(Some(selected));
    frame.render_stateful_widget(table, body, &mut state.view_state_mut().table);
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
