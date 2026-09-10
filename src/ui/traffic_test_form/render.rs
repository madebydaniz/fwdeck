//! Width-aware local form and full review viewport.

use super::{Draft, EditKind, Editor, Field, Stage};
use crate::ui::theme::Theme;
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, BorderType, Clear, Paragraph},
};

pub(in crate::ui) fn render(frame: &mut Frame, editor: &mut Editor, theme: &Theme, screen: Rect) {
    let available = screen.width.saturating_sub(2).max(1);
    let width = (screen.width.saturating_mul(60) / 100)
        .max(60.min(available))
        .min(available);
    let height = screen.height.saturating_sub(2).max(1);
    let area = Rect::new(
        screen.x + screen.width.saturating_sub(width) / 2,
        screen.y + screen.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .title(title(editor))
        .style(theme.panel())
        .border_style(theme.border_focused());
    let inner = block.inner(area);
    frame.render_widget(Clear, area);
    frame.render_widget(block, area);
    let footer_lines = wrap(footer(editor), usize::from(inner.width));
    let footer_height = u16::try_from(footer_lines.len())
        .unwrap_or(u16::MAX)
        .min(inner.height);
    let body = Rect {
        height: inner.height.saturating_sub(footer_height),
        ..inner
    };
    let footer_area = Rect {
        y: inner.y + body.height,
        height: footer_height,
        ..inner
    };
    let (lines, focus) = content(editor, usize::from(inner.width), theme);
    let max_scroll = lines.len().saturating_sub(usize::from(body.height));
    let offset = if editor.stage == Stage::Draft && editor.discard.is_none() {
        focus
            .map_or(0, |(start, end)| {
                end.saturating_sub(usize::from(body.height)).min(start)
            })
            .min(max_scroll)
    } else {
        usize::from(editor.scroll).min(max_scroll)
    };
    editor.scroll = u16::try_from(offset).unwrap_or(u16::MAX);
    let mut visible: Vec<_> = lines
        .iter()
        .skip(offset)
        .take(usize::from(body.height))
        .cloned()
        .collect();
    if let Some((start, end)) = focus
        && body.height > 0
    {
        let mut cursor_row = end.saturating_sub(1 + offset);
        if end - start > usize::from(body.height) {
            visible = vec![lines[start].clone()];
            visible.extend(
                lines
                    .iter()
                    .take(end)
                    .skip(end - usize::from(body.height) + 1)
                    .cloned(),
            );
            cursor_row = visible.len().saturating_sub(1);
        }
        if matches!(
            editor.draft.fields().get(editor.draft.focus),
            Some(
                Field::Name
                    | Field::Source
                    | Field::IngressValue
                    | Field::DestinationPort
                    | Field::SourcePort
                    | Field::Icmp
                    | Field::Protocol
                    | Field::Note
            )
        ) {
            let column = lines[end - 1]
                .width()
                .min(usize::from(body.width.saturating_sub(1)));
            frame.set_cursor_position((
                body.x + u16::try_from(column).unwrap_or(0),
                body.y + u16::try_from(cursor_row).unwrap_or(0),
            ));
        }
    }
    frame.render_widget(Paragraph::new(visible), body);
    frame.render_widget(
        Paragraph::new(footer_lines).style(theme.info()),
        footer_area,
    );
}

fn title(editor: &Editor) -> &'static str {
    if editor.discard.is_some() {
        return "Discard local draft?";
    }
    match editor.stage {
        Stage::Draft => "Local traffic scenario",
        Stage::Review => "Review local traffic change",
        Stage::Pending => "Saving local traffic suite",
        Stage::Failed => "Local save failed; reload required",
    }
}

fn footer(editor: &Editor) -> &'static str {
    if editor.discard.is_some() {
        return "y Discard  n/Esc Keep draft";
    }
    match editor.stage {
        Stage::Draft => "Tab/arrows fields  Enter Review  Esc Cancel",
        Stage::Review => "y Save  Esc Back  arrows/PgUp/PgDn scroll",
        Stage::Pending => "Save pending; conflicting actions disabled",
        Stage::Failed => "Esc Discard  Ctrl-C Emergency exit",
    }
}

fn content(
    editor: &Editor,
    width: usize,
    theme: &Theme,
) -> (Vec<Line<'static>>, Option<(usize, usize)>) {
    if editor.discard.is_some() {
        return (
            wrap(
                "Discard this unsaved local draft and continue? No local file or firewall changes will be made by discarding.",
                width,
            ),
            None,
        );
    }
    let mut lines = wrap(
        "Configuration evaluation\nLive connectivity: NOT VERIFIED\nRequired gates: not enforced in Phase 2",
        width,
    );
    if editor.draft.metadata_only() {
        lines.extend(wrap(
            "Reserved inputs preserved: metadata-only editing (name, severity, enabled, note).",
            width,
        ));
    }
    if let Some(error) = &editor.error {
        lines.extend(
            wrap(error, width)
                .into_iter()
                .map(|line| line.style(theme.danger())),
        );
    }
    let mut focus = None;
    if editor.stage == Stage::Draft {
        for (index, field) in editor.draft.fields().iter().enumerate() {
            let selected = index == editor.draft.focus;
            let start = lines.len();
            let label = format!(
                "{} {}: {}",
                if selected { ">" } else { " " },
                label(*field),
                value(&editor.draft, *field)
            );
            lines.extend(wrap(&label, width).into_iter().map(|line| {
                if selected {
                    line.style(theme.info())
                } else {
                    line
                }
            }));
            if selected {
                focus = Some((start, lines.len()));
            }
        }
    } else {
        lines.extend(
            review(editor)
                .into_iter()
                .flat_map(|line| wrap(&line, width)),
        );
    }
    (lines, focus)
}

fn label(field: Field) -> &'static str {
    match field {
        Field::Name => "Name",
        Field::Source => "Source IP/CIDR",
        Field::Ingress => "Ingress mode (review explicitly)",
        Field::IngressValue => "Ingress value",
        Field::Transport => "Transport",
        Field::DestinationPort => "Destination port/range",
        Field::SourcePort => "Source port/range (optional)",
        Field::Icmp => "ICMP type",
        Field::Protocol => "Raw IP protocol",
        Field::Expectation => "Expected result",
        Field::Severity => "Severity",
        Field::Enabled => "Enabled",
        Field::Note => "Note",
    }
}

fn value(draft: &Draft, field: Field) -> String {
    match field {
        Field::Name => draft.name.clone(),
        Field::Source => draft.source.clone(),
        Field::IngressValue => draft.ingress_value.clone(),
        Field::DestinationPort => draft.destination_port.clone(),
        Field::SourcePort => draft.source_port.clone(),
        Field::Icmp => draft.icmp.clone(),
        Field::Protocol => draft.protocol.clone(),
        Field::Note => draft.note.clone(),
        Field::Ingress => ["unspecified", "zone", "interface"]
            .get(draft.ingress)
            .unwrap_or(&"invalid")
            .to_string(),
        Field::Transport => ["TCP", "UDP", "ICMP", "raw"]
            .get(draft.transport)
            .unwrap_or(&"invalid")
            .to_string(),
        Field::Expectation => format!("{:?}", draft.expectation),
        Field::Severity => format!("{:?}", draft.severity),
        Field::Enabled => draft.enabled.to_string(),
    }
}

fn review(editor: &Editor) -> Vec<String> {
    let scenario = if editor.kind == EditKind::Delete {
        editor.draft.original.as_ref()
    } else {
        editor.candidate.as_ref().and_then(|candidate| {
            editor.draft.original.as_ref().map_or_else(
                || candidate.scenarios.last(),
                |original| {
                    candidate
                        .scenarios
                        .iter()
                        .find(|scenario| scenario.id == original.id)
                },
            )
        })
    };
    let mut lines = vec![format!(
        "Action: {:?}; suite {} ({}) revision {}",
        editor.kind,
        editor.base.name,
        editor.base.id,
        editor.base.revision.get()
    )];
    if let Some(scenario) = scenario {
        lines.extend([
            format!("Name: {} (ID {})", scenario.name, scenario.id),
            format!("Source: {}", scenario.source),
            format!(
                "Ingress zone: {}; interface: {}",
                scenario
                    .ingress_zone
                    .as_ref()
                    .map_or_else(|| "unspecified".into(), ToString::to_string),
                scenario
                    .ingress_interface
                    .as_ref()
                    .map_or_else(|| "unspecified".into(), ToString::to_string)
            ),
            format!("Transport: {:?}", scenario.transport),
            format!(
                "Destination port: {:?}; source port: {:?}",
                scenario.destination_port, scenario.source_port
            ),
            format!(
                "Expected: {:?}; severity: {:?}; enabled: {}",
                scenario.expectation, scenario.severity, scenario.enabled
            ),
            format!(
                "Reserved direction: {:?}; state: {:?}",
                scenario.direction, scenario.connection_state
            ),
            format!("Reserved destination: {:?}", scenario.destination),
            format!(
                "Reserved egress zone: {:?}; interface: {:?}",
                scenario.egress_zone, scenario.egress_interface
            ),
            format!(
                "Required safety gate: {}; not enforced in Phase 2",
                scenario.required_safety_gate
            ),
            format!("Note: {}", scenario.note.as_deref().unwrap_or("")),
        ]);
    }
    lines.push("No firewall changes. No connectivity probes.".into());
    lines.push("Save local file only".into());
    lines
}

fn wrap(text: &str, width: usize) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        let mut line = String::new();
        let mut used = 0;
        for character in paragraph.chars() {
            let columns = Span::raw(character.to_string()).width();
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
