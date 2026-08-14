//! Modal overlays: help, command palette, details, and confirmation. Rendering
//! only — state lives in `UiState::overlays`, transitions in the reducer.

use ratatui::Frame;
use ratatui::layout::{Alignment, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph, Wrap};

use super::action::UiAction;
pub use super::details::DetailsContent;
use super::keymap;
use super::palette::{self, Availability, PaletteState};
use super::state::UiState;
use super::theme::Theme;

/// One entry of the overlay stack; the topmost is the one rendered.
#[derive(Debug, Clone, PartialEq)]
pub enum Overlay {
    /// Keybinding reference.
    Help,
    /// About screen: version, description, developer, and links.
    About,
    /// Fuzzy-searchable command palette.
    Palette(PaletteState),
    /// Global search across every data view.
    GlobalSearch(super::search::GlobalSearchState),
    /// Key/value details pane (rows, zones, errors, reports).
    Details(DetailsContent),
    /// Yes/stage/no confirmation gate in front of a mutation.
    Confirm(Confirmation),
    /// Single-field text input form.
    Form(FormState),
    /// Guided multi-step rich-rule builder.
    RichBuilder(super::rich_builder::RichBuilder),
}

/// Single-field input form for add-service / add-port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormState {
    /// What the form creates or removes.
    pub kind: FormKind,
    /// The text typed so far.
    pub buffer: String,
}

/// Every single-field form the UI can open; selects title, label, and the
/// parser applied on submit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormKind {
    /// Add a service to the zone.
    AddService,
    /// Open a port/protocol in the zone.
    AddPort,
    /// Add a port-forwarding rule to the zone.
    AddForwardPort,
    /// Add a hand-written rich rule to the zone.
    AddRichRule,
    /// Bind a network interface to the zone.
    AddInterface,
    /// Bind a source (IP/CIDR/MAC/ipset) to the zone.
    AddSource,
    /// Create a new zone (permanent-only).
    CreateZone,
    /// Create a new ipset (permanent-only).
    CreateIpSet,
    /// Add an entry to the selected ipset.
    AddIpSetEntry,
    /// Remove an entry from the selected ipset.
    RemoveIpSetEntry,
    /// Block an ICMP type in the zone.
    AddIcmpBlock,
    /// Set the zone's target (permanent-only).
    SetZoneTarget,
    /// Add a source-port match to the zone.
    AddSourcePort,
    /// Remove a source-port match from the zone.
    RemoveSourcePort,
    /// Allow an IP protocol in the zone.
    AddProtocol,
    /// Stop allowing an IP protocol in the zone.
    RemoveProtocol,
    /// Create a new service definition (permanent-only).
    CreateService,
    /// Add a port to a service definition.
    AddServicePort,
    /// Remove a port from a service definition.
    RemoveServicePort,
    /// Create a new policy object (permanent-only).
    CreatePolicy,
    /// Add a service to a policy object.
    AddPolicyService,
    /// Enable or disable a predefined policy set.
    SetPolicySetState,
    /// Create a reviewed policy replacement for the selected direct rule.
    MigrateDirectRule,
    /// Stage a plan restoring a saved snapshot.
    RestoreSnapshot,
    /// Show a read-only diff of the current state against a saved snapshot.
    DiffSnapshot,
    /// Explain how firewalld would treat ingress traffic (read-only).
    ExplainTraffic,
    /// `<service> <seconds>` — temporary runtime allow via `--timeout`.
    AddTemporaryService,
}

impl FormKind {
    /// Modal title for this form.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::AddService => "Add service",
            Self::AddPort => "Add port",
            Self::AddForwardPort => "Add forward port",
            Self::AddRichRule => "Add rich rule",
            Self::AddInterface => "Bind interface",
            Self::AddSource => "Bind source",
            Self::CreateZone => "Create zone",
            Self::CreateIpSet => "Create ipset",
            Self::AddIpSetEntry => "Add ipset entry",
            Self::RemoveIpSetEntry => "Remove ipset entry",
            Self::AddIcmpBlock => "Block ICMP type",
            Self::SetZoneTarget => "Set zone target (permanent)",
            Self::AddSourcePort => "Add source-port",
            Self::RemoveSourcePort => "Remove source-port",
            Self::AddProtocol => "Allow protocol",
            Self::RemoveProtocol => "Remove protocol",
            Self::CreateService => "Create service",
            Self::AddServicePort => "Add port to service",
            Self::RemoveServicePort => "Remove port from service",
            Self::CreatePolicy => "Create policy",
            Self::AddPolicyService => "Add service to policy",
            Self::SetPolicySetState => "Set policy-set state",
            Self::MigrateDirectRule => "Migrate selected direct rule",
            Self::RestoreSnapshot => "Restore snapshot (stages a plan)",
            Self::DiffSnapshot => "Diff against snapshot (read-only)",
            Self::ExplainTraffic => "Explain traffic",
            Self::AddTemporaryService => "Temporary service (runtime, auto-expires)",
        }
    }

    /// Input-line label with an example of the expected syntax.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AddService => "service name (e.g. https)",
            Self::AddPort => "port/protocol (e.g. 8080/tcp, 5000-5010/udp)",
            Self::AddForwardPort => "port=<p>:proto=<proto>[:toport=<p>][:toaddr=<ip>]",
            Self::AddRichRule => {
                "rich rule (e.g. rule family=\"ipv4\" source address=\"10.0.0.0/8\" accept)"
            }
            Self::AddInterface => "interface name (e.g. eth0)",
            Self::AddSource => "source (IP, CIDR, MAC or ipset:<name>)",
            Self::CreateZone => "zone name (max 17 chars; created permanent-only)",
            Self::CreateIpSet => "name [type] (e.g. blocklist hash:ip; permanent-only)",
            Self::AddIpSetEntry => {
                "entry for the selected ipset (e.g. 203.0.113.9 or 1.2.3.4,tcp:80)"
            }
            Self::RemoveIpSetEntry => "entry to remove from the selected ipset",
            Self::AddIcmpBlock => "ICMP type to block (e.g. echo-request, timestamp-request)",
            Self::SetZoneTarget => "target: default, ACCEPT, DROP or REJECT (permanent)",
            Self::AddSourcePort => "source port/proto (e.g. 68/udp, 546/udp)",
            Self::RemoveSourcePort => "source port/proto to remove (e.g. 68/udp)",
            Self::AddProtocol => "IP protocol (e.g. gre, esp, igmp, ipv6-icmp)",
            Self::RemoveProtocol => "IP protocol to remove (e.g. gre)",
            Self::CreateService => "service name (permanent-only; reload to activate)",
            Self::AddServicePort => "name port/proto (e.g. myapp 9200/tcp)",
            Self::RemoveServicePort => "name port/proto to remove (e.g. myapp 9200/tcp)",
            Self::CreatePolicy => "policy name (max 17 chars; permanent-only)",
            Self::AddPolicyService => "policy service (e.g. mypolicy http)",
            Self::SetPolicySetState => "<set> <enable|disable>  e.g. gateway enable",
            Self::MigrateDirectRule => "new policy name (max 17 chars; direct rule remains)",
            Self::RestoreSnapshot => "snapshot filename (see \"Browse saved snapshots\")",
            Self::DiffSnapshot => "snapshot filename to diff against current",
            Self::ExplainTraffic => "<source-ip> <port>/<proto>  e.g. 203.0.113.7 443/tcp",
            Self::AddTemporaryService => "<service> <seconds>  e.g. https 300",
        }
    }
}

/// A yes/no gate in front of an action. The body must spell out the exact
/// resource, zone, and configuration target (used by mutations).
#[derive(Debug, Clone, PartialEq)]
pub struct Confirmation {
    /// Modal title.
    pub title: String,
    /// Body lines spelling out the exact change.
    pub body: Vec<String>,
    /// Action dispatched when the operator confirms (`y`).
    pub on_confirm: UiAction,
}

/// Renders the topmost overlay, if any, centered over the screen. Takes `&mut`
/// so the scrollable modals (Help / Details) can write their clamped scroll
/// offset back into state after measuring against the real screen height.
pub fn render(f: &mut Frame, state: &mut UiState, theme: &Theme, screen: Rect) {
    let scroll = state.overlay_scroll;
    let clamped = match state.overlays.last() {
        Some(Overlay::Help) => Some(render_help(f, theme, screen, scroll)),
        Some(Overlay::About) => Some(render_about(f, theme, screen, scroll)),
        Some(Overlay::Palette(palette_state)) => {
            render_palette(f, state, palette_state, theme, screen);
            None
        }
        Some(Overlay::GlobalSearch(search_state)) => {
            render_global_search(f, state, search_state, theme, screen);
            None
        }
        Some(Overlay::Details(content)) => Some(render_details(f, content, theme, screen, scroll)),
        Some(Overlay::Confirm(confirmation)) => {
            render_confirm(f, confirmation, theme, screen);
            None
        }
        Some(Overlay::Form(form)) => {
            render_form(f, form, theme, screen);
            None
        }
        Some(Overlay::RichBuilder(builder)) => {
            render_rich_builder(f, builder, theme, screen);
            None
        }
        None => None,
    };
    if let Some(clamped) = clamped {
        state.overlay_scroll = clamped;
    }
}

/// Clears `area` and returns the shared bordered modal block.
fn modal(f: &mut Frame, theme: &Theme, area: Rect, title: &str) -> Block<'static> {
    f.render_widget(Clear, area);
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme.border_focused())
        .title(Span::styled(format!(" {title} "), theme.accent()))
        .style(theme.panel())
}

const TEXT_MODAL_PERCENT: u16 = 70;
const TEXT_MODAL_MIN_WIDTH: u16 = 60;
const TEXT_MODAL_MAX_WIDTH: u16 = 120;
const MODAL_MARGIN: u16 = 2;
const HELP_KEY_WIDTH: usize = 22;

fn text_modal_width(screen: Rect) -> u16 {
    let available = screen.width.saturating_sub(MODAL_MARGIN).max(1);
    let proportional = screen.width.saturating_mul(TEXT_MODAL_PERCENT) / 100;
    proportional
        .max(TEXT_MODAL_MIN_WIDTH.min(available))
        .min(TEXT_MODAL_MAX_WIDTH)
        .min(available)
}

fn display_width(text: &str) -> usize {
    Line::from(text).width()
}

fn split_word(word: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut chunks = Vec::new();
    let mut current = String::new();
    for character in word.chars() {
        let mut candidate = current.clone();
        candidate.push(character);
        if !current.is_empty() && display_width(&candidate) > width {
            chunks.push(std::mem::take(&mut current));
        }
        current.push(character);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut rows = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        for chunk in split_word(word, width) {
            if current.is_empty() {
                current = chunk;
                continue;
            }
            let candidate = format!("{current} {chunk}");
            if display_width(&candidate) <= width {
                current = candidate;
            } else {
                rows.push(std::mem::take(&mut current));
                current = chunk;
            }
        }
    }
    if !current.is_empty() || rows.is_empty() {
        rows.push(current);
    }
    rows
}

fn help_entry_rows(keys: &str, description: &str, inner_width: usize) -> Vec<(String, String)> {
    let key_width = HELP_KEY_WIDTH.min(inner_width.saturating_sub(8).max(1));
    let prefix = format!("   {keys:<key_width$}");
    let continuation = " ".repeat(display_width(&prefix));
    let description_width = inner_width.saturating_sub(display_width(&prefix)).max(1);
    wrap_text(description, description_width)
        .into_iter()
        .enumerate()
        .map(|(index, row)| {
            let keys = if index == 0 {
                prefix.clone()
            } else {
                continuation.clone()
            };
            (keys, row)
        })
        .collect()
}

fn render_help(f: &mut Frame, theme: &Theme, screen: Rect, scroll: u16) -> u16 {
    let width = text_modal_width(screen);
    let inner_width = usize::from(width.saturating_sub(2));
    let mut lines = Vec::new();
    for (category, entries) in keymap::HELP {
        lines.push(Line::from(Span::styled(
            format!(" {category}"),
            theme.accent(),
        )));
        for entry in *entries {
            lines.extend(
                help_entry_rows(entry.keys, entry.desc, inner_width)
                    .into_iter()
                    .map(|(keys, description)| {
                        Line::from(vec![
                            Span::styled(keys, theme.hotkey()),
                            Span::styled(description, theme.text()),
                        ])
                    }),
            );
        }
        lines.push(Line::default());
    }

    let desired = u16::try_from(lines.len() + 2).unwrap_or(u16::MAX);
    let area = centered(screen, width, desired);
    let scroll = clamp_scroll(scroll, lines.len(), area.height);
    let title = scroll_title("Help", scroll, lines.len(), area.height);
    let block = modal(f, theme, area, &title);
    f.render_widget(Paragraph::new(lines).block(block).scroll((scroll, 0)), area);
    scroll
}

fn render_about(f: &mut Frame, theme: &Theme, screen: Rect, scroll: u16) -> u16 {
    let field = |label: &str, value: &'static str| {
        Line::from(vec![
            Span::styled(format!("   {label:<10}"), theme.accent()),
            Span::styled(value, theme.text()),
        ])
    };
    let body = |text: &'static str| Line::from(Span::styled(format!(" {text}"), theme.text()));
    let lines = vec![
        Line::from(Span::styled(
            format!(" FWDeck v{}", env!("CARGO_PKG_VERSION")),
            theme.brand(),
        )),
        Line::default(),
        body("A safety-first terminal UI for firewalld — manage zones,"),
        body("services, ports, and rich rules from the keyboard, with"),
        body("runtime-vs-permanent scope on every row and a dead-man's"),
        body("switch that auto-reverts a change that would cut your session."),
        Line::default(),
        field("Developer", "Daniel Niazmand"),
        field("Website", "https://madebydaniz.com"),
        field("Docs", "https://madebydaniz.github.io/fwdeck/"),
        field("Source", "https://github.com/madebydaniz/fwdeck"),
        field("Updates", "https://github.com/madebydaniz/fwdeck/releases"),
        field("License", "MIT"),
        Line::default(),
        body("Run `fwdeck doctor` for your exact upgrade command."),
    ];
    let desired = u16::try_from(lines.len() + 2).unwrap_or(u16::MAX);
    let area = centered(screen, text_modal_width(screen), desired);
    let scroll = clamp_scroll(scroll, lines.len(), area.height);
    let title = scroll_title("About", scroll, lines.len(), area.height);
    let block = modal(f, theme, area, &title);
    f.render_widget(Paragraph::new(lines).block(block).scroll((scroll, 0)), area);
    scroll
}

/// The largest valid scroll offset so the last row can reach the bottom of the
/// modal's inner area (2 rows of border), never scrolling into empty space.
fn clamp_scroll(scroll: u16, line_count: usize, area_height: u16) -> u16 {
    let inner = area_height.saturating_sub(2);
    let max = u16::try_from(line_count)
        .unwrap_or(u16::MAX)
        .saturating_sub(inner);
    scroll.min(max)
}

/// Appends a scroll indicator to a modal title when its content overflows.
fn scroll_title(base: &str, scroll: u16, line_count: usize, area_height: u16) -> String {
    let inner = area_height.saturating_sub(2);
    if usize::from(inner) >= line_count {
        return base.to_owned();
    }
    format!(
        "{base}  (↑/↓ scroll · {}%)",
        scroll_percent(scroll, line_count, inner)
    )
}

/// Rough scroll progress as a percentage, for the title indicator.
fn scroll_percent(scroll: u16, line_count: usize, inner: u16) -> u16 {
    let max = u16::try_from(line_count)
        .unwrap_or(u16::MAX)
        .saturating_sub(inner);
    if max == 0 {
        return 100;
    }
    u16::try_from(u32::from(scroll) * 100 / u32::from(max)).unwrap_or(100)
}

fn render_global_search(
    f: &mut Frame,
    state: &UiState,
    search_state: &super::search::GlobalSearchState,
    theme: &Theme,
    screen: Rect,
) {
    let hits = super::search::hits(state, &search_state.query);
    let visible_rows = 12usize;
    let area = centered(
        screen,
        72,
        u16::try_from(visible_rows + 6).unwrap_or(u16::MAX),
    );
    let block = modal(f, theme, area, "Global search");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines = vec![
        Line::from(vec![
            Span::styled(" / ", theme.accent()),
            Span::styled(search_state.query.clone(), theme.text()),
            Span::styled("█", theme.accent()),
        ]),
        Line::default(),
    ];

    let selected = search_state.selected.min(hits.len().saturating_sub(1));
    let offset = selected.saturating_sub(visible_rows.saturating_sub(1));
    for (index, hit) in hits.iter().enumerate().skip(offset).take(visible_rows) {
        let is_selected = index == selected;
        let marker = if is_selected { "▸ " } else { "  " };
        let label: String = hit.label.chars().take(54).collect();
        let spans = vec![
            Span::styled(marker.to_owned(), theme.accent()),
            Span::styled(format!("{:<11}", hit.view.title()), theme.muted()),
            Span::styled(label, theme.text()),
        ];
        let line = Line::from(spans);
        lines.push(if is_selected {
            line.style(theme.selected())
        } else {
            line
        });
    }
    if hits.is_empty() {
        let message = if search_state.query.trim().is_empty() {
            "  type to search every view"
        } else {
            "  no matches"
        };
        lines.push(Line::from(Span::styled(message, theme.muted())));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn render_palette(
    f: &mut Frame,
    state: &UiState,
    palette_state: &PaletteState,
    theme: &Theme,
    screen: Rect,
) {
    let commands = palette::filtered(state);
    let visible_rows = 12usize;
    let width = text_modal_width(screen);
    let inner_width = usize::from(width.saturating_sub(2));
    let title_width = inner_width.saturating_sub(18).max(8);

    let mut lines = vec![
        Line::from(vec![
            Span::styled(" > ", theme.accent()),
            Span::styled(palette_state.query.clone(), theme.text()),
            Span::styled("█", theme.accent()),
        ]),
        Line::default(),
    ];

    let selected = palette_state.selected.min(commands.len().saturating_sub(1));
    // Keep the selection inside the visible window.
    let offset = selected.saturating_sub(visible_rows.saturating_sub(1));
    for (index, command) in commands.iter().enumerate().skip(offset).take(visible_rows) {
        let is_selected = index == selected;
        let marker = if is_selected { "▸ " } else { "  " };
        let mut spans = vec![Span::styled(marker.to_owned(), theme.accent())];
        let title: String = command.title.chars().take(title_width).collect();
        match command.availability {
            Availability::Enabled => {
                spans.push(Span::styled(format!("{title:<title_width$}"), theme.text()));
                spans.push(Span::styled(command.category.label(), theme.muted()));
            }
            Availability::Disabled(reason) => {
                spans.push(Span::styled(
                    format!("{title:<title_width$}"),
                    theme.muted(),
                ));
                spans.push(Span::styled(reason, theme.warn()));
            }
        }
        let line = Line::from(spans);
        lines.push(if is_selected {
            line.style(theme.selected())
        } else {
            line
        });
    }
    if commands.is_empty() {
        lines.push(Line::from(Span::styled(
            "  no matching command",
            theme.muted(),
        )));
    }

    lines.push(Line::default());
    if let Some(command) = commands.get(selected) {
        lines.extend(
            wrap_text(command.description, inner_width.saturating_sub(1))
                .into_iter()
                .map(|row| Line::from(Span::styled(format!(" {row}"), theme.info()))),
        );
    }
    lines.push(Line::from(Span::styled(
        " enter run · esc close",
        theme.muted(),
    )));
    let height = u16::try_from(lines.len() + 2)
        .unwrap_or(u16::MAX)
        .min(screen.height);
    let area = centered(screen, width, height);
    let block = modal(f, theme, area, "Commands");
    let inner = block.inner(area);
    f.render_widget(block, area);
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn render_details(
    f: &mut Frame,
    content: &DetailsContent,
    theme: &Theme,
    screen: Rect,
    scroll: u16,
) -> u16 {
    let mut lines: Vec<Line> = content
        .lines
        .iter()
        .map(|(key, value)| {
            if key.is_empty() {
                Line::from(Span::styled(format!("   {value}"), theme.text()))
            } else {
                Line::from(vec![
                    Span::styled(format!(" {key:<12}"), theme.muted()),
                    Span::styled(value.clone(), theme.text()),
                ])
            }
        })
        .collect();
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(
        " esc close  ·  : for actions on this object",
        theme.muted(),
    )));

    let height = u16::try_from(lines.len() + 2)
        .unwrap_or(u16::MAX)
        .min(screen.height.saturating_sub(2));
    let area = centered(screen, text_modal_width(screen), height);
    let scroll = clamp_scroll(scroll, lines.len(), area.height);
    let title = scroll_title(&content.title, scroll, lines.len(), area.height);
    let block = modal(f, theme, area, &title);
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block)
            .scroll((scroll, 0)),
        area,
    );
    scroll
}

fn render_form(f: &mut Frame, form: &FormState, theme: &Theme, screen: Rect) {
    let label = form.kind.label();

    // Size to the content: wide enough for the whole label (plus borders and a
    // leading space), clamped to the screen. Below the clamp the label wraps.
    let label_width = u16::try_from(label.chars().count() + 3).unwrap_or(u16::MAX);
    let width = label_width.clamp(44, screen.width.saturating_sub(4).max(20));
    let inner_width = usize::from(width.saturating_sub(3)); // borders + leading space
    let label_rows = u16::try_from(label.chars().count().div_ceil(inner_width.max(1))).unwrap_or(1);
    let height = (label_rows + 6).min(screen.height);
    let area = centered(screen, width, height);
    let block = modal(f, theme, area, form.kind.title());

    // Keep the cursor visible: when the input outgrows the line, show its tail.
    let input_budget = inner_width.saturating_sub(4); // "> " prefix + cursor
    let visible_input: String = if form.buffer.chars().count() > input_budget {
        let skip = form.buffer.chars().count() - input_budget;
        std::iter::once('…')
            .chain(form.buffer.chars().skip(skip + 1))
            .collect()
    } else {
        form.buffer.clone()
    };

    let mut lines = vec![Line::default()];
    lines.push(Line::from(Span::styled(format!(" {label}"), theme.muted())));
    lines.push(Line::from(vec![
        Span::styled(" > ", theme.accent()),
        Span::styled(visible_input, theme.text()),
        Span::styled("█", theme.accent()),
    ]));
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(
        " enter continue · esc cancel",
        theme.muted(),
    )));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}

fn render_rich_builder(
    f: &mut Frame,
    builder: &super::rich_builder::RichBuilder,
    theme: &Theme,
    screen: Rect,
) {
    let width = text_modal_width(screen);
    let inner_width = usize::from(width.saturating_sub(2));
    let (label, example) = builder.prompt();
    let mut lines: Vec<Line> = wrap_text(
        &format!("preview: {}", builder.assemble()),
        inner_width.saturating_sub(1),
    )
    .into_iter()
    .map(|row| Line::from(Span::styled(format!(" {row}"), theme.info())))
    .collect();
    lines.push(Line::default());
    lines.extend(
        wrap_text(
            &format!("{label} — {example}"),
            inner_width.saturating_sub(1),
        )
        .into_iter()
        .map(|row| Line::from(Span::styled(format!(" {row}"), theme.muted()))),
    );
    lines.extend([
        Line::from(vec![
            Span::styled(" > ", theme.accent()),
            Span::styled(builder.buffer.clone(), theme.text()),
            Span::styled("█", theme.accent()),
        ]),
        Line::default(),
        Line::from(Span::styled(
            " enter next/finish · esc cancel",
            theme.muted(),
        )),
    ]);
    let height = u16::try_from(lines.len() + 2)
        .unwrap_or(u16::MAX)
        .min(screen.height);
    let area = centered(screen, width, height);
    let block = modal(f, theme, area, "Rich rule builder");
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}

fn render_confirm(f: &mut Frame, confirmation: &Confirmation, theme: &Theme, screen: Rect) {
    let width = text_modal_width(screen);
    let inner_width = usize::from(width.saturating_sub(3));
    let body: Vec<String> = confirmation
        .body
        .iter()
        .flat_map(|entry| wrap_text(entry, inner_width))
        .collect();
    let height = u16::try_from(body.len() + 5)
        .unwrap_or(u16::MAX)
        .min(screen.height);
    let area = centered(screen, width, height);
    let block = modal(f, theme, area, &confirmation.title);

    let mut lines: Vec<Line> = vec![Line::default()];
    for entry in body {
        lines.push(Line::from(Span::styled(format!(" {entry}"), theme.text())));
    }
    lines.push(Line::default());
    lines.push(
        Line::from(vec![
            Span::styled("y", theme.ok()),
            Span::styled(" confirm · ", theme.muted()),
            Span::styled("s", theme.info()),
            Span::styled(" stage · ", theme.muted()),
            Span::styled("n", theme.danger()),
            Span::styled("/esc cancel", theme.muted()),
        ])
        .alignment(Alignment::Center),
    );
    f.render_widget(Paragraph::new(lines).block(block), area);
}

/// A `width`×`height` rect centered on `screen`, clamped to fit.
fn centered(screen: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(screen.width);
    let height = height.min(screen.height);
    Rect {
        x: screen.x + (screen.width.saturating_sub(width)) / 2,
        y: screen.y + (screen.height.saturating_sub(height)) / 2,
        width,
        height,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::domain::mock;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect()
    }

    #[test]
    fn text_modal_width_is_seventy_percent_with_safe_bounds() {
        assert_eq!(text_modal_width(Rect::new(0, 0, 100, 30)), 70);
        assert_eq!(text_modal_width(Rect::new(0, 0, 200, 50)), 120);
        assert_eq!(text_modal_width(Rect::new(0, 0, 40, 20)), 38);
    }

    #[test]
    fn help_entry_wraps_under_the_description_column() {
        let rows = help_entry_rows("u", "roll back last change now (during countdown)", 36);

        assert!(rows.len() > 1);
        assert!(rows.iter().all(|(keys, description)| {
            Line::from(format!("{keys}{description}")).width() <= 36
        }));
        assert!(rows[1].0.chars().all(|character| character == ' '));
        assert_eq!(rows[0].0.len(), rows[1].0.len());
    }

    #[test]
    fn wide_help_keeps_the_full_long_description_visible() {
        let mut terminal = Terminal::new(TestBackend::new(200, 50)).unwrap();
        let theme = Theme::new(crate::ui::theme::Variant::Dracula, true, true);

        terminal
            .draw(|frame| {
                render_help(frame, &theme, frame.area(), 0);
            })
            .unwrap();

        let content = buffer_text(&terminal);
        assert!(content.contains("roll back last change now"));
        assert!(content.contains("during a countdown"));
    }

    #[test]
    fn narrow_confirmation_wraps_body_without_hiding_its_suffix_or_actions() {
        let mut terminal = Terminal::new(TestBackend::new(72, 24)).unwrap();
        let theme = Theme::new(crate::ui::theme::Variant::Dracula, true, true);
        let confirmation = Confirmation {
            title: "Apply staged plan".to_owned(),
            body: vec![
                "this deliberately long confirmation description must remain visible".to_owned(),
            ],
            on_confirm: UiAction::Quit,
        };

        terminal
            .draw(|frame| {
                render_confirm(frame, &confirmation, &theme, frame.area());
            })
            .unwrap();

        let content = buffer_text(&terminal);
        assert!(content.contains("description must"));
        assert!(content.contains("remain visible"));
        assert!(content.contains("confirm"));
        assert!(content.contains("cancel"));
    }

    #[test]
    fn wide_palette_keeps_the_full_selected_description_visible() {
        let mut terminal = Terminal::new(TestBackend::new(200, 40)).unwrap();
        let theme = Theme::new(crate::ui::theme::Variant::Dracula, true, true);
        let mut state = UiState::new(&Config::default(), "testhost".to_owned(), false, None);
        state.snapshot = Some(std::sync::Arc::new(mock::sample().unwrap()));
        let palette_state = PaletteState {
            query: "temporary service".to_owned(),
            selected: 0,
        };
        state.overlays.push(Overlay::Palette(palette_state.clone()));

        terminal
            .draw(|frame| {
                render_palette(frame, &state, &palette_state, &theme, frame.area());
            })
            .unwrap();

        let content = buffer_text(&terminal);
        assert!(
            content.contains("removed automatically after N seconds"),
            "{content}"
        );
    }
}
