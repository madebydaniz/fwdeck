//! Dracula theme with graceful degradation: 256-color approximation when the
//! terminal lacks truecolor, and modifier-only styles when color is disabled.

use ratatui::style::{Color, Modifier, Style};

struct Palette {
    bg: Color,
    panel: Color,
    deep: Color,
    border: Color,
    muted: Color,
    fg: Color,
    cyan: Color,
    green: Color,
    pink: Color,
    purple: Color,
    red: Color,
    orange: Color,
    yellow: Color,
}

impl Palette {
    const fn dracula() -> Self {
        Self {
            bg: Color::Rgb(0x28, 0x2a, 0x36),
            panel: Color::Rgb(0x21, 0x22, 0x2c),
            deep: Color::Rgb(0x19, 0x1a, 0x21),
            border: Color::Rgb(0x44, 0x47, 0x5a),
            muted: Color::Rgb(0x62, 0x72, 0xa4),
            fg: Color::Rgb(0xf8, 0xf8, 0xf2),
            cyan: Color::Rgb(0x8b, 0xe9, 0xfd),
            green: Color::Rgb(0x50, 0xfa, 0x7b),
            pink: Color::Rgb(0xff, 0x79, 0xc6),
            purple: Color::Rgb(0xbd, 0x93, 0xf9),
            red: Color::Rgb(0xff, 0x55, 0x55),
            orange: Color::Rgb(0xff, 0xb8, 0x6c),
            yellow: Color::Rgb(0xf1, 0xfa, 0x8c),
        }
    }

    /// Nearest xterm-256 approximations of the Dracula palette.
    const fn indexed() -> Self {
        Self {
            bg: Color::Indexed(235),
            panel: Color::Indexed(234),
            deep: Color::Indexed(233),
            border: Color::Indexed(238),
            muted: Color::Indexed(103),
            fg: Color::Indexed(253),
            cyan: Color::Indexed(117),
            green: Color::Indexed(84),
            pink: Color::Indexed(212),
            purple: Color::Indexed(141),
            red: Color::Indexed(203),
            orange: Color::Indexed(215),
            yellow: Color::Indexed(228),
        }
    }
}

/// Selectable theme variants (the `theme` config key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// Dracula palette; truecolor with a 256-color fallback.
    Dracula,
    /// Pure ANSI colors for low-quality or bright terminals.
    HighContrast,
    /// No colors at all; modifier-only styling.
    Mono,
}

impl Variant {
    /// Parses a config-file theme name; `None` for unknown names.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "dracula" => Some(Self::Dracula),
            "high-contrast" => Some(Self::HighContrast),
            "mono" => Some(Self::Mono),
            _ => None,
        }
    }
}

impl Palette {
    /// Pure high-visibility ANSI colors for low-quality or bright terminals.
    const fn high_contrast() -> Self {
        Self {
            bg: Color::Black,
            panel: Color::Black,
            deep: Color::Black,
            border: Color::White,
            muted: Color::Gray,
            fg: Color::White,
            cyan: Color::Cyan,
            green: Color::Green,
            pink: Color::Magenta,
            purple: Color::Magenta,
            red: Color::Red,
            orange: Color::Yellow,
            yellow: Color::Yellow,
        }
    }
}

/// Resolved style provider: a palette (or none for mono/no-color) behind
/// semantic accessors like [`Theme::ok`] and [`Theme::danger`].
pub struct Theme {
    palette: Option<Palette>,
}

impl Theme {
    /// Resolves the variant against the terminal's color capabilities.
    #[must_use]
    pub fn new(variant: Variant, color_enabled: bool, truecolor: bool) -> Self {
        // Mono ignores color entirely (modifier-only styling).
        let palette = match (color_enabled, variant) {
            (false, _) | (_, Variant::Mono) => None,
            (true, Variant::HighContrast) => Some(Palette::high_contrast()),
            (true, Variant::Dracula) if truecolor => Some(Palette::dracula()),
            (true, Variant::Dracula) => Some(Palette::indexed()),
        };
        Self { palette }
    }

    /// Detects truecolor support from `COLORTERM` and applies the variant.
    #[must_use]
    pub fn detect(variant: Variant, color_enabled: bool) -> Self {
        let truecolor = std::env::var("COLORTERM")
            .map(|v| v.contains("truecolor") || v.contains("24bit"))
            .unwrap_or(false);
        Self::new(variant, color_enabled, truecolor)
    }

    fn style(&self, colored: impl FnOnce(&Palette) -> Style, fallback: Style) -> Style {
        self.palette.as_ref().map_or(fallback, colored)
    }

    /// Default screen background and foreground.
    #[must_use]
    pub fn base(&self) -> Style {
        self.style(|p| Style::new().bg(p.bg).fg(p.fg), Style::new())
    }

    /// Slightly darker background for panels and modals.
    #[must_use]
    pub fn panel(&self) -> Style {
        self.style(|p| Style::new().bg(p.panel).fg(p.fg), Style::new())
    }

    /// Darkest background, used for the bottom command line.
    #[must_use]
    pub fn deep(&self) -> Style {
        self.style(|p| Style::new().bg(p.deep).fg(p.fg), Style::new())
    }

    /// Unfocused panel border.
    #[must_use]
    pub fn border(&self) -> Style {
        self.style(
            |p| Style::new().fg(p.border),
            Style::new().add_modifier(Modifier::DIM),
        )
    }

    /// Border of the focused panel or modal.
    #[must_use]
    pub fn border_focused(&self) -> Style {
        self.style(|p| Style::new().fg(p.purple), Style::new())
    }

    /// Regular body text.
    #[must_use]
    pub fn text(&self) -> Style {
        self.style(|p| Style::new().fg(p.fg), Style::new())
    }

    /// De-emphasized text: labels, hints, inactive rows.
    #[must_use]
    pub fn muted(&self) -> Style {
        self.style(
            |p| Style::new().fg(p.muted),
            Style::new().add_modifier(Modifier::DIM),
        )
    }

    /// Table column headers.
    #[must_use]
    pub fn header(&self) -> Style {
        self.style(
            |p| Style::new().fg(p.muted).add_modifier(Modifier::BOLD),
            Style::new().add_modifier(Modifier::DIM),
        )
    }

    /// Highlight of the selected row or list entry.
    #[must_use]
    pub fn selected(&self) -> Style {
        self.style(
            |p| {
                Style::new()
                    .bg(p.border)
                    .fg(p.fg)
                    .add_modifier(Modifier::BOLD)
            },
            Style::new().add_modifier(Modifier::REVERSED),
        )
    }

    /// Keybinding labels in hints and help.
    #[must_use]
    pub fn hotkey(&self) -> Style {
        self.style(
            |p| Style::new().fg(p.yellow),
            Style::new().add_modifier(Modifier::BOLD),
        )
    }

    /// Positive state: success, active, accepted.
    #[must_use]
    pub fn ok(&self) -> Style {
        self.style(|p| Style::new().fg(p.green), Style::new())
    }

    /// Errors and destructive state: failures, drops, panic mode.
    #[must_use]
    pub fn danger(&self) -> Style {
        self.style(
            |p| Style::new().fg(p.red),
            Style::new().add_modifier(Modifier::BOLD),
        )
    }

    /// Warnings: drift, degraded sections, deprecations.
    #[must_use]
    pub fn warn(&self) -> Style {
        self.style(|p| Style::new().fg(p.orange), Style::new())
    }

    /// Informational values and neutral highlights.
    #[must_use]
    pub fn info(&self) -> Style {
        self.style(|p| Style::new().fg(p.cyan), Style::new())
    }

    /// Accent color for markers, cursors, and section titles.
    #[must_use]
    pub fn accent(&self) -> Style {
        self.style(|p| Style::new().fg(p.purple), Style::new())
    }

    /// The FWDECK brand mark.
    #[must_use]
    pub fn brand(&self) -> Style {
        self.style(
            |p| Style::new().fg(p.pink).add_modifier(Modifier::BOLD),
            Style::new().add_modifier(Modifier::BOLD),
        )
    }
}
