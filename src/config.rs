//! Configuration: XDG config file plus CLI overrides.
//! `~/.config/fwdeck/config.toml` on Linux.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use crate::cli::Cli;
use crate::domain::ConfigurationTarget;
use crate::error::AppError;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    ui: UiSection,
    behavior: BehaviorSection,
    logging: LoggingSection,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct UiSection {
    theme: String,
    color: bool,
    show_help_bar: bool,
    sidebar_width: u16,
}

impl Default for UiSection {
    fn default() -> Self {
        Self {
            theme: "dracula".to_owned(),
            color: true,
            show_help_bar: true,
            sidebar_width: 22,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct BehaviorSection {
    default_target: TargetSetting,
    refresh_interval_ms: u64,
    log_refresh_interval_ms: u64,
    confirm_destructive_actions: bool,
    read_only: bool,
    rollback_timeout_seconds: u64,
}

impl Default for BehaviorSection {
    fn default() -> Self {
        Self {
            default_target: TargetSetting::RuntimeAndPermanent,
            refresh_interval_ms: 5000,
            log_refresh_interval_ms: 1000,
            confirm_destructive_actions: true,
            read_only: false,
            rollback_timeout_seconds: 30,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct LoggingSection {
    level: String,
}

impl Default for LoggingSection {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TargetSetting {
    Runtime,
    Permanent,
    #[default]
    RuntimeAndPermanent,
}

impl From<TargetSetting> for ConfigurationTarget {
    fn from(value: TargetSetting) -> Self {
        match value {
            TargetSetting::Runtime => Self::Runtime,
            TargetSetting::Permanent => Self::Permanent,
            TargetSetting::RuntimeAndPermanent => Self::RuntimeAndPermanent,
        }
    }
}

/// Final merged configuration (file values overridden by CLI flags).
// A config file legitimately holds independent feature toggles.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct Config {
    /// Theme name (`dracula`, `high-contrast` or `mono`).
    pub theme: String,
    /// Whether colored output is enabled at all.
    pub color: bool,
    /// Show the key-hint bar in the header.
    pub show_help_bar: bool,
    /// Sidebar width in columns, clamped to 16..=40.
    pub sidebar_width: u16,
    /// Default configuration target for mutations.
    pub target: ConfigurationTarget,
    /// How often the firewall snapshot is refreshed.
    pub refresh_interval: Duration,
    /// Refresh cadence for the kernel-log tailer.
    pub log_refresh_interval: Duration,
    /// Require a confirmation modal before a mutation is applied.
    pub confirm_destructive: bool,
    /// Never execute mutating operations.
    pub read_only: bool,
    /// Manage the permanent config via `firewall-offline-cmd` (no daemon).
    pub offline: bool,
    /// Dead-man's switch window for risky operations; 0 disables it.
    pub rollback_timeout: Duration,
    /// Tracing filter level (trace/debug/info/warn/error).
    pub log_level: String,
    /// Zone to select at startup, if any.
    pub initial_zone: Option<String>,
    /// The config file this was loaded from, if one existed.
    pub path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self::from_file(FileConfig::default())
    }
}

/// Refresh intervals are clamped to this floor. A zero interval would panic
/// `tokio::time::interval`, and anything faster than this just burns CPU
/// hammering the daemon.
const MIN_REFRESH: Duration = Duration::from_millis(200);
/// And to this ceiling, so a fat-fingered value can't freeze the UI for hours.
const MAX_REFRESH: Duration = Duration::from_secs(3600);

/// Clamps a millisecond count to the sane refresh window, never producing a
/// zero (panic) or absurd duration.
fn refresh_from_millis(ms: u64) -> Duration {
    Duration::from_millis(ms).clamp(MIN_REFRESH, MAX_REFRESH)
}

impl Config {
    fn from_file(file: FileConfig) -> Self {
        Self {
            theme: file.ui.theme,
            color: file.ui.color,
            show_help_bar: file.ui.show_help_bar,
            sidebar_width: file.ui.sidebar_width.clamp(16, 40),
            target: file.behavior.default_target.into(),
            refresh_interval: refresh_from_millis(file.behavior.refresh_interval_ms),
            log_refresh_interval: refresh_from_millis(file.behavior.log_refresh_interval_ms),
            confirm_destructive: file.behavior.confirm_destructive_actions,
            read_only: file.behavior.read_only,
            offline: false,
            rollback_timeout: Duration::from_secs(file.behavior.rollback_timeout_seconds),
            log_level: file.logging.level,
            initial_zone: None,
            path: None,
        }
    }
}

/// The XDG default config path (`~/.config/fwdeck/config.toml` on Linux).
#[must_use]
pub fn default_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("com", "madebydaniz", "fwdeck")
        .map(|dirs| dirs.config_dir().join("config.toml"))
}

/// Loads the config file (CLI `--config` or the default path), applies CLI
/// overrides, and validates the theme.
///
/// # Errors
/// Returns [`AppError::Config`] when the file is unreadable, malformed, or
/// names an unknown theme.
pub fn load(cli: &Cli) -> Result<Config, AppError> {
    let path = cli.config.clone().or_else(default_path);

    let file = match &path {
        Some(p) if p.exists() => {
            let display = p.display().to_string();
            let raw = std::fs::read_to_string(p).map_err(|err| AppError::Config {
                path: display.clone(),
                message: err.to_string(),
            })?;
            toml::from_str::<FileConfig>(&raw).map_err(|err| AppError::Config {
                path: display,
                message: err.to_string(),
            })?
        }
        _ => FileConfig::default(),
    };

    let mut config = Config::from_file(file);
    config.path = path;

    if cli.read_only {
        config.read_only = true;
    }
    if cli.no_color {
        config.color = false;
    }
    if let Some(target) = cli.target {
        config.target = target.into();
    }
    // Offline is applied last so it wins over any inherited target: there is no
    // runtime with the daemon down, so the only honest target is permanent.
    if cli.offline {
        config.offline = true;
        // An *explicit* `--target runtime` is a contradiction offline — fail
        // loudly rather than silently rewriting the operator's stated intent.
        if matches!(cli.target, Some(crate::cli::TargetArg::Runtime)) {
            return Err(AppError::Config {
                path: "<cli>".to_owned(),
                message: "--offline manages only the permanent config, so \
                          --target runtime is impossible (there is no running daemon)"
                    .to_owned(),
            });
        }
        config.target = crate::domain::ConfigurationTarget::Permanent;
    }
    if let Some(interval) = cli.refresh_interval {
        // parse_duration already rejects zero; clamp the ceiling so the engine
        // never receives an interval outside the sane window.
        config.refresh_interval = interval.clamp(MIN_REFRESH, MAX_REFRESH);
    }
    if let Some(level) = &cli.log_level {
        config.log_level.clone_from(level);
    }
    if let Some(zone) = &cli.zone {
        config.initial_zone = Some(zone.clone());
    }

    if crate::ui::theme::Variant::parse(&config.theme).is_none() {
        return Err(AppError::Config {
            path: config
                .path
                .as_ref()
                .map_or_else(|| "<defaults>".to_owned(), |p| p.display().to_string()),
            message: format!(
                "unknown theme `{}` (choose dracula, high-contrast or mono)",
                config.theme
            ),
        });
    }
    Ok(config)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_spec() {
        let config = Config::default();
        assert_eq!(config.theme, "dracula");
        assert_eq!(config.sidebar_width, 22);
        assert_eq!(config.refresh_interval, Duration::from_secs(5));
        assert_eq!(config.target, ConfigurationTarget::RuntimeAndPermanent);
        assert!(config.confirm_destructive);
        assert!(!config.read_only);
        assert_eq!(config.rollback_timeout, Duration::from_secs(30));
    }

    #[test]
    fn parses_partial_file_with_defaults() {
        let file: FileConfig = toml::from_str(
            r#"
            [behavior]
            default_target = "runtime"
            read_only = true
            "#,
        )
        .unwrap();
        let config = Config::from_file(file);
        assert_eq!(config.target, ConfigurationTarget::Runtime);
        assert!(config.read_only);
        assert_eq!(config.sidebar_width, 22); // untouched section keeps defaults
    }

    #[test]
    fn rejects_unknown_fields_with_context() {
        let result = toml::from_str::<FileConfig>("[ui]\nsidebar_widht = 30\n");
        assert!(result.is_err());
    }

    #[test]
    fn clamps_extreme_sidebar_width() {
        let file: FileConfig = toml::from_str("[ui]\nsidebar_width = 99\n").unwrap();
        assert_eq!(Config::from_file(file).sidebar_width, 40);
    }

    #[test]
    fn zero_refresh_interval_is_clamped_not_zero() {
        // A zero interval would panic tokio::time::interval — it must never
        // reach the engine.
        let file: FileConfig =
            toml::from_str("[behavior]\nrefresh_interval_ms = 0\nlog_refresh_interval_ms = 0\n")
                .unwrap();
        let config = Config::from_file(file);
        assert!(config.refresh_interval >= MIN_REFRESH);
        assert!(config.log_refresh_interval >= MIN_REFRESH);
        assert!(!config.refresh_interval.is_zero());
    }

    #[test]
    fn absurd_refresh_interval_is_capped() {
        let file: FileConfig =
            toml::from_str("[behavior]\nrefresh_interval_ms = 999999999999\n").unwrap();
        assert_eq!(Config::from_file(file).refresh_interval, MAX_REFRESH);
    }

    use clap::Parser as _;

    // A `--config` path that cannot exist, so `load` always falls back to
    // defaults regardless of the developer's real config file.
    const NO_FILE: &str = "/nonexistent/fwdeck-test-config.toml";

    #[test]
    fn offline_forces_permanent_target() {
        let cli = Cli::try_parse_from(["fwdeck", "--config", NO_FILE, "--offline"]).unwrap();
        let config = load(&cli).unwrap();
        assert!(config.offline);
        assert_eq!(config.target, ConfigurationTarget::Permanent);
    }

    #[test]
    fn offline_with_explicit_runtime_target_is_rejected() {
        // Offline has no runtime — asking for it explicitly is a contradiction,
        // and must not be silently rewritten to permanent.
        let cli = Cli::try_parse_from([
            "fwdeck",
            "--config",
            NO_FILE,
            "--offline",
            "--target",
            "runtime",
        ])
        .unwrap();
        assert!(load(&cli).is_err());
    }

    #[test]
    fn offline_with_both_target_narrows_to_permanent() {
        let cli = Cli::try_parse_from([
            "fwdeck",
            "--config",
            NO_FILE,
            "--offline",
            "--target",
            "both",
        ])
        .unwrap();
        assert_eq!(load(&cli).unwrap().target, ConfigurationTarget::Permanent);
    }
}
