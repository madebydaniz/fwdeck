//! Command-line interface. CLI flags override config-file values (see
//! `config::load`).

use std::path::PathBuf;
use std::time::Duration;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};

use crate::domain::ConfigurationTarget;

/// Parsed command-line arguments for the `fwdeck` binary.
#[derive(Debug, Parser)]
#[command(
    name = "fwdeck",
    version,
    about = "A safety-first terminal UI for inspecting and managing firewalld"
)]
pub struct Cli {
    /// Never execute mutating firewall operations
    #[arg(long)]
    pub read_only: bool,

    /// Zone to select at startup
    #[arg(long)]
    pub zone: Option<String>,

    /// Default configuration target for mutations
    #[arg(long, value_enum)]
    pub target: Option<TargetArg>,

    /// Data refresh interval, e.g. `5s` or `1500ms`
    #[arg(long, value_parser = parse_duration)]
    pub refresh_interval: Option<Duration>,

    /// Log level: trace, debug, info, warn, error
    #[arg(long)]
    pub log_level: Option<String>,

    /// Disable colors
    #[arg(long)]
    pub no_color: bool,

    /// Backend to talk to firewalld with (the `dbus` value needs the `dbus`
    /// build feature; otherwise it falls back to the CLI backend)
    #[arg(long, value_enum, default_value = "cli")]
    pub backend: BackendArg,

    /// Offline mode: manage the permanent config via `firewall-offline-cmd`
    /// when the daemon is not running (install / chroot / recovery)
    #[arg(long)]
    pub offline: bool,

    /// Path to an alternative config file
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Subcommand to run instead of the TUI.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Non-TUI subcommands; the TUI starts when none is given.
#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Inspect the environment without touching the firewall
    Doctor,
    /// Print shell completions to stdout
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Print the man page (troff) to stdout
    Manpage,
    /// Inspect or apply local-state retention (dry-run unless --apply is set)
    Prune {
        /// Explicitly request the default read-only preview
        #[arg(long, conflicts_with = "apply")]
        dry_run: bool,
        /// Delete the files selected by the retention policy
        #[arg(long, conflicts_with = "dry_run")]
        apply: bool,
    },
    /// List, pin, or unpin saved snapshots
    Snapshots {
        /// Snapshot metadata operation
        #[command(subcommand)]
        command: SnapshotCommand,
    },
}

/// Snapshot metadata subcommands.
#[derive(Debug, Clone, Subcommand)]
pub enum SnapshotCommand {
    /// List saved snapshots and their pin state
    List,
    /// Exclude an app-generated snapshot from automatic retention
    Pin {
        /// Snapshot filename shown by `fwdeck snapshots list`
        name: String,
    },
    /// Return a pinned snapshot to the normal retention policy
    Unpin {
        /// Snapshot filename shown by `fwdeck snapshots list`
        name: String,
    },
}

/// Rendered completions for `shell`.
#[must_use]
pub fn completions(shell: clap_complete::Shell) -> String {
    let mut command = Cli::command();
    let mut buffer = Vec::new();
    clap_complete::generate(shell, &mut command, "fwdeck", &mut buffer);
    String::from_utf8_lossy(&buffer).into_owned()
}

/// Rendered man page (troff source).
#[must_use]
pub fn manpage() -> String {
    let command = Cli::command();
    let man = clap_mangen::Man::new(command);
    let mut buffer = Vec::new();
    // Rendering into a Vec<u8> cannot fail.
    if man.render(&mut buffer).is_err() {
        return String::new();
    }
    String::from_utf8_lossy(&buffer).into_owned()
}

/// `--target` values: which configuration mutations apply to.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum TargetArg {
    /// Apply changes to the runtime configuration only
    Runtime,
    /// Apply changes to the permanent configuration only
    Permanent,
    /// Apply changes to both the runtime and permanent configuration
    Both,
}

/// `--backend` values: how fwdeck talks to firewalld.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BackendArg {
    /// Shell out to firewall-cmd
    Cli,
    /// Talk to firewalld directly over D-Bus (needs the `dbus` build feature)
    Dbus,
}

impl From<TargetArg> for ConfigurationTarget {
    fn from(value: TargetArg) -> Self {
        match value {
            TargetArg::Runtime => Self::Runtime,
            TargetArg::Permanent => Self::Permanent,
            TargetArg::Both => Self::RuntimeAndPermanent,
        }
    }
}

/// Parses `5s`, `1500ms`, or a bare number of seconds.
fn parse_duration(raw: &str) -> Result<Duration, String> {
    let raw = raw.trim();
    let (digits, unit_ms) = if let Some(n) = raw.strip_suffix("ms") {
        (n, 1)
    } else if let Some(n) = raw.strip_suffix('s') {
        (n, 1000)
    } else {
        (raw, 1000)
    };
    let value: u64 = digits
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration `{raw}`: expected `<n>s` or `<n>ms`"))?;
    if value == 0 {
        return Err(format!("invalid duration `{raw}`: must be positive"));
    }
    // A huge seconds value would overflow the ms conversion; report it, don't panic.
    let millis = value
        .checked_mul(unit_ms)
        .ok_or_else(|| format!("invalid duration `{raw}`: too large"))?;
    Ok(Duration::from_millis(millis))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(
            parse_duration("1500ms").unwrap(),
            Duration::from_millis(1500)
        );
        assert_eq!(parse_duration("3").unwrap(), Duration::from_secs(3));
    }

    #[test]
    fn rejects_bad_durations() {
        assert!(parse_duration("fast").is_err());
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("-5s").is_err());
        // Must error, not panic, on ms-conversion overflow.
        assert!(parse_duration("99999999999999999999s").is_err());
        assert!(parse_duration(&format!("{}s", u64::MAX)).is_err());
    }

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn completions_and_manpage_render() {
        let bash = completions(clap_complete::Shell::Bash);
        assert!(bash.contains("fwdeck"));
        let zsh = completions(clap_complete::Shell::Zsh);
        assert!(zsh.contains("fwdeck"));
        let man = manpage();
        assert!(man.contains(".TH"), "troff output expected");
        assert!(man.contains("fwdeck"));
    }

    #[test]
    fn parses_retention_and_snapshot_commands() {
        let dry_run = Cli::try_parse_from(["fwdeck", "prune", "--dry-run"]).unwrap();
        assert!(matches!(
            dry_run.command,
            Some(Command::Prune {
                dry_run: true,
                apply: false
            })
        ));
        let apply = Cli::try_parse_from(["fwdeck", "prune", "--apply"]).unwrap();
        assert!(matches!(
            apply.command,
            Some(Command::Prune {
                dry_run: false,
                apply: true
            })
        ));
        let pin = Cli::try_parse_from(["fwdeck", "snapshots", "pin", "snapshot-1.json"]).unwrap();
        assert!(matches!(
            pin.command,
            Some(Command::Snapshots {
                command: SnapshotCommand::Pin { .. }
            })
        ));
        assert!(Cli::try_parse_from(["fwdeck", "prune", "--dry-run", "--apply"]).is_err());
    }
}
