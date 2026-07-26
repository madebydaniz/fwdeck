//! `fwdeck` binary entry point: parses the CLI, loads configuration, wires the
//! selected backend into the engine, and hands off to the terminal UI. All the
//! reusable logic lives in the `fwdeck` library crate; this file is only the
//! process shell (argument parsing, subcommands, and engine/UI wiring).

use clap::Parser;

use fwdeck::application::api::{self, EngineHandle};
use fwdeck::application::ports::FirewallBackend;
use fwdeck::cli::{BackendArg, Cli, Command};
use fwdeck::config::Config;
use fwdeck::infrastructure::firewalld::CliBackend;
use fwdeck::infrastructure::logs;
use fwdeck::infrastructure::process::TokioRunner;
use fwdeck::{bootstrap, config, ui};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    let config = config::load(&args)?;

    match args.command {
        Some(Command::Doctor) => {
            run_doctor(&config).await;
            return Ok(());
        }
        Some(Command::Completions { shell }) => {
            print!("{}", fwdeck::cli::completions(shell));
            return Ok(());
        }
        Some(Command::Manpage) => {
            print!("{}", fwdeck::cli::manpage());
            return Ok(());
        }
        None => {}
    }

    bootstrap::init_tracing(&config);
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "starting fwdeck");

    let mut config = config;
    // Capability latch: without root and without polkit there is no path to a
    // successful mutation — start read-only instead of failing every apply.
    if !config.read_only && fwdeck::infrastructure::process_uid() != 0 {
        let polkit = std::path::Path::new("/usr/lib/polkit-1").exists()
            || std::path::Path::new("/usr/libexec/polkit-1").exists();
        if !polkit {
            eprintln!("warning: unprivileged and no polkit found — starting read-only");
            tracing::warn!("no mutation authorization path; latching read-only");
            config.read_only = true;
            config.read_only_reason = Some("unprivileged, no polkit".to_owned());
        }
    }

    // Leftover watchdogs from a previous crashed/killed session mean a
    // rollback either fired without us or is still ticking — tell the operator.
    warn_stale_watchdogs();

    // Advisory instance lock: a second FWDeck on the same host degrades to
    // read-only instead of racing the first one's mutations.
    let holds_lock = match bootstrap::acquire_instance_lock() {
        Ok(()) => true,
        Err(holder) => {
            let who =
                holder.map_or_else(|| "another process".to_owned(), |pid| format!("PID {pid}"));
            eprintln!("warning: fwdeck already running ({who}) — starting read-only");
            tracing::warn!(holder = %who, "instance lock held; forcing read-only");
            config.read_only = true;
            config.read_only_reason = Some("another instance is running".to_owned());
            false
        }
    };

    // The D-Bus backend mutates runtime only. Narrow the default `both` target
    // to its achievable subset so mutations don't all fail against it; an
    // explicit `--target permanent` is left alone to fail loudly with a pointer
    // to the CLI backend. Compiled in only with the `dbus` feature, so the
    // no-feature fallback to CLI (which supports permanent) never narrows.
    #[cfg(feature = "dbus")]
    if !args.offline
        && args.backend == BackendArg::Dbus
        && config.target == fwdeck::domain::ConfigurationTarget::RuntimeAndPermanent
    {
        tracing::info!(
            "D-Bus backend is runtime-only; applying the runtime half of the default target"
        );
        config.target = fwdeck::domain::ConfigurationTarget::Runtime;
    }

    // Backend selection: the CLI backend is the reference; the D-Bus backend is
    // an optional build feature (ADR-4). Both implement `FirewallBackend`, so
    // only this line differs — the engine, UI, and domain are backend-agnostic.
    let engine = spawn_engine(&args, &config).await?;
    let (log_tx, log_rx) = tokio::sync::mpsc::channel(256);
    logs::spawn_tailer(log_tx);
    let hostname = bootstrap::hostname();
    let ssh_session = bootstrap::ssh_session();
    let ssh_interface = bootstrap::ssh_interface()
        .and_then(|name| fwdeck::domain::InterfaceName::parse(&name).ok());
    let result = ui::run(
        &config,
        hostname,
        ssh_session,
        ssh_interface,
        engine,
        log_rx,
    )
    .await;
    if holds_lock {
        bootstrap::release_instance_lock();
    }
    result?;
    Ok(())
}

/// Reports systemd `fwdeck-rollback-*` units left over from an earlier
/// session (crash recovery visibility; read-only check).
fn warn_stale_watchdogs() {
    let systemctl = fwdeck::infrastructure::process::resolve_trusted("systemctl");
    if !systemctl.is_absolute() {
        return;
    }
    let Ok(output) = std::process::Command::new(systemctl)
        .args(["list-units", "--plain", "--no-legend", "fwdeck-rollback-*"])
        .output()
    else {
        return;
    };
    let listing = String::from_utf8_lossy(&output.stdout);
    for line in listing.lines().filter(|line| !line.trim().is_empty()) {
        eprintln!("warning: leftover rollback watchdog from a previous session: {line}");
        tracing::warn!(unit = %line, "stale rollback watchdog found at startup");
    }
}

/// Builds the engine over the selected backend. Both branches feed the same
/// `EngineHandle`, so nothing downstream knows which backend it talks to.
async fn spawn_engine(args: &Cli, config: &Config) -> anyhow::Result<EngineHandle> {
    if args.offline {
        tracing::info!("using the offline backend (firewall-offline-cmd)");
        return Ok(api::spawn(
            CliBackend::offline(TokioRunner),
            config.refresh_interval,
            config.read_only,
        ));
    }
    match args.backend {
        BackendArg::Dbus => spawn_dbus_engine(config).await,
        BackendArg::Cli => Ok(api::spawn(
            CliBackend::new(TokioRunner),
            config.refresh_interval,
            config.read_only,
        )),
    }
}

#[cfg(feature = "dbus")]
async fn spawn_dbus_engine(config: &Config) -> anyhow::Result<EngineHandle> {
    use fwdeck::infrastructure::firewalld::dbus::DbusBackend;
    let backend = DbusBackend::connect().await?;
    tracing::info!("using the D-Bus backend");
    Ok(api::spawn(
        backend,
        config.refresh_interval,
        config.read_only,
    ))
}

#[cfg(not(feature = "dbus"))]
#[allow(clippy::unused_async)] // signature must match the `dbus`-feature variant
async fn spawn_dbus_engine(config: &Config) -> anyhow::Result<EngineHandle> {
    eprintln!("note: this build has no `dbus` feature — falling back to the CLI backend");
    tracing::warn!("dbus backend requested but not compiled in; using CLI backend");
    Ok(api::spawn(
        CliBackend::new(TokioRunner),
        config.refresh_interval,
        config.read_only,
    ))
}

/// Read-only environment inspection; never mutates the firewall.
async fn run_doctor(config: &Config) {
    println!("fwdeck {} — doctor", env!("CARGO_PKG_VERSION"));
    println!(
        "os:            {} ({})",
        std::env::consts::OS,
        std::env::consts::ARCH
    );

    let config_path = config
        .path
        .as_ref()
        .map_or_else(|| "<none>".to_owned(), |p| p.display().to_string());
    let config_exists = config.path.as_ref().is_some_and(|p| p.exists());
    println!(
        "config file:   {config_path} ({})",
        if config_exists {
            "found"
        } else {
            "using defaults"
        }
    );
    let state_dir = bootstrap::state_dir()
        .map_or_else(|| "<unavailable>".to_owned(), |p| p.display().to_string());
    println!("state dir:     {state_dir}");
    println!(
        "TERM:          {}",
        std::env::var("TERM").unwrap_or_else(|_| "<unset>".to_owned())
    );
    println!(
        "COLORTERM:     {}",
        std::env::var("COLORTERM").unwrap_or_else(|_| "<unset>".to_owned())
    );
    println!();

    let backend = CliBackend::new(TokioRunner);
    let status = match backend.probe().await {
        Ok(status) => status,
        Err(err) => {
            println!("firewall-cmd:  FAILED — {err}");
            return;
        }
    };
    println!(
        "firewall-cmd:  found{}",
        status
            .version
            .as_deref()
            .map_or_else(String::new, |v| format!(", version {v}"))
    );
    println!(
        "daemon:        {}",
        if status.daemon_running {
            "running"
        } else {
            "not running"
        }
    );
    println!("netfilter:     {}", status.backend.as_str());
    if !status.daemon_running {
        println!();
        println!("start the daemon (`systemctl start firewalld`) and re-run doctor.");
        return;
    }
    println!("log denied:    {}", status.log_denied.as_str());

    match backend.snapshot().await {
        Ok(snapshot) => {
            println!("default zone:  {}", snapshot.default_zone);
            println!(
                "zones:         {} ({} active)",
                snapshot.zone_names().len(),
                snapshot.active.len()
            );
            println!("read access:   OK");
            let drifted = snapshot
                .zone_names()
                .iter()
                .filter(|zone| !snapshot.is_zone_synced(zone))
                .count();
            println!(
                "drift:         {}",
                if drifted == 0 {
                    "runtime and permanent in sync".to_owned()
                } else {
                    format!("{drifted} zone(s) differ between runtime and permanent")
                }
            );
            if snapshot.degraded.is_empty() {
                println!("data health:   all sections fetched");
            } else {
                for section in &snapshot.degraded {
                    println!("data health:   DEGRADED — {section}");
                }
            }
        }
        Err(err) => println!("read access:   FAILED — {err}"),
    }
    preflight(&backend).await;
}

/// Environment preflight: authorization, binaries, host managers, `SELinux`,
/// permanent-config sanity. Read-only — never mutates anything.
async fn preflight(backend: &CliBackend<TokioRunner>) {
    use fwdeck::infrastructure::process::resolve_trusted;
    println!();

    // Authorization surface.
    let uid = fwdeck::infrastructure::process_uid();
    let polkit = std::path::Path::new("/usr/lib/polkit-1").exists()
        || std::path::Path::new("/usr/libexec/polkit-1").exists();
    println!(
        "authorization: uid {uid}{}",
        if uid == 0 {
            " (root — full access)".to_owned()
        } else if polkit {
            " (unprivileged — mutations will prompt via polkit or fail)".to_owned()
        } else {
            " (unprivileged, no polkit — expect read-only)".to_owned()
        }
    );

    // Resolved binaries: which executables would actually run.
    for tool in [
        "firewall-cmd",
        "firewall-offline-cmd",
        "journalctl",
        "dmesg",
    ] {
        let path = resolve_trusted(tool);
        let found = path.is_absolute();
        println!(
            "binary:        {tool} → {}",
            if found {
                path.display().to_string()
            } else {
                "NOT FOUND in trusted dirs".to_owned()
            }
        );
    }

    // State directory: perms and free space matter for audit/snapshots.
    if let Some(dir) = bootstrap::state_dir() {
        #[cfg(unix)]
        if let Ok(metadata) = std::fs::metadata(&dir) {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = metadata.permissions().mode() & 0o777;
            println!(
                "state dir:     mode {mode:03o}{}",
                if mode.trailing_zeros() >= 6 {
                    ""
                } else {
                    "  ⚠ group/other access — expected 700"
                }
            );
        }
        let lock = dir.join("fwdeck.lock");
        if let Ok(pid) = std::fs::read_to_string(&lock) {
            println!("instance lock: held by PID {}", pid.trim());
        }
    }

    // Host-manager interplay.
    println!(
        "networkmanager: {}",
        if std::path::Path::new("/run/NetworkManager").exists() {
            "running — it owns interface⇄zone bindings for managed connections"
        } else {
            "not detected"
        }
    );
    if resolve_trusted("ufw").is_absolute() {
        println!("conflict:      ⚠ UFW is installed — two firewall managers fight over nftables");
    }
    match std::fs::read_to_string("/sys/fs/selinux/enforce") {
        Ok(value) if value.trim() == "1" => println!("selinux:       enforcing"),
        Ok(_) => println!("selinux:       permissive"),
        Err(_) => println!("selinux:       not present"),
    }

    // Permanent-config sanity straight from firewalld.
    match backend.check_config().await {
        Ok(()) => println!("check-config:  OK"),
        Err(err) => println!("check-config:  FAILED — {err}"),
    }

    // SSH context: what a bad rule would cut.
    if bootstrap::ssh_session() {
        let iface = bootstrap::ssh_interface().unwrap_or_else(|| "unknown".to_owned());
        println!("ssh session:   yes — arrives via interface `{iface}`");
    } else {
        println!("ssh session:   no");
    }
}
