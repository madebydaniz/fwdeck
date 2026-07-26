//! Kernel/netfilter log tailing behind a small source abstraction. The tailer
//! task tries `journalctl -k -f` first and falls back to `dmesg --follow`
//! (journald is absent in containers). Entries stream to the UI over a bounded
//! channel; the UI keeps a bounded ring buffer — memory stays flat.

use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

use crate::domain::{LogAction, LogEntry};

/// Parses one netfilter log line (`LogDenied` output and friends). Non-netfilter
/// lines return `None`. Format reference: kernel `nf_log` — stable for decades.
///
/// `2026-07-16T10:00:00+0000 host kernel: FINAL_REJECT: IN=eth0 OUT= SRC=10.0.0.1
///  DST=10.0.0.2 ... PROTO=TCP SPT=51000 DPT=23 ...`
#[must_use]
pub fn parse_line(line: &str) -> Option<LogEntry> {
    if !line.contains("IN=") || !line.contains("SRC=") {
        return None;
    }
    let field = |key: &str| {
        line.split_whitespace()
            .find_map(|token| token.strip_prefix(key))
            .unwrap_or("")
            .to_owned()
    };
    let action = if line.contains("REJECT") {
        LogAction::Reject
    } else if line.contains("DROP") || line.contains("DENIED") {
        LogAction::Drop
    } else if line.contains("ACCEPT") || line.contains("ALLOW") {
        LogAction::Accept
    } else {
        LogAction::Unknown
    };
    // First token is an ISO timestamp (journalctl short-iso / dmesg iso);
    // keep the HH:MM:SS slice when it looks like one.
    let time = line
        .split_whitespace()
        .next()
        .map(|token| token.get(11..19).unwrap_or(token).to_owned())
        .unwrap_or_default();

    Some(LogEntry {
        time,
        action,
        src: field("SRC="),
        dst: field("DST="),
        dport: field("DPT="),
        proto: field("PROTO="),
        iface: field("IN="),
    })
}

/// Spawns the tailer task. Tries each source in order; a source that never
/// produces a line (missing binary, no journal) falls through to the next.
pub fn spawn_tailer(tx: mpsc::Sender<LogEntry>) {
    tokio::spawn(async move {
        let sources: [(&str, &[&str]); 2] = [
            ("journalctl", &["-k", "-f", "-o", "short-iso", "-n", "200"]),
            ("dmesg", &["--follow", "--time-format", "iso"]),
        ];
        for (program, args) in sources {
            match tail(program, args, &tx).await {
                Ok(true) => {
                    tracing::info!(source = program, "log source ended");
                    return;
                }
                Ok(false) => tracing::debug!(source = program, "log source produced nothing"),
                Err(err) => tracing::debug!(source = program, error = %err, "log source failed"),
            }
            if tx.is_closed() {
                return;
            }
        }
        tracing::warn!("no usable kernel log source (journalctl/dmesg) — Logs view stays empty");
    });
}

/// Streams one source until EOF. Returns whether it produced any output line.
async fn tail(program: &str, args: &[&str], tx: &mpsc::Sender<LogEntry>) -> std::io::Result<bool> {
    #[allow(clippy::disallowed_methods)] // resolve_trusted + env_clear: sanctioned log-tail spawn
    let mut child = tokio::process::Command::new(super::process::resolve_trusted(program))
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let Some(stdout) = child.stdout.take() else {
        return Ok(false);
    };
    let mut lines = BufReader::new(stdout).lines();
    let mut produced = false;
    while let Ok(Some(line)) = lines.next_line().await {
        produced = true;
        if let Some(entry) = parse_line(&line)
            && tx.send(entry).await.is_err()
        {
            return Ok(true); // UI is gone
        }
    }
    Ok(produced)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const REJECT_LINE: &str = "2026-07-16T10:00:00+0000 fedora kernel: FINAL_REJECT: IN=eth0 OUT= MAC=aa:bb SRC=203.0.113.7 DST=172.17.0.2 LEN=60 TOS=0x00 PROTO=TCP SPT=51000 DPT=23 WINDOW=64240 SYN";
    const DROP_LINE: &str = "2026-07-16T10:00:01+0000 fedora kernel: filter_IN_public_DROP: IN=eth0 OUT= SRC=198.51.100.9 DST=172.17.0.2 PROTO=UDP SPT=999 DPT=53";
    const ACCEPT_LINE: &str = "2026-07-16T10:00:02+0000 fedora kernel: filter_IN_public_ACCEPT: IN=eth0 OUT= SRC=192.0.2.1 DST=172.17.0.2 PROTO=TCP DPT=22";

    #[test]
    fn parses_reject_drop_accept() {
        let entry = parse_line(REJECT_LINE).unwrap();
        assert_eq!(entry.action, LogAction::Reject);
        assert_eq!(entry.src, "203.0.113.7");
        assert_eq!(entry.dport, "23");
        assert_eq!(entry.proto, "TCP");
        assert_eq!(entry.iface, "eth0");
        assert_eq!(entry.time, "10:00:00");
        assert!(entry.action.is_denied());

        assert_eq!(parse_line(DROP_LINE).unwrap().action, LogAction::Drop);
        let accept = parse_line(ACCEPT_LINE).unwrap();
        assert_eq!(accept.action, LogAction::Accept);
        assert!(!accept.action.is_denied());
    }

    #[test]
    fn ignores_non_netfilter_lines() {
        assert!(parse_line("2026-07-16T10:00:00+0000 fedora systemd[1]: Started foo.").is_none());
        assert!(parse_line("random text").is_none());
    }
}
