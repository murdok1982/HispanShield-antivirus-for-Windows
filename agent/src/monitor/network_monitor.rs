use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP_STATE_ESTAB, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_OWNER_PID,
};
use windows::Win32::Foundation::NO_ERROR;

use crate::config::Config;
use crate::db::{Database, NetworkConnection};
use crate::scoring::{calculate_score, ScoreFactors};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub pid: u32,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: String,
    pub state: String,
}

// Tracks connection frequency per (pid, remote_addr) for beaconing detection
struct BeaconTracker {
    counts: HashMap<(u32, String), Vec<std::time::Instant>>,
    window: Duration,
    threshold: usize,
}

impl BeaconTracker {
    fn new() -> Self {
        Self {
            counts: HashMap::new(),
            window: Duration::from_secs(60),
            threshold: 10,
        }
    }

    fn record(&mut self, pid: u32, remote: &str) -> bool {
        let now = std::time::Instant::now();
        let key = (pid, remote.to_string());
        let times = self.counts.entry(key).or_default();

        // Remove old entries outside window
        times.retain(|&t| now.duration_since(t) < self.window);
        times.push(now);

        times.len() >= self.threshold
    }
}

pub async fn run(
    config: Config,
    db: Arc<Database>,
    event_tx: tokio::sync::broadcast::Sender<crate::monitor::MonitorEvent>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<()> {
    info!("Network monitor started");
    let mut beacon_tracker = BeaconTracker::new();
    let interval = Duration::from_secs(10);

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("Network monitor stopping");
                break;
            }
            _ = tokio::time::sleep(interval) => {
                if let Err(e) = scan_connections(&config, &db, &mut beacon_tracker, &event_tx).await {
                    warn!("Network scan error: {:?}", e);
                }
            }
        }
    }

    Ok(())
}

async fn scan_connections(
    config: &Config,
    db: &Database,
    beacon_tracker: &mut BeaconTracker,
    event_tx: &tokio::sync::broadcast::Sender<crate::monitor::MonitorEvent>,
) -> Result<()> {
    let connections = get_tcp_connections()?;

    for conn in &connections {
        let remote = &conn.remote_addr;

        // Skip local/loopback
        if remote.starts_with("127.") || remote == "0.0.0.0" || remote == "::" {
            continue;
        }

        let mut factors = ScoreFactors::default();

        // Check remote IP against IOC cache
        if let Ok(Some(ioc)) = db.query_ioc_by_value("ip", remote) {
            if !ioc.is_allowlist {
                factors.connection_to_ioc = true;
                warn!(
                    "IOC match! PID={} connecting to {} (source: {})",
                    conn.pid, remote, ioc.source
                );
            }
        }

        // Beaconing detection
        if beacon_tracker.record(conn.pid, remote) {
            factors.beaconing = true;
            warn!("Beaconing detected: PID={} → {} (>10 conns/60s)", conn.pid, remote);
        }

        // Rare port detection (not 80, 443, 8080, 8443, 53, 22, 25, 587)
        let common_ports = [80u16, 443, 8080, 8443, 53, 22, 25, 587, 465, 110, 143, 993, 995, 3389, 5985];
        if !common_ports.contains(&conn.remote_port) && conn.remote_port > 1024 {
            factors.rare_port_connection = true;
        }

        let score = calculate_score(&factors);

        // Save to DB
        let _ = db.save_connection(&NetworkConnection {
            id: None,
            captured_at: Utc::now().to_rfc3339(),
            pid: conn.pid as i64,
            process_name: get_process_name(conn.pid).unwrap_or_default(),
            local_addr: conn.local_addr.clone(),
            local_port: conn.local_port as i64,
            remote_addr: conn.remote_addr.clone(),
            remote_port: conn.remote_port as i64,
            protocol: conn.protocol.clone(),
            state: conn.state.clone(),
            score: score as i64,
            ioc_match: if factors.connection_to_ioc {
                Some(remote.clone())
            } else {
                None
            },
            country: None,
            asn: None,
        });

        if score >= config.scoring.alert_threshold {
            let _ = event_tx.send(crate::monitor::MonitorEvent::NetworkAlert {
                pid: conn.pid,
                remote_addr: remote.clone(),
                remote_port: conn.remote_port,
                score,
            });
        }
    }

    Ok(())
}

fn get_tcp_connections() -> Result<Vec<ConnectionInfo>> {
    let mut connections = Vec::new();
    let mut buf_size: u32 = 0;

    // First call to get required buffer size
    unsafe {
        GetExtendedTcpTable(None, &mut buf_size, false, 2, TCP_TABLE_OWNER_PID_ALL, 0);
    }

    let mut buf = vec![0u8; buf_size as usize];

    let result = unsafe {
        GetExtendedTcpTable(
            Some(buf.as_mut_ptr() as *mut _),
            &mut buf_size,
            false,
            2, // AF_INET
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if result != NO_ERROR.0 {
        return Ok(connections);
    }

    // Parse MIB_TCPTABLE_OWNER_PID
    let table = unsafe {
        &*(buf.as_ptr() as *const windows::Win32::NetworkManagement::IpHelper::MIB_TCPTABLE_OWNER_PID)
    };

    let rows = unsafe {
        std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize)
    };

    for row in rows {
        let local_ip = u32::from_be(row.dwLocalAddr);
        let remote_ip = u32::from_be(row.dwRemoteAddr);
        let local_port = u16::from_be(row.dwLocalPort as u16);
        let remote_port = u16::from_be(row.dwRemotePort as u16);

        connections.push(ConnectionInfo {
            pid: row.dwOwningPid,
            local_addr: ip_u32_to_string(local_ip),
            local_port,
            remote_addr: ip_u32_to_string(remote_ip),
            remote_port,
            protocol: "TCP".to_string(),
            state: tcp_state_to_string(row.dwState),
        });
    }

    Ok(connections)
}

fn ip_u32_to_string(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}

fn tcp_state_to_string(state: u32) -> String {
    match state {
        1 => "CLOSED",
        2 => "LISTENING",
        3 => "SYN_SENT",
        4 => "SYN_RECEIVED",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
    .to_string()
}

fn get_process_name(pid: u32) -> Option<String> {
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    use windows::Win32::Foundation::CloseHandle;

    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()? };
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut found = unsafe { Process32FirstW(snap, &mut entry).is_ok() };
    while found {
        if entry.th32ProcessID == pid {
            let name = String::from_utf16_lossy(
                &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(260)],
            );
            unsafe { CloseHandle(snap).ok() };
            return Some(name);
        }
        found = unsafe { Process32NextW(snap, &mut entry).is_ok() };
    }

    unsafe { CloseHandle(snap).ok() };
    None
}
