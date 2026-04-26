use crate::config::Config;
use crate::db::{Database, Event, ProcessSnapshot, Threat};
use crate::detection::{analyse_file, hash_file, is_lolbin, HashDetector};
use crate::scoring::{calculate_score, risk_level, RiskLevel};
use anyhow::Result;
use chrono::Utc;
use serde_json::json;
use std::collections::HashMap;
use std::mem::size_of;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::time::{interval, Duration};
use tracing::{debug, info, warn};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HINSTANCE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

const SNAPSHOT_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: Option<String>,
}

pub struct ProcessMonitor {
    config: Arc<Config>,
    db: Database,
    shutdown_rx: broadcast::Receiver<()>,
}

impl ProcessMonitor {
    pub fn new(
        config: Arc<Config>,
        db: Database,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Self {
        Self { config, db, shutdown_rx }
    }

    /// Run process monitoring loop, taking snapshots every 30 seconds.
    pub async fn run(mut self) -> Result<()> {
        let mut tick = interval(Duration::from_secs(SNAPSHOT_INTERVAL_SECS));

        loop {
            tokio::select! {
                _ = self.shutdown_rx.recv() => {
                    info!("Process monitor shutting down");
                    break;
                }
                _ = tick.tick() => {
                    if let Err(e) = self.take_snapshot().await {
                        warn!("Process snapshot error: {}", e);
                    }
                }
            }
        }
        Ok(())
    }

    async fn take_snapshot(&self) -> Result<()> {
        let processes = enumerate_processes()?;
        let now = Utc::now().to_rfc3339();

        // Build PID→name map for parent lookup
        let pid_map: HashMap<u32, String> =
            processes.iter().map(|p| (p.pid, p.name.clone())).collect();

        for proc in &processes {
            let mut factors = crate::scoring::ScoreFactors::default();
            let mut flags: Vec<String> = Vec::new();

            // Check if it's a LOLBin
            let is_lolbin_proc = is_lolbin(&proc.name);

            // Path-based analysis
            if let Some(path_str) = &proc.path {
                let path = PathBuf::from(path_str);
                let heuristic = analyse_file(&path, None, pid_map.get(&proc.ppid).map(|s| s.as_str()));
                flags.extend(heuristic.flags.clone());

                // Merge heuristic factors
                let hf = &heuristic.score_factors;
                if hf.exec_from_temp { factors.exec_from_temp = true; }
                if hf.exec_from_appdata { factors.exec_from_appdata = true; }
                if hf.suspicious_parent { factors.suspicious_parent = true; }
                if hf.lolbin_suspicious { factors.lolbin_suspicious = true; }
                if hf.no_digital_signature { factors.no_digital_signature = true; }

                // Hash check (async IOC lookup)
                if let Ok((sha256, sha1, md5)) = hash_file(&path) {
                    let hash_detector = HashDetector::new(Database::new(self.db.conn()));
                    if let Ok(Some(ioc)) = hash_detector.check(&sha256, &sha1, &md5).await {
                        factors.hash_in_feed = true;
                        flags.push(format!("ioc_hash_{}", ioc.source));
                    }
                }
            }

            let score = calculate_score(&factors);
            let level = risk_level(score);

            let snap = ProcessSnapshot {
                id: None,
                captured_at: now.clone(),
                pid: proc.pid as i64,
                ppid: Some(proc.ppid as i64),
                name: proc.name.clone(),
                path: proc.path.clone(),
                cmdline: None,
                hash_sha256: None,
                signed: None,
                signer: None,
                score: score as i64,
                connections: 0,
                status: "Running".into(),
                flags: if flags.is_empty() { None } else {
                    Some(serde_json::to_string(&flags).unwrap_or_default())
                },
            };

            if let Err(e) = self.db.save_process_snapshot(&snap) {
                debug!("Failed to save process snapshot for PID {}: {}", proc.pid, e);
            }

            // Emit threat for high/critical processes
            if level == RiskLevel::High || level == RiskLevel::Critical {
                let severity = if level == RiskLevel::Critical { "Critical" } else { "High" };
                let event = Event {
                    id: None,
                    timestamp: now.clone(),
                    event_type: "Threat".into(),
                    severity: severity.into(),
                    source: Some("ProcessMonitor".into()),
                    path: proc.path.clone(),
                    pid: Some(proc.pid as i64),
                    process_name: Some(proc.name.clone()),
                    score: Some(score as i64),
                    details: Some(json!({ "flags": flags }).to_string()),
                    resolved: false,
                };
                if let Err(e) = self.db.insert_event(&event) {
                    warn!("Failed to insert process threat event: {}", e);
                }

                let threat = Threat {
                    id: None,
                    detected_at: now.clone(),
                    threat_type: if is_lolbin_proc { "LOLBin" } else { "Suspicious" }.into(),
                    name: None,
                    path: proc.path.clone(),
                    pid: Some(proc.pid as i64),
                    process_name: Some(proc.name.clone()),
                    hash_sha256: None,
                    hash_sha1: None,
                    hash_md5: None,
                    score: score as i64,
                    detection_method: "Heuristic".into(),
                    ioc_source: None,
                    status: "Active".into(),
                    action_taken: None,
                    details: Some(json!({ "flags": flags }).to_string()),
                };
                if let Err(e) = self.db.insert_threat(&threat) {
                    warn!("Failed to insert process threat: {}", e);
                } else {
                    info!("Suspicious process detected: {} (PID {}, score {})", proc.name, proc.pid, score);
                }
            }
        }
        Ok(())
    }
}

/// Enumerate all running processes using CreateToolhelp32Snapshot.
pub fn enumerate_processes() -> Result<Vec<ProcessInfo>> {
    let mut processes = Vec::new();

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }?;

    let mut entry = PROCESSENTRY32 {
        dwSize: size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };

    let first = unsafe { Process32First(snapshot, &mut entry) };
    if first.is_err() {
        unsafe { CloseHandle(snapshot) }?;
        return Ok(processes);
    }

    loop {
        let name = {
            let bytes: Vec<u8> = entry.szExeFile.iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as u8)
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        };

        let path = get_process_path(entry.th32ProcessID);

        processes.push(ProcessInfo {
            pid: entry.th32ProcessID,
            ppid: entry.th32ParentProcessID,
            name,
            path,
        });

        if unsafe { Process32Next(snapshot, &mut entry) }.is_err() {
            break;
        }
    }

    unsafe { CloseHandle(snapshot) }?;
    Ok(processes)
}

/// Query the full executable path for a running process.
fn get_process_path(pid: u32) -> Option<String> {
    if pid == 0 || pid == 4 {
        return None;
    }

    let handle = unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?
    };

    let mut buf = [0u16; 32768];
    let mut size = buf.len() as u32;

    let result = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut size,
        )
    };

    unsafe { CloseHandle(handle).ok() };

    if result.is_ok() {
        Some(String::from_utf16_lossy(&buf[..size as usize]))
    } else {
        None
    }
}
