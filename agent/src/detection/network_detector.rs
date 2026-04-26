use crate::db::Database;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::debug;

/// Ports considered common/expected for outbound traffic.
pub static COMMON_PORTS: &[u16] = &[
    20, 21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    3389, 8080, 8443, 8888,
];

/// Result from network IOC or behaviour analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkThreatResult {
    pub ip: String,
    pub port: u16,
    pub pid: u32,
    pub threat_type: NetworkThreatType,
    pub score: u8,
    pub ioc_source: Option<String>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NetworkThreatType {
    IocIp,
    IocDomain,
    Beaconing,
    RarePort,
    TorExitNode,
    HighFrequency,
}

pub struct NetworkDetector {
    db: Database,
    /// Tracks (pid, remote_ip) → Vec<timestamp_epoch_secs>
    beacon_tracker: std::sync::Mutex<HashMap<(u32, String), Vec<i64>>,>,
}

impl NetworkDetector {
    pub fn new(db: Database) -> Self {
        Self {
            db,
            beacon_tracker: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Check a remote IP against the IOC cache.
    pub async fn check_ip(&self, ip: &str, port: u16, pid: u32) -> Result<Option<NetworkThreatResult>> {
        if ip.is_empty() || ip == "0.0.0.0" || ip == "::" {
            return Ok(None);
        }

        debug!("Checking IP {}:{} for pid {}", ip, port, pid);

        if let Some(entry) = self.db.query_ioc_by_value("ip", ip)? {
            if !entry.is_allowlist {
                return Ok(Some(NetworkThreatResult {
                    ip: ip.to_string(),
                    port,
                    pid,
                    threat_type: NetworkThreatType::IocIp,
                    score: (entry.confidence as u8).min(100),
                    ioc_source: Some(entry.source),
                    details: format!("IP {} found in IOC feed", ip),
                }));
            }
        }
        Ok(None)
    }

    /// Check a domain against the IOC cache.
    pub async fn check_domain(&self, domain: &str, pid: u32) -> Result<Option<NetworkThreatResult>> {
        if domain.is_empty() {
            return Ok(None);
        }

        if let Some(entry) = self.db.query_ioc_by_value("domain", domain)? {
            if !entry.is_allowlist {
                return Ok(Some(NetworkThreatResult {
                    ip: domain.to_string(),
                    port: 0,
                    pid,
                    threat_type: NetworkThreatType::IocDomain,
                    score: (entry.confidence as u8).min(100),
                    ioc_source: Some(entry.source),
                    details: format!("Domain {} found in IOC feed", domain),
                }));
            }
        }
        Ok(None)
    }

    /// Determine if a port is unusual for outbound connections.
    pub fn is_rare_port(&self, port: u16) -> bool {
        port != 0 && !COMMON_PORTS.contains(&port)
    }

    /// Record a connection event and detect beaconing (>10 connections
    /// to the same host within a 60-second window).
    pub fn record_and_check_beaconing(
        &self,
        pid: u32,
        remote_ip: &str,
        now_epoch: i64,
    ) -> bool {
        let mut tracker = self.beacon_tracker.lock().unwrap();
        let key = (pid, remote_ip.to_string());
        let timestamps = tracker.entry(key).or_default();

        // Keep only entries within the last 60 seconds
        timestamps.retain(|t| now_epoch - t <= 60);
        timestamps.push(now_epoch);

        timestamps.len() >= 10
    }

    /// Clean up stale beacon tracking entries older than 5 minutes.
    pub fn cleanup_beacon_tracker(&self, now_epoch: i64) {
        let mut tracker = self.beacon_tracker.lock().unwrap();
        tracker.retain(|_, timestamps| {
            timestamps.retain(|t| now_epoch - t <= 300);
            !timestamps.is_empty()
        });
    }
}
