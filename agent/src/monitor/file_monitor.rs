use crate::config::Config;
use crate::db::{Database, Event, Threat};
use crate::detection::{
    analyse_file, hash_file, is_suspicious_extension, HashDetector, YaraDetector,
};
use crate::scoring::{calculate_score, risk_level, RiskLevel, ScoreFactors};
use anyhow::Result;
use chrono::Utc;
use notify::{Config as NotifyConfig, Event as FsEvent, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info, warn};

/// Burst detection window: 10 seconds, 50 modifications = potential ransomware.
const BURST_WINDOW_SECS: i64 = 10;
const BURST_THRESHOLD: usize = 50;

pub struct FileMonitor {
    config: Arc<Config>,
    db: Database,
    shutdown_rx: broadcast::Receiver<()>,
}

impl FileMonitor {
    pub fn new(
        config: Arc<Config>,
        db: Database,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Self {
        Self { config, db, shutdown_rx }
    }

    /// Launch the file system watcher. Runs until shutdown signal received.
    pub async fn run(mut self) -> Result<()> {
        let (tx, mut rx) = mpsc::channel::<notify::Result<FsEvent>>(512);

        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.blocking_send(res);
            },
            NotifyConfig::default(),
        )?;

        let watch_paths = self.watch_paths();
        for path in &watch_paths {
            if path.exists() {
                watcher.watch(path, RecursiveMode::Recursive)?;
                info!("File monitor watching: {:?}", path);
            }
        }

        // Track modification counts per parent directory for burst/ransomware detection
        let mut mod_tracker: HashMap<PathBuf, Vec<i64>> = HashMap::new();

        loop {
            tokio::select! {
                _ = self.shutdown_rx.recv() => {
                    info!("File monitor shutting down");
                    break;
                }
                event = rx.recv() => {
                    match event {
                        Some(Ok(fs_event)) => {
                            self.handle_event(fs_event, &mut mod_tracker).await;
                        }
                        Some(Err(e)) => warn!("File watch error: {}", e),
                        None => break,
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_event(
        &self,
        event: FsEvent,
        mod_tracker: &mut HashMap<PathBuf, Vec<i64>>,
    ) {
        let now = Utc::now();

        for path in &event.paths {
            // Skip excluded paths
            if self.is_excluded(path) {
                continue;
            }

            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    // Only analyse files, not directories
                    if path.is_file() {
                        // Track modifications per parent dir
                        if let Some(parent) = path.parent() {
                            let timestamps = mod_tracker.entry(parent.to_path_buf()).or_default();
                            let now_epoch = now.timestamp();
                            timestamps.retain(|t| now_epoch - t <= BURST_WINDOW_SECS);
                            timestamps.push(now_epoch);

                            if timestamps.len() >= BURST_THRESHOLD {
                                warn!("Mass file modification detected in {:?} ({} files in {}s)", parent, timestamps.len(), BURST_WINDOW_SECS);
                                self.emit_ransomware_alert(parent).await;
                            }
                        }

                        self.analyse_file(path).await;
                    }
                }
                EventKind::Remove(_) => {
                    debug!("File removed: {:?}", path);
                }
                _ => {}
            }
        }
    }

    async fn analyse_file(&self, path: &Path) {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        // Quick check: suspicious extension?
        let suspicious_ext = is_suspicious_extension(ext);

        // Skip very large files (>50MB) for hash computation to avoid stalling
        let file_size = std::fs::metadata(path)
            .map(|m| m.len())
            .unwrap_or(0);

        if file_size > 50 * 1024 * 1024 {
            debug!("Skipping large file ({}MB): {:?}", file_size / (1024 * 1024), path);
            return;
        }

        // Compute hashes
        let (sha256, sha1, md5) = match hash_file(path) {
            Ok(h) => h,
            Err(e) => {
                debug!("Could not hash {:?}: {}", path, e);
                return;
            }
        };

        // IOC hash check
        let hash_detector = HashDetector::new(Database::new(self.db.conn.clone()));
        let ioc_match = hash_detector
            .check(&sha256, &sha1, &md5)
            .await
            .unwrap_or(None);

        // Heuristics
        let heuristic = analyse_file(path, None, None);

        // Build score factors
        let mut factors = heuristic.score_factors.clone();
        if ioc_match.is_some() {
            factors.hash_in_feed = true;
        }
        if suspicious_ext
            && (factors.exec_from_temp || factors.exec_from_appdata)
        {
            // Executable in temp with suspicious extension — flag it
            factors.no_digital_signature = true;
        }

        let score = calculate_score(&factors);
        let level = risk_level(score);

        if level == RiskLevel::Clean {
            return;
        }

        let severity = match level {
            RiskLevel::Suspicious => "Medium",
            RiskLevel::High => "High",
            RiskLevel::Critical => "Critical",
            RiskLevel::Clean => return,
        };

        let now = Utc::now().to_rfc3339();
        let details = serde_json::to_string(&serde_json::json!({
            "sha256": sha256,
            "sha1": sha1,
            "md5": md5,
            "flags": heuristic.flags,
            "ioc_match": ioc_match.as_ref().map(|m| &m.source),
        }))
        .unwrap_or_default();

        let event = Event {
            id: None,
            timestamp: now.clone(),
            event_type: "FileScan".into(),
            severity: severity.into(),
            source: Some("FileMonitor".into()),
            path: Some(path.to_string_lossy().into_owned()),
            pid: None,
            process_name: None,
            score: Some(score as i64),
            details: Some(details.clone()),
            resolved: false,
        };

        if let Err(e) = self.db.insert_event(&event) {
            warn!("Failed to insert file event: {}", e);
        }

        if level == RiskLevel::High || level == RiskLevel::Critical {
            let threat = Threat {
                id: None,
                detected_at: now,
                threat_type: if ioc_match.is_some() { "Malware" } else { "Suspicious" }.into(),
                name: ioc_match.as_ref().and_then(|m| m.tags.clone()),
                path: Some(path.to_string_lossy().into_owned()),
                pid: None,
                process_name: None,
                hash_sha256: Some(sha256),
                hash_sha1: Some(sha1),
                hash_md5: Some(md5),
                score: score as i64,
                detection_method: if ioc_match.is_some() { "Hash" } else { "Heuristic" }.into(),
                ioc_source: ioc_match.as_ref().map(|m| m.source.clone()),
                status: "Active".into(),
                action_taken: None,
                details: Some(details),
            };

            if let Err(e) = self.db.insert_threat(&threat) {
                warn!("Failed to insert file threat: {}", e);
            } else {
                info!("Threat detected (score {}): {:?}", score, path);
            }
        }
    }

    async fn emit_ransomware_alert(&self, dir: &Path) {
        let event = Event {
            id: None,
            timestamp: Utc::now().to_rfc3339(),
            event_type: "Threat".into(),
            severity: "Critical".into(),
            source: Some("FileMonitor".into()),
            path: Some(dir.to_string_lossy().into_owned()),
            pid: None,
            process_name: None,
            score: Some(85),
            details: Some(r#"{"reason":"mass_file_modification","type":"Ransomware"}"#.into()),
            resolved: false,
        };
        if let Err(e) = self.db.insert_event(&event) {
            warn!("Failed to insert ransomware alert event: {}", e);
        }
    }

    fn watch_paths(&self) -> Vec<PathBuf> {
        let mut paths = vec![
            PathBuf::from("C:\\Users"),
            PathBuf::from("C:\\Windows\\Temp"),
            PathBuf::from("C:\\Windows\\System32"),
            PathBuf::from("C:\\ProgramData"),
        ];
        if let Ok(appdata) = std::env::var("APPDATA") {
            paths.push(PathBuf::from(appdata));
        }
        if let Ok(temp) = std::env::var("TEMP") {
            paths.push(PathBuf::from(temp));
        }
        paths
    }

    fn is_excluded(&self, path: &Path) -> bool {
        for excluded in &self.config.protection.excluded_paths {
            if path.starts_with(excluded) {
                return true;
            }
        }
        false
    }
}

// Make the db field accessible for the inner HashDetector construction
use crate::db::DbConn;

trait HasConn {
    fn conn(&self) -> DbConn;
}

impl Database {
    pub fn conn(&self) -> DbConn {
        self.conn.clone()
    }
}
