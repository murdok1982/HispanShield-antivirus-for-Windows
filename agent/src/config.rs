use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub general: GeneralConfig,
    pub protection: ProtectionConfig,
    pub feeds: FeedsConfig,
    pub ipc: IpcConfig,
    pub quarantine: QuarantineConfig,
    pub scoring: ScoringConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub log_level: String,
    pub log_dir: PathBuf,
    pub data_dir: PathBuf,
    pub db_path: PathBuf,
    pub update_interval_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionConfig {
    pub realtime_enabled: bool,
    pub scan_on_access: bool,
    pub scan_on_execute: bool,
    pub monitor_network: bool,
    pub monitor_registry: bool,
    pub action_on_threat: ThreatAction,
    pub excluded_paths: Vec<PathBuf>,
    pub excluded_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatAction {
    AlertOnly,
    Quarantine,
    Block,
    KillAndQuarantine,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedsConfig {
    pub enabled: bool,
    pub auto_update: bool,
    pub update_interval_hours: u64,
    pub feeds: Vec<FeedConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedConfig {
    pub name: String,
    pub url: String,
    pub feed_type: FeedType,
    pub enabled: bool,
    pub ttl_hours: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FeedType {
    MalwareBazaar,
    ThreatFox,
    UrlHaus,
    FeodoTracker,
    SslBlacklist,
    MispWarninglist,
    YaraRules,
    CustomCsv,
    CustomJson,
    CustomTxt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcConfig {
    pub pipe_name: String,
    pub auth_token_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineConfig {
    pub quarantine_dir: PathBuf,
    pub max_size_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringConfig {
    /// Score threshold to emit an alert event (0-100)
    pub alert_threshold: u8,
    /// Score threshold to classify as High risk
    pub high_threshold: u8,
    /// Score threshold to classify as Critical risk
    pub critical_threshold: u8,
}

impl Default for Config {
    fn default() -> Self {
        let data_dir = PathBuf::from("C:\\ProgramData\\HispanShield");
        Config {
            general: GeneralConfig {
                log_level: "info".into(),
                log_dir: data_dir.join("logs"),
                data_dir: data_dir.clone(),
                db_path: data_dir.join("hispanshield.db"),
                update_interval_hours: 6,
            },
            protection: ProtectionConfig {
                realtime_enabled: true,
                scan_on_access: true,
                scan_on_execute: true,
                monitor_network: true,
                monitor_registry: true,
                action_on_threat: ThreatAction::Quarantine,
                excluded_paths: vec![],
                excluded_hashes: vec![],
            },
            feeds: FeedsConfig {
                enabled: true,
                auto_update: true,
                update_interval_hours: 6,
                feeds: default_feeds(),
            },
            ipc: IpcConfig {
                pipe_name: r"\\.\pipe\HispanShieldAgent".into(),
                auth_token_path: data_dir.join("ipc_token"),
            },
            quarantine: QuarantineConfig {
                quarantine_dir: data_dir.join("quarantine"),
                max_size_mb: 2048,
            },
            scoring: ScoringConfig {
                alert_threshold: 30,
                high_threshold: 60,
                critical_threshold: 80,
            },
        }
    }
}

fn default_feeds() -> Vec<FeedConfig> {
    vec![
        FeedConfig {
            name: "MalwareBazaar".into(),
            url: "https://bazaar.abuse.ch/export/csv/full/".into(),
            feed_type: FeedType::MalwareBazaar,
            enabled: true,
            ttl_hours: 24,
        },
        FeedConfig {
            name: "ThreatFox".into(),
            url: "https://threatfox.abuse.ch/export/csv/full/".into(),
            feed_type: FeedType::ThreatFox,
            enabled: true,
            ttl_hours: 12,
        },
        FeedConfig {
            name: "URLhaus".into(),
            url: "https://urlhaus.abuse.ch/downloads/csv/".into(),
            feed_type: FeedType::UrlHaus,
            enabled: true,
            ttl_hours: 6,
        },
        FeedConfig {
            name: "Feodo Tracker".into(),
            url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt".into(),
            feed_type: FeedType::FeodoTracker,
            enabled: true,
            ttl_hours: 6,
        },
        FeedConfig {
            name: "MISP Warninglists".into(),
            url: "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/alexa/list.json".into(),
            feed_type: FeedType::MispWarninglist,
            enabled: true,
            ttl_hours: 168,
        },
    ]
}

impl Config {
    /// Load config from %ProgramData%\HispanShield\config.toml; create with defaults if absent.
    pub fn load() -> Result<Self> {
        let path = PathBuf::from("C:\\ProgramData\\HispanShield\\config.toml");
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            Ok(toml::from_str(&content)?)
        } else {
            let default = Config::default();
            default.save()?;
            Ok(default)
        }
    }

    /// Persist current config to disk.
    pub fn save(&self) -> Result<()> {
        let path = PathBuf::from("C:\\ProgramData\\HispanShield\\config.toml");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        std::fs::write(&path, content)?;
        Ok(())
    }
}
