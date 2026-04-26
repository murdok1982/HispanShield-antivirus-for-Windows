use crate::config::{FeedConfig, FeedType, FeedsConfig};
use crate::db::{Database, FeedStatusRow, IocEntry};
use anyhow::{anyhow, Result};
use chrono::{Duration, Utc};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{error, info, warn};

pub struct FeedManager {
    db: Database,
    client: Client,
    config: FeedsConfig,
}

impl FeedManager {
    /// Create a new FeedManager with a shared HTTP client.
    pub fn new(db: Database, config: FeedsConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .user_agent("HispanShield-Agent/0.1")
            .build()?;
        Ok(Self { db, client, config })
    }

    /// Update all enabled feeds that have exceeded their TTL.
    pub async fn update_all_feeds(&self) -> HashMap<String, Result<usize>> {
        let mut results = HashMap::new();
        for feed in &self.config.feeds {
            if !feed.enabled {
                continue;
            }
            if !self.feed_needs_update(feed) {
                info!("Feed '{}' is still fresh, skipping", feed.name);
                continue;
            }
            info!("Updating feed '{}'", feed.name);
            let result = self.download_feed(feed).await;
            results.insert(feed.name.clone(), result);
        }
        results
    }

    /// Check whether a feed's TTL has elapsed since last update.
    fn feed_needs_update(&self, feed: &FeedConfig) -> bool {
        match self.db.get_all_feed_status() {
            Ok(statuses) => {
                let status = statuses.iter().find(|s| s.name == feed.name);
                match status {
                    Some(s) => match &s.last_updated {
                        Some(ts) => {
                            if let Ok(last) = chrono::DateTime::parse_from_rfc3339(ts) {
                                let age = Utc::now().signed_duration_since(last.with_timezone(&Utc));
                                age > Duration::hours(feed.ttl_hours as i64)
                            } else {
                                true
                            }
                        }
                        None => true,
                    },
                    None => true,
                }
            }
            Err(_) => true,
        }
    }

    /// Download and parse a single feed, storing IOCs in the database.
    pub async fn download_feed(&self, feed: &FeedConfig) -> Result<usize> {
        // Mark as updating
        self.db.update_feed_status(&FeedStatusRow {
            name: feed.name.clone(),
            last_updated: None,
            next_update: None,
            ioc_count: 0,
            status: "Updating".into(),
            error_msg: None,
            checksum: None,
        })?;

        let response = match self.client.get(&feed.url).send().await {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("HTTP request failed: {}", e);
                error!("Feed '{}' download error: {}", feed.name, msg);
                self.db.update_feed_status(&FeedStatusRow {
                    name: feed.name.clone(),
                    last_updated: None,
                    next_update: None,
                    ioc_count: 0,
                    status: "Error".into(),
                    error_msg: Some(msg.clone()),
                    checksum: None,
                })?;
                return Err(anyhow!(msg));
            }
        };

        if !response.status().is_success() {
            let msg = format!("HTTP {}", response.status());
            self.db.update_feed_status(&FeedStatusRow {
                name: feed.name.clone(),
                last_updated: None,
                next_update: None,
                ioc_count: 0,
                status: "Error".into(),
                error_msg: Some(msg.clone()),
                checksum: None,
            })?;
            return Err(anyhow!(msg));
        }

        let body = response.text().await?;

        // Clear old entries for a full refresh
        self.db.clear_feed_iocs(&feed.name)?;

        let iocs = match feed.feed_type {
            FeedType::MalwareBazaar => self.parse_malwarebazaar_csv(&body, &feed.name),
            FeedType::ThreatFox => self.parse_threatfox_csv(&body, &feed.name),
            FeedType::UrlHaus => self.parse_urlhaus_csv(&body, &feed.name),
            FeedType::FeodoTracker => self.parse_feodo_txt(&body, &feed.name),
            FeedType::MispWarninglist => self.parse_misp_warninglist(&body, &feed.name),
            FeedType::CustomTxt => self.parse_custom_txt(&body, &feed.name),
            FeedType::CustomCsv => self.parse_custom_csv(&body, &feed.name),
            FeedType::CustomJson => self.parse_custom_json(&body, &feed.name),
            _ => {
                warn!("Unsupported feed type for '{}', skipping parse", feed.name);
                vec![]
            }
        };

        let count = iocs.len();
        for ioc in &iocs {
            if let Err(e) = self.db.upsert_ioc(ioc) {
                warn!("Failed to upsert IOC {}: {}", ioc.value, e);
            }
        }

        let now = Utc::now();
        let next = now + Duration::hours(feed.ttl_hours as i64);

        self.db.update_feed_status(&FeedStatusRow {
            name: feed.name.clone(),
            last_updated: Some(now.to_rfc3339()),
            next_update: Some(next.to_rfc3339()),
            ioc_count: count as i64,
            status: "OK".into(),
            error_msg: None,
            checksum: None,
        })?;

        info!("Feed '{}' updated: {} IOCs imported", feed.name, count);
        Ok(count)
    }

    // -----------------------------------------------------------------------
    // Parsers
    // -----------------------------------------------------------------------

    /// Parse MalwareBazaar CSV export (sha256_hash, md5_hash, sha1_hash, reporter, file_name, ...).
    pub fn parse_malwarebazaar_csv(&self, data: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now().to_rfc3339();
        let mut iocs = Vec::new();

        let mut rdr = csv::ReaderBuilder::new()
            .comment(Some(b'#'))
            .flexible(true)
            .from_reader(data.as_bytes());

        for result in rdr.records() {
            let record = match result {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Fields: sha256_hash(0), md5_hash(1), sha1_hash(2), first_seen(3), ...
            let sha256 = record.get(0).unwrap_or("").trim().to_lowercase();
            let md5 = record.get(1).unwrap_or("").trim().to_lowercase();
            let sha1 = record.get(2).unwrap_or("").trim().to_lowercase();
            let first_seen = record.get(3).unwrap_or("").trim().to_string();

            if sha256.len() == 64 {
                iocs.push(IocEntry {
                    id: None,
                    ioc_type: "sha256".into(),
                    value: sha256,
                    source: source.into(),
                    confidence: 80,
                    first_seen: Some(first_seen.clone()),
                    last_seen: Some(now.clone()),
                    tags: Some("[\"malware\"]".into()),
                    is_allowlist: false,
                });
            }
            if md5.len() == 32 {
                iocs.push(IocEntry {
                    id: None,
                    ioc_type: "md5".into(),
                    value: md5,
                    source: source.into(),
                    confidence: 75,
                    first_seen: Some(first_seen.clone()),
                    last_seen: Some(now.clone()),
                    tags: Some("[\"malware\"]".into()),
                    is_allowlist: false,
                });
            }
            if sha1.len() == 40 {
                iocs.push(IocEntry {
                    id: None,
                    ioc_type: "sha1".into(),
                    value: sha1,
                    source: source.into(),
                    confidence: 75,
                    first_seen: Some(first_seen),
                    last_seen: Some(now.clone()),
                    tags: Some("[\"malware\"]".into()),
                    is_allowlist: false,
                });
            }
        }
        iocs
    }

    /// Parse ThreatFox CSV (first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type, ...).
    pub fn parse_threatfox_csv(&self, data: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now().to_rfc3339();
        let mut iocs = Vec::new();

        let mut rdr = csv::ReaderBuilder::new()
            .comment(Some(b'#'))
            .flexible(true)
            .from_reader(data.as_bytes());

        for result in rdr.records() {
            let record = match result {
                Ok(r) => r,
                Err(_) => continue,
            };

            let first_seen = record.get(0).unwrap_or("").trim().to_string();
            let ioc_value = record.get(2).unwrap_or("").trim().to_string();
            let ioc_type_raw = record.get(3).unwrap_or("").trim().to_lowercase();
            let threat_type = record.get(4).unwrap_or("").trim().to_string();
            let confidence_str = record.get(6).unwrap_or("50").trim().to_string();
            let confidence: i64 = confidence_str.parse().unwrap_or(50);

            if ioc_value.is_empty() {
                continue;
            }

            let ioc_type = match ioc_type_raw.as_str() {
                "ip:port" => {
                    // Strip port
                    let ip = ioc_value.split(':').next().unwrap_or(&ioc_value).to_string();
                    iocs.push(IocEntry {
                        id: None,
                        ioc_type: "ip".into(),
                        value: ip,
                        source: source.into(),
                        confidence,
                        first_seen: Some(first_seen.clone()),
                        last_seen: Some(now.clone()),
                        tags: Some(format!("[\"{}\"]", threat_type)),
                        is_allowlist: false,
                    });
                    continue;
                }
                "domain" => "domain",
                "url" => "url",
                "sha256_hash" | "md5_hash" | "sha1_hash" => {
                    if ioc_type_raw.contains("sha256") {
                        "sha256"
                    } else if ioc_type_raw.contains("md5") {
                        "md5"
                    } else {
                        "sha1"
                    }
                }
                _ => continue,
            };

            iocs.push(IocEntry {
                id: None,
                ioc_type: ioc_type.into(),
                value: ioc_value,
                source: source.into(),
                confidence,
                first_seen: Some(first_seen),
                last_seen: Some(now.clone()),
                tags: Some(format!("[\"{}\"]", threat_type)),
                is_allowlist: false,
            });
        }
        iocs
    }

    /// Parse URLhaus CSV (id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter).
    pub fn parse_urlhaus_csv(&self, data: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now().to_rfc3339();
        let mut iocs = Vec::new();

        let mut rdr = csv::ReaderBuilder::new()
            .comment(Some(b'#'))
            .flexible(true)
            .from_reader(data.as_bytes());

        for result in rdr.records() {
            let record = match result {
                Ok(r) => r,
                Err(_) => continue,
            };

            let date_added = record.get(1).unwrap_or("").trim().to_string();
            let url = record.get(2).unwrap_or("").trim().to_string();
            let status = record.get(3).unwrap_or("").trim().to_lowercase();
            let threat = record.get(5).unwrap_or("malware").trim().to_string();
            let tags = record.get(6).unwrap_or("").trim().to_string();

            if url.is_empty() || status == "offline" {
                continue;
            }

            // Extract domain/IP from URL
            let domain = extract_host_from_url(&url);

            iocs.push(IocEntry {
                id: None,
                ioc_type: "url".into(),
                value: url,
                source: source.into(),
                confidence: 75,
                first_seen: Some(date_added.clone()),
                last_seen: Some(now.clone()),
                tags: Some(format!("[\"{}\",\"{}\"]", threat, tags)),
                is_allowlist: false,
            });

            if let Some(host) = domain {
                iocs.push(IocEntry {
                    id: None,
                    ioc_type: if is_ip(&host) { "ip" } else { "domain" }.into(),
                    value: host,
                    source: source.into(),
                    confidence: 65,
                    first_seen: Some(date_added),
                    last_seen: Some(now.clone()),
                    tags: Some(format!("[\"{}\"]", threat)),
                    is_allowlist: false,
                });
            }
        }
        iocs
    }

    /// Parse Feodo Tracker IP blocklist (plain text, one IP per line, # comments).
    pub fn parse_feodo_txt(&self, data: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now().to_rfc3339();
        data.lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(|line| {
                let ip = line.split(',').next().unwrap_or(line).trim().to_string();
                IocEntry {
                    id: None,
                    ioc_type: "ip".into(),
                    value: ip,
                    source: source.into(),
                    confidence: 85,
                    first_seen: None,
                    last_seen: Some(now.clone()),
                    tags: Some("[\"c2\",\"botnet\"]".into()),
                    is_allowlist: false,
                }
            })
            .filter(|e| !e.value.is_empty())
            .collect()
    }

    /// Parse MISP warning list JSON ({"name":"...","list":["domain1","domain2",...], "type":"hostname"}).
    /// These are generally allowlist entries (benign).
    pub fn parse_misp_warninglist(&self, data: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now().to_rfc3339();
        let mut iocs = Vec::new();

        let json: Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to parse MISP warninglist JSON: {}", e);
                return iocs;
            }
        };

        let list_type = json["type"].as_str().unwrap_or("hostname");
        let ioc_type = match list_type {
            "hostname" | "domain" => "domain",
            "ip" => "ip",
            "url" => "url",
            "sha256" => "sha256",
            _ => "domain",
        };

        if let Some(list) = json["list"].as_array() {
            for item in list {
                let value = match item.as_str() {
                    Some(s) => s.trim().to_string(),
                    None => continue,
                };
                if value.is_empty() {
                    continue;
                }
                iocs.push(IocEntry {
                    id: None,
                    ioc_type: ioc_type.into(),
                    value,
                    source: source.into(),
                    confidence: 90,
                    first_seen: None,
                    last_seen: Some(now.clone()),
                    tags: Some("[\"allowlist\"]".into()),
                    is_allowlist: true,
                });
            }
        }
        iocs
    }

    /// Parse a plain-text feed with one IOC per line.
    pub fn parse_custom_txt(&self, data: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now().to_rfc3339();
        data.lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(|line| {
                let value = line.trim().to_string();
                let ioc_type = infer_ioc_type(&value);
                IocEntry {
                    id: None,
                    ioc_type: ioc_type.into(),
                    value,
                    source: source.into(),
                    confidence: 60,
                    first_seen: None,
                    last_seen: Some(now.clone()),
                    tags: None,
                    is_allowlist: false,
                }
            })
            .collect()
    }

    /// Parse a generic CSV feed with at least two columns: type, value.
    pub fn parse_custom_csv(&self, data: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now().to_rfc3339();
        let mut iocs = Vec::new();

        let mut rdr = csv::ReaderBuilder::new()
            .comment(Some(b'#'))
            .flexible(true)
            .from_reader(data.as_bytes());

        for result in rdr.records() {
            let record = match result {
                Ok(r) => r,
                Err(_) => continue,
            };

            let ioc_type = record.get(0).unwrap_or("").trim().to_string();
            let value = record.get(1).unwrap_or("").trim().to_string();

            if ioc_type.is_empty() || value.is_empty() {
                continue;
            }

            iocs.push(IocEntry {
                id: None,
                ioc_type,
                value,
                source: source.into(),
                confidence: 60,
                first_seen: None,
                last_seen: Some(now.clone()),
                tags: None,
                is_allowlist: false,
            });
        }
        iocs
    }

    /// Parse a JSON array feed: [{"type":"...","value":"...","confidence":N}, ...].
    pub fn parse_custom_json(&self, data: &str, source: &str) -> Vec<IocEntry> {
        let now = Utc::now().to_rfc3339();
        let json: Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(e) => {
                warn!("Failed to parse custom JSON feed: {}", e);
                return vec![];
            }
        };

        let items = match json.as_array() {
            Some(a) => a,
            None => return vec![],
        };

        items
            .iter()
            .filter_map(|item| {
                let ioc_type = item["type"].as_str()?.trim().to_string();
                let value = item["value"].as_str()?.trim().to_string();
                if ioc_type.is_empty() || value.is_empty() {
                    return None;
                }
                let confidence = item["confidence"].as_i64().unwrap_or(60);
                Some(IocEntry {
                    id: None,
                    ioc_type,
                    value,
                    source: source.into(),
                    confidence,
                    first_seen: None,
                    last_seen: Some(now.clone()),
                    tags: item["tags"].as_str().map(|t| t.to_string()),
                    is_allowlist: item["allowlist"].as_bool().unwrap_or(false),
                })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_host_from_url(url: &str) -> Option<String> {
    let url = url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host = url.split('/').next()?.split('?').next()?;
    // Strip port
    let host = if host.starts_with('[') {
        // IPv6
        host.trim_end_matches(']').trim_start_matches('[').to_string()
    } else {
        host.split(':').next()?.to_string()
    };
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn is_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

fn infer_ioc_type(value: &str) -> &'static str {
    if value.parse::<std::net::IpAddr>().is_ok() {
        return "ip";
    }
    if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return "sha256";
    }
    if value.len() == 40 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return "sha1";
    }
    if value.len() == 32 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        return "md5";
    }
    if value.starts_with("http://") || value.starts_with("https://") {
        return "url";
    }
    "domain"
}
