use crate::db::Database;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Result of a hash lookup against the IOC cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocMatch {
    pub ioc_type: String,
    pub value: String,
    pub source: String,
    pub confidence: i64,
    pub tags: Option<String>,
    pub is_allowlist: bool,
}

pub struct HashDetector {
    db: Database,
}

impl HashDetector {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Check SHA-256, SHA-1, and MD5 against the IOC cache.
    /// Returns the first (highest-confidence) match, or None.
    pub async fn check(
        &self,
        sha256: &str,
        sha1: &str,
        md5: &str,
    ) -> Result<Option<IocMatch>> {
        for (ioc_type, value) in [("sha256", sha256), ("sha1", sha1), ("md5", md5)] {
            if value.is_empty() {
                continue;
            }
            debug!("Checking {} {} against IOC cache", ioc_type, value);
            if let Some(entry) = self.db.query_ioc_by_value(ioc_type, value)? {
                return Ok(Some(IocMatch {
                    ioc_type: entry.ioc_type,
                    value: entry.value,
                    source: entry.source,
                    confidence: entry.confidence,
                    tags: entry.tags,
                    is_allowlist: entry.is_allowlist,
                }));
            }
        }
        Ok(None)
    }

    /// Check a single SHA-256 hash.
    pub async fn check_sha256(&self, sha256: &str) -> Result<Option<IocMatch>> {
        if sha256.is_empty() {
            return Ok(None);
        }
        let entry = self.db.query_ioc_by_value("sha256", sha256)?;
        Ok(entry.map(|e| IocMatch {
            ioc_type: e.ioc_type,
            value: e.value,
            source: e.source,
            confidence: e.confidence,
            tags: e.tags,
            is_allowlist: e.is_allowlist,
        }))
    }

    /// Check an IP address against the IOC cache.
    pub async fn check_ip(&self, ip: &str) -> Result<Option<IocMatch>> {
        if ip.is_empty() {
            return Ok(None);
        }
        let entry = self.db.query_ioc_by_value("ip", ip)?;
        Ok(entry.map(|e| IocMatch {
            ioc_type: e.ioc_type,
            value: e.value,
            source: e.source,
            confidence: e.confidence,
            tags: e.tags,
            is_allowlist: e.is_allowlist,
        }))
    }

    /// Check a domain against the IOC cache.
    pub async fn check_domain(&self, domain: &str) -> Result<Option<IocMatch>> {
        if domain.is_empty() {
            return Ok(None);
        }
        let entry = self.db.query_ioc_by_value("domain", domain)?;
        Ok(entry.map(|e| IocMatch {
            ioc_type: e.ioc_type,
            value: e.value,
            source: e.source,
            confidence: e.confidence,
            tags: e.tags,
            is_allowlist: e.is_allowlist,
        }))
    }

    /// Check a URL against the IOC cache.
    pub async fn check_url(&self, url: &str) -> Result<Option<IocMatch>> {
        if url.is_empty() {
            return Ok(None);
        }
        let entry = self.db.query_ioc_by_value("url", url)?;
        Ok(entry.map(|e| IocMatch {
            ioc_type: e.ioc_type,
            value: e.value,
            source: e.source,
            confidence: e.confidence,
            tags: e.tags,
            is_allowlist: e.is_allowlist,
        }))
    }
}
