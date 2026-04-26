use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, warn};
use yara::Compiler;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    /// YARA rule identifier
    pub rule_name: String,
    /// Namespace of the matched rule
    pub namespace: String,
    /// Tag annotations from the rule
    pub tags: Vec<String>,
    /// Offset and data of matched strings
    pub strings: Vec<YaraStringMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraStringMatch {
    pub identifier: String,
    pub offset: u64,
    pub data: Vec<u8>,
}

pub struct YaraDetector {
    rules: yara::Rules,
}

impl YaraDetector {
    /// Compile all .yar / .yara files found in `rules_dir` into a single ruleset.
    pub fn new(rules_dir: &Path) -> Result<Self> {
        let mut compiler = Compiler::new()?;

        if rules_dir.is_dir() {
            for entry in std::fs::read_dir(rules_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                    if ext == "yar" || ext == "yara" {
                        match compiler.add_rules_file(&path) {
                            Ok(_) => debug!("Loaded YARA rules from {:?}", path),
                            Err(e) => warn!("Failed to load YARA rules from {:?}: {}", path, e),
                        }
                    }
                }
            }
        }

        // Add built-in minimal rules as fallback
        compiler.add_rules_str(BUILTIN_RULES)?;

        let rules = compiler.compile_rules()?;
        Ok(Self { rules })
    }

    /// Build a YaraDetector from raw rule source strings (e.g., loaded from DB).
    pub fn from_rules_strings(rules_sources: &[String]) -> Result<Self> {
        let mut compiler = Compiler::new()?;
        compiler.add_rules_str(BUILTIN_RULES)?;
        for src in rules_sources {
            compiler.add_rules_str(src).map_err(|e| anyhow!("YARA compile error: {}", e))?;
        }
        let rules = compiler.compile_rules()?;
        Ok(Self { rules })
    }

    /// Scan a file on disk and return all rule matches.
    pub fn scan_file(&self, path: &Path) -> Result<Vec<YaraMatch>> {
        let matches = self.rules.scan_file(path, 30)?;
        Ok(convert_matches(matches))
    }

    /// Scan an in-memory byte buffer and return all rule matches.
    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<YaraMatch>> {
        let matches = self.rules.scan_mem(data, 30)?;
        Ok(convert_matches(matches))
    }
}

fn convert_matches(raw: Vec<yara::Rule>) -> Vec<YaraMatch> {
    raw.into_iter()
        .map(|rule| YaraMatch {
            rule_name: rule.identifier.to_string(),
            namespace: rule.namespace.to_string(),
            tags: rule.tags.iter().map(|t| t.to_string()).collect(),
            strings: rule
                .strings
                .iter()
                .flat_map(|s| {
                    s.matches.iter().map(|m| YaraStringMatch {
                        identifier: s.identifier.to_string(),
                        offset: m.offset as u64,
                        data: m.data.to_vec(),
                    })
                })
                .collect(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Built-in minimal ruleset (PE header + common malware patterns)
// ---------------------------------------------------------------------------
const BUILTIN_RULES: &str = r#"
rule PE_Executable
{
    meta:
        description = "Detects Windows PE executable"
        severity = "info"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}

rule Suspicious_PowerShell_Download
{
    meta:
        description = "PowerShell download cradle"
        severity = "high"
    strings:
        $a = "DownloadString" nocase
        $b = "IEX" nocase
        $c = "Invoke-Expression" nocase
        $d = "Net.WebClient" nocase
    condition:
        2 of ($a, $b, $c, $d)
}

rule Ransomware_Extension_Rename
{
    meta:
        description = "Potential ransomware file extension rename pattern"
        severity = "critical"
    strings:
        $a = ".encrypted" nocase
        $b = ".locked" nocase
        $c = ".crypto" nocase
        $d = "YOUR_FILES_ARE_ENCRYPTED" nocase
        $e = "HOW_TO_DECRYPT" nocase
    condition:
        any of them
}

rule LOLBin_CertUtil_Download
{
    meta:
        description = "CertUtil used for file download (LOLBin)"
        severity = "high"
    strings:
        $a = "certutil" nocase
        $b = "-urlcache" nocase
        $c = "-decode" nocase
    condition:
        $a and ($b or $c)
}

rule Suspicious_Base64_Payload
{
    meta:
        description = "Large base64 encoded payload in script"
        severity = "medium"
    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/
    condition:
        $b64
}

rule Mimikatz_Strings
{
    meta:
        description = "Mimikatz credential dumper strings"
        severity = "critical"
    strings:
        $a = "mimikatz" nocase
        $b = "sekurlsa" nocase
        $c = "lsadump" nocase
        $d = "wdigest" nocase
    condition:
        2 of them
}
"#;
