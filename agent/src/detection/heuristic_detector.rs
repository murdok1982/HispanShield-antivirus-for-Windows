use crate::scoring::ScoreFactors;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// LOLBin (Living off the Land Binaries) that are abused by attackers.
pub static LOLBINS: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "wmic.exe",
    "msiexec.exe",
    "regasm.exe",
    "regsvcs.exe",
    "installutil.exe",
    "msbuild.exe",
    "cmstp.exe",
    "odbcconf.exe",
    "appsyncpublishing.exe",
    "bginfo.exe",
    "wab.exe",
    "xwizard.exe",
    "ftp.exe",
    "nltest.exe",
    "replace.exe",
    "winrm.cmd",
    "pcalua.exe",
    "squirrel.exe",
];

/// Suspicious file extensions often used to disguise malware.
pub static SUSPICIOUS_EXTENSIONS: &[&str] = &[
    ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".psm1", ".psd1", ".hta", ".jar", ".lnk",
];

/// Suspicious double-extension patterns (e.g. document.pdf.exe).
pub static DOUBLE_EXTENSION_RE: once_cell::sync::Lazy<Regex> =
    once_cell::sync::Lazy::new(|| {
        Regex::new(r"(?i)\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.(exe|scr|bat|cmd|vbs|js|ps1)$")
            .unwrap()
    });

/// PowerShell suspicious argument patterns.
pub static PS_SUSPICIOUS_RE: once_cell::sync::Lazy<Regex> =
    once_cell::sync::Lazy::new(|| {
        Regex::new(
            r"(?i)(-enc|-encodedcommand|iex|invoke-expression|downloadstring|net\.webclient|bypass|hidden|noprofile)",
        )
        .unwrap()
    });

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeuristicResult {
    pub flags: Vec<String>,
    pub score_factors: ScoreFactors,
}

/// Analyse a file path and optional command-line to produce heuristic flags.
pub fn analyse_file(path: &Path, cmdline: Option<&str>, parent_name: Option<&str>) -> HeuristicResult {
    let mut flags = Vec::new();
    let mut factors = ScoreFactors::default();

    let path_str = path.to_string_lossy().to_lowercase();
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();

    // --- Execution from temp ---
    if path_str.contains("\\temp\\")
        || path_str.contains("\\tmp\\")
        || path_str.contains("%temp%")
        || path_str.contains("\\appdata\\local\\temp")
    {
        factors.exec_from_temp = true;
        flags.push("exec_from_temp".into());
    }

    // --- Execution from AppData ---
    if path_str.contains("\\appdata\\roaming\\")
        || path_str.contains("\\appdata\\local\\")
    {
        factors.exec_from_appdata = true;
        flags.push("exec_from_appdata".into());
    }

    // --- LOLBin detection ---
    if LOLBINS.iter().any(|l| file_name == *l) {
        // Only flag LOLBins when suspicious cmdline args are present
        if let Some(cmd) = cmdline {
            let cmd_lower = cmd.to_lowercase();
            if file_name.contains("powershell") || file_name == "pwsh.exe" {
                if PS_SUSPICIOUS_RE.is_match(&cmd_lower) {
                    factors.lolbin_suspicious = true;
                    flags.push("lolbin_ps_suspicious_args".into());
                }
            } else if file_name == "certutil.exe" {
                if cmd_lower.contains("-urlcache") || cmd_lower.contains("-decode") {
                    factors.lolbin_suspicious = true;
                    flags.push("lolbin_certutil_download".into());
                }
            } else if file_name == "mshta.exe" || file_name == "wscript.exe" || file_name == "cscript.exe" {
                factors.lolbin_suspicious = true;
                flags.push(format!("lolbin_{}", file_name));
            } else if file_name == "rundll32.exe" {
                // rundll32 running from temp or with suspicious DLLs
                if factors.exec_from_temp {
                    factors.lolbin_suspicious = true;
                    flags.push("lolbin_rundll32_temp".into());
                }
            }
        }
    }

    // --- Double extension ---
    if DOUBLE_EXTENSION_RE.is_match(path.to_str().unwrap_or("")) {
        flags.push("double_extension".into());
        // Boost temp flag since this is almost always malicious
        factors.exec_from_temp = true;
    }

    // --- Suspicious extension in system paths ---
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{}", e.to_lowercase()))
        .unwrap_or_default();

    if SUSPICIOUS_EXTENSIONS.contains(&ext.as_str())
        && (path_str.contains("\\system32\\") || path_str.contains("\\syswow64\\"))
    {
        flags.push("suspicious_ext_in_system32".into());
    }

    // --- Suspicious parent process ---
    if let Some(parent) = parent_name {
        let parent_lower = parent.to_lowercase();
        // Office apps spawning shell processes
        let office_parents = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"];
        if office_parents.iter().any(|p| parent_lower == *p)
            && (file_name.contains("powershell")
                || file_name == "cmd.exe"
                || file_name == "wscript.exe"
                || file_name == "cscript.exe")
        {
            factors.suspicious_parent = true;
            flags.push(format!("office_spawned_{}", file_name));
        }

        // Browser spawning shell
        let browser_parents = [
            "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "opera.exe",
        ];
        if browser_parents.iter().any(|p| parent_lower == *p)
            && LOLBINS.iter().any(|l| file_name == *l)
        {
            factors.suspicious_parent = true;
            flags.push(format!("browser_spawned_{}", file_name));
        }
    }

    HeuristicResult { flags, score_factors: factors }
}

/// Detect potential ransomware: returns true if a mass file modification burst occurred.
pub fn detect_mass_file_modification(events_in_window: usize, threshold: usize) -> bool {
    events_in_window >= threshold
}

/// Check if a given extension is suspicious.
pub fn is_suspicious_extension(ext: &str) -> bool {
    let ext_lower = format!(".{}", ext.to_lowercase());
    SUSPICIOUS_EXTENSIONS.contains(&ext_lower.as_str())
}

/// Returns true if the file name matches a known LOLBin.
pub fn is_lolbin(file_name: &str) -> bool {
    let lower = file_name.to_lowercase();
    LOLBINS.iter().any(|l| lower == *l)
}
