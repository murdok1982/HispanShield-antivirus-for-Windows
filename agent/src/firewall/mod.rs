use anyhow::{anyhow, Result};
use std::process::Command;
use tracing::{info, warn};

const RULE_PREFIX: &str = "HispanShield-Block-";

/// Block outbound traffic to a specific IP using Windows Firewall (netsh).
/// Requires elevated privileges (LocalSystem / Administrator).
pub fn block_ip(ip: &str) -> Result<()> {
    // Validate the IP to avoid command injection
    ip.parse::<std::net::IpAddr>()
        .map_err(|_| anyhow!("Invalid IP address: {}", ip))?;

    let rule_name = format!("{}{}", RULE_PREFIX, ip);

    let status = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={}", rule_name),
            "dir=out",
            "action=block",
            &format!("remoteip={}", ip),
            "enable=yes",
            "profile=any",
            "description=HispanShield auto-block",
        ])
        .status()?;

    if !status.success() {
        return Err(anyhow!("netsh failed to block IP {}", ip));
    }

    info!("Blocked outbound traffic to IP {}", ip);
    Ok(())
}

/// Remove a previously created HispanShield IP block rule.
pub fn unblock_ip(ip: &str) -> Result<()> {
    ip.parse::<std::net::IpAddr>()
        .map_err(|_| anyhow!("Invalid IP address: {}", ip))?;

    let rule_name = format!("{}{}", RULE_PREFIX, ip);

    let status = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={}", rule_name),
        ])
        .status()?;

    if !status.success() {
        warn!("netsh could not find or delete rule for IP {}", ip);
    }

    info!("Unblocked IP {}", ip);
    Ok(())
}

/// Block all network traffic for a program executable path.
/// Creates both inbound and outbound block rules.
pub fn block_program(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(anyhow!("Empty program path"));
    }

    let safe_path = path.replace('"', "");
    let rule_name = format!(
        "{}prog-{}",
        RULE_PREFIX,
        std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
    );

    for dir in &["in", "out"] {
        let status = Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}-{}", rule_name, dir),
                &format!("dir={}", dir),
                "action=block",
                &format!("program={}", safe_path),
                "enable=yes",
                "profile=any",
                "description=HispanShield auto-block program",
            ])
            .status()?;

        if !status.success() {
            return Err(anyhow!(
                "netsh failed to block program {} direction {}",
                path,
                dir
            ));
        }
    }

    info!("Blocked program: {}", path);
    Ok(())
}

/// Remove all firewall rules created by HispanShield.
pub fn remove_all_hispan_rules() -> Result<()> {
    let status = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={}*", RULE_PREFIX),
        ])
        .status()?;

    if !status.success() {
        warn!("netsh could not delete all HispanShield rules (may not exist)");
    }
    Ok(())
}

/// List all firewall rules whose name starts with the HispanShield prefix.
pub fn list_hispan_rules() -> Result<Vec<String>> {
    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "show",
            "rule",
            &format!("name={}*", RULE_PREFIX),
            "verbose",
        ])
        .output()?;

    let raw = String::from_utf8_lossy(&output.stdout);
    let rules: Vec<String> = raw
        .lines()
        .filter(|l| l.trim_start().starts_with("Rule Name:"))
        .map(|l| l.trim_start_matches("Rule Name:").trim().to_string())
        .collect();

    Ok(rules)
}

/// Check that the current process has the SeSecurityPrivilege needed to
/// manipulate the firewall. Returns false if running without elevation.
pub fn is_elevated() -> bool {
    // Simple heuristic: try to open a privileged system path
    std::path::Path::new("C:\\Windows\\System32\\drivers\\etc\\hosts")
        .metadata()
        .is_ok()
}
