use serde::{Deserialize, Serialize};

/// All boolean flags that contribute to (or reduce) a threat score.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ScoreFactors {
    /// File hash found in a malware feed (+90)
    pub hash_in_feed: bool,
    /// YARA rule with high-confidence match (+80)
    pub yara_match_strong: bool,
    /// Network connection to IOC-listed IP or domain (+70)
    pub connection_to_ioc: bool,
    /// Executable launched from a TEMP directory (+20)
    pub exec_from_temp: bool,
    /// Binary has no Authenticode signature (+15)
    pub no_digital_signature: bool,
    /// Parent process is a known suspicious process (+20)
    pub suspicious_parent: bool,
    /// LOLBin executing with suspicious arguments (+25)
    pub lolbin_suspicious: bool,
    /// Mass file modification detected (potential ransomware) (+40)
    pub mass_file_modification: bool,
    /// Persistence via Autorun registry key added (+35)
    pub autorun_persistence: bool,
    /// Repeated beaconing to same host detected (+30)
    pub beaconing: bool,
    /// File is signed by a trusted CA (-30)
    pub valid_signature_trusted: bool,
    /// Domain/IP present in MISP allowlist (benign) (-20)
    pub misp_allowlist: bool,
    /// YARA rule with lower-confidence match (+40)
    pub yara_match_weak: bool,
    /// Executable launched from AppData (+15)
    pub exec_from_appdata: bool,
    /// Connection to a rarely-used or suspicious port (+20)
    pub rare_port_connection: bool,
}

/// Compute a 0-100 risk score from a set of boolean factors.
pub fn calculate_score(factors: &ScoreFactors) -> u8 {
    let mut score: i32 = 0;

    if factors.hash_in_feed {
        score += 90;
    }
    if factors.yara_match_strong {
        score += 80;
    }
    if factors.connection_to_ioc {
        score += 70;
    }
    if factors.exec_from_temp {
        score += 20;
    }
    if factors.no_digital_signature {
        score += 15;
    }
    if factors.suspicious_parent {
        score += 20;
    }
    if factors.lolbin_suspicious {
        score += 25;
    }
    if factors.mass_file_modification {
        score += 40;
    }
    if factors.autorun_persistence {
        score += 35;
    }
    if factors.beaconing {
        score += 30;
    }
    if factors.valid_signature_trusted {
        score -= 30;
    }
    if factors.misp_allowlist {
        score -= 20;
    }
    if factors.yara_match_weak {
        score += 40;
    }
    if factors.exec_from_appdata {
        score += 15;
    }
    if factors.rare_port_connection {
        score += 20;
    }

    score.clamp(0, 100) as u8
}

/// Qualitative risk level derived from a numeric score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RiskLevel {
    /// Score 0-29: no significant indicators
    Clean,
    /// Score 30-59: worth investigating
    Suspicious,
    /// Score 60-79: likely malicious
    High,
    /// Score 80-100: confirmed threat
    Critical,
}

/// Map a numeric score to the corresponding risk level.
pub fn risk_level(score: u8) -> RiskLevel {
    match score {
        0..=29 => RiskLevel::Clean,
        30..=59 => RiskLevel::Suspicious,
        60..=79 => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_score() {
        let factors = ScoreFactors::default();
        assert_eq!(calculate_score(&factors), 0);
        assert_eq!(risk_level(0), RiskLevel::Clean);
    }

    #[test]
    fn hash_in_feed_is_critical() {
        let factors = ScoreFactors {
            hash_in_feed: true,
            ..Default::default()
        };
        assert!(calculate_score(&factors) >= 80);
        assert_eq!(risk_level(calculate_score(&factors)), RiskLevel::Critical);
    }

    #[test]
    fn trusted_signature_reduces_score() {
        let factors_unsigned = ScoreFactors {
            exec_from_temp: true,
            no_digital_signature: true,
            ..Default::default()
        };
        let factors_signed = ScoreFactors {
            exec_from_temp: true,
            valid_signature_trusted: true,
            ..Default::default()
        };
        assert!(calculate_score(&factors_unsigned) > calculate_score(&factors_signed));
    }

    #[test]
    fn score_clamps_at_100() {
        let factors = ScoreFactors {
            hash_in_feed: true,
            yara_match_strong: true,
            connection_to_ioc: true,
            mass_file_modification: true,
            autorun_persistence: true,
            ..Default::default()
        };
        assert_eq!(calculate_score(&factors), 100);
    }
}
