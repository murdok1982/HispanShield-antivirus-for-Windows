#[cfg(test)]
mod scoring_tests {
    use hispanshield_agent::scoring::{calculate_score, risk_level, RiskLevel, ScoreFactors};

    #[test]
    fn score_zero_for_clean_file() {
        let factors = ScoreFactors::default();
        assert_eq!(calculate_score(&factors), 0);
        assert!(matches!(risk_level(0), RiskLevel::Clean));
    }

    #[test]
    fn score_critical_for_hash_in_feed() {
        let factors = ScoreFactors {
            hash_in_feed: true,
            ..Default::default()
        };
        let score = calculate_score(&factors);
        assert!(score >= 80, "Expected critical score, got {}", score);
        assert!(matches!(risk_level(score), RiskLevel::Critical));
    }

    #[test]
    fn score_high_for_yara_strong() {
        let factors = ScoreFactors {
            yara_match_strong: true,
            ..Default::default()
        };
        let score = calculate_score(&factors);
        assert!(score >= 60, "Expected high score, got {}", score);
    }

    #[test]
    fn score_suspicious_for_temp_exec_no_sign() {
        let factors = ScoreFactors {
            exec_from_temp: true,
            no_digital_signature: true,
            ..Default::default()
        };
        let score = calculate_score(&factors);
        assert!(score >= 30, "Expected suspicious score, got {}", score);
        assert!(matches!(risk_level(score), RiskLevel::Suspicious | RiskLevel::High | RiskLevel::Critical));
    }

    #[test]
    fn trusted_signature_reduces_score() {
        let without_trust = ScoreFactors {
            exec_from_temp: true,
            no_digital_signature: true,
            ..Default::default()
        };
        let with_trust = ScoreFactors {
            exec_from_temp: true,
            valid_signature_trusted: true,
            misp_allowlist: true,
            ..Default::default()
        };
        let score_without = calculate_score(&without_trust);
        let score_with = calculate_score(&with_trust);
        assert!(score_with < score_without, "Trusted signature should reduce score");
    }

    #[test]
    fn score_never_exceeds_100() {
        let factors = ScoreFactors {
            hash_in_feed: true,
            yara_match_strong: true,
            connection_to_ioc: true,
            mass_file_modification: true,
            autorun_persistence: true,
            beaconing: true,
            lolbin_suspicious: true,
            ..Default::default()
        };
        let score = calculate_score(&factors);
        assert!(score <= 100, "Score must not exceed 100, got {}", score);
    }

    #[test]
    fn score_never_below_zero() {
        let factors = ScoreFactors {
            valid_signature_trusted: true,
            misp_allowlist: true,
            ..Default::default()
        };
        let score = calculate_score(&factors);
        assert!(score <= 100, "Score underflow, got {}", score);
    }

    #[test]
    fn risk_level_boundaries() {
        assert!(matches!(risk_level(0), RiskLevel::Clean));
        assert!(matches!(risk_level(29), RiskLevel::Clean));
        assert!(matches!(risk_level(30), RiskLevel::Suspicious));
        assert!(matches!(risk_level(59), RiskLevel::Suspicious));
        assert!(matches!(risk_level(60), RiskLevel::High));
        assert!(matches!(risk_level(79), RiskLevel::High));
        assert!(matches!(risk_level(80), RiskLevel::Critical));
        assert!(matches!(risk_level(100), RiskLevel::Critical));
    }
}
