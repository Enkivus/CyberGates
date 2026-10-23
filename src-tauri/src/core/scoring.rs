use uuid::Uuid;

use crate::models::{
    now_rfc3339, CheckResult, CheckStatus, Finding, ScoreBreakdown, ScoreFactor, Severity,
};

/// Deterministic, documented score:
/// - Each check carries an explicit weight and severity.
/// - Pass earns full weight, Warning earns half, Fail earns zero.
/// - Unavailable / NotApplicable checks are excluded from the denominator, so
///   missing platform permissions never silently inflate or deflate the score.
/// - The score is the weighted percentage of evaluated checks that passed.
pub fn evaluate(checks: &[CheckResult]) -> ScoreBreakdown {
    let mut earned: u32 = 0;
    let mut evaluated: u32 = 0;
    let mut factors = Vec::with_capacity(checks.len());

    for check in checks {
        let check_earned = match check.status {
            CheckStatus::Pass => check.weight,
            CheckStatus::Warning => check.weight / 2,
            CheckStatus::Fail => 0,
            CheckStatus::Unavailable | CheckStatus::NotApplicable => 0,
        };
        if check.status.is_scored() {
            earned += check_earned;
            evaluated += check.weight;
        }
        factors.push(ScoreFactor {
            id: check.id.clone(),
            title: check.title.clone(),
            category: check.category.clone(),
            status: check.status,
            severity: check.severity,
            weight: check.weight,
            earned: check_earned,
            evidence: check.evidence.clone(),
            explanation: check.explanation.clone(),
            remediation: check.remediation.clone(),
            verification: check.verification.clone(),
            source: check.source.clone(),
        });
    }

    factors.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| a.title.cmp(&b.title))
    });

    let score = if evaluated == 0 {
        None
    } else {
        Some(((earned as f64 / evaluated as f64) * 100.0).round() as u8)
    };

    ScoreBreakdown {
        score,
        label: label_for(score).to_string(),
        earned,
        evaluated,
        factors,
    }
}

pub fn label_for(score: Option<u8>) -> &'static str {
    match score {
        None => "Unknown",
        Some(90..=100) => "Excellent",
        Some(75..=89) => "Good",
        Some(50..=74) => "Needs attention",
        Some(_) => "At risk",
    }
}

pub fn findings_from_checks(audit_id: &str, checks: &[CheckResult]) -> Vec<Finding> {
    checks
        .iter()
        .filter(|check| check.status.is_finding())
        .map(|check| Finding {
            id: Uuid::new_v4().to_string(),
            audit_id: audit_id.to_string(),
            check_id: check.id.clone(),
            title: check.title.clone(),
            severity: check.severity,
            status: "open".to_string(),
            category: check.category.clone(),
            evidence: check.evidence.clone(),
            explanation: check.explanation.clone(),
            remediation: check.remediation.clone(),
            verification: check.verification.clone(),
            source: check.source.clone(),
            detected_at: check.checked_at.clone(),
            resolved_at: None,
        })
        .collect()
}

pub fn summarize_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut sorted = findings;
    sorted.sort_by(|a, b| {
        b.severity
            .rank()
            .cmp(&a.severity.rank())
            .then_with(|| b.detected_at.cmp(&a.detected_at))
    });
    sorted
}

pub fn finding_is_open(finding: &Finding) -> bool {
    finding.resolved_at.is_none() && finding.status == "open"
}

pub fn severity_rank(label: &str) -> u8 {
    Severity::parse(label).rank()
}

pub fn now() -> String {
    now_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(id: &str, status: CheckStatus, weight: u32) -> CheckResult {
        CheckResult {
            id: id.to_string(),
            title: id.to_string(),
            category: "test".to_string(),
            status,
            severity: Severity::High,
            weight,
            evidence: "evidence".to_string(),
            explanation: "explanation".to_string(),
            remediation: "remediation".to_string(),
            verification: "verification".to_string(),
            source: "test".to_string(),
            checked_at: now(),
        }
    }

    #[test]
    fn all_pass_is_100() {
        let score = evaluate(&[check("a", CheckStatus::Pass, 20), check("b", CheckStatus::Pass, 10)]);
        assert_eq!(score.score, Some(100));
        assert_eq!(score.earned, 30);
        assert_eq!(score.evaluated, 30);
    }

    #[test]
    fn warning_earns_half_and_unavailable_is_excluded() {
        let score = evaluate(&[
            check("a", CheckStatus::Pass, 20),
            check("b", CheckStatus::Warning, 10),
            check("c", CheckStatus::Unavailable, 100),
        ]);
        assert_eq!(score.evaluated, 30);
        assert_eq!(score.earned, 25);
        assert_eq!(score.score, Some(83));
    }

    #[test]
    fn no_evaluated_checks_has_no_score() {
        let score = evaluate(&[check("a", CheckStatus::Unavailable, 10)]);
        assert_eq!(score.score, None);
        assert_eq!(score.label, "Unknown");
    }

    #[test]
    fn findings_only_from_warning_and_fail() {
        let checks = [
            check("pass", CheckStatus::Pass, 1),
            check("warn", CheckStatus::Warning, 1),
            check("fail", CheckStatus::Fail, 1),
            check("na", CheckStatus::NotApplicable, 1),
        ];
        let findings = findings_from_checks("audit-1", &checks);
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.status == "open"));
    }

    #[test]
    fn labels_are_bounded() {
        assert_eq!(label_for(Some(100)), "Excellent");
        assert_eq!(label_for(Some(0)), "At risk");
    }
}
