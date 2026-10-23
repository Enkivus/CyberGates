use crate::core::scoring::{self, finding_is_open};
use crate::db::Db;
use crate::error::AppResult;
use crate::models::{
    now_rfc3339, AuditRecord, Dashboard, Finding, ScoreFactor, SystemInfo,
};
use crate::platform::PlatformAudit;

pub fn execute(db: &Db, adapter: &dyn PlatformAudit) -> AppResult<Dashboard> {
    let previous = db.latest_audit()?;
    let audit = db.start_audit(adapter.platform_name())?;
    db.log_action(
        "audit.start",
        &format!("audit {} on {}", audit.id, adapter.platform_name()),
        "started",
    )?;

    let checks = adapter.audit();
    let breakdown = scoring::evaluate(&checks);
    let findings = scoring::findings_from_checks(&audit.id, &checks);
    let factors_json = serde_json::to_string(&breakdown.factors).unwrap_or_else(|_| "[]".to_string());

    let current_finding_ids: Vec<String> =
        findings.iter().map(|finding| finding.check_id.clone()).collect();

    let insert_result = db.insert_findings(&findings);
    if let Err(err) = insert_result {
        let _ = db.finish_audit(&audit.id, None, "failed", "[]");
        let _ = db.log_action("audit.finish", &audit.id, "failed");
        return Err(err);
    }

    if let Some(previous) = &previous {
        db.resolve_absent(&previous.id, &current_finding_ids)?;
    }

    db.finish_audit(&audit.id, breakdown.score, "completed", &factors_json)?;
    db.log_action(
        "audit.finish",
        &format!(
            "audit {} completed with score {} and {} findings",
            audit.id,
            breakdown
                .score
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            findings.len()
        ),
        "success",
    )?;

    db.set_setting("lastAuditId", &audit.id)?;

    build_dashboard(db, adapter)
}

pub fn build_dashboard(db: &Db, adapter: &dyn PlatformAudit) -> AppResult<Dashboard> {
    let system: SystemInfo = crate::services::system::collect(adapter);
    let last_audit = db.latest_audit()?;

    let mut score = None;
    let mut score_label = "Unknown".to_string();
    let mut earned = 0;
    let mut evaluated = 0;
    let mut factors: Vec<ScoreFactor> = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();

    if let Some(audit) = &last_audit {
        if audit.status == "completed" || audit.status == "interrupted" {
            if let Some(json) = db.factors_for_audit(&audit.id)? {
                factors = serde_json::from_str(&json).unwrap_or_default();
            }
            earned = factors.iter().map(|factor| factor.earned).sum();
            evaluated = factors
                .iter()
                .filter(|factor| {
                    matches!(
                        factor.status,
                        crate::models::CheckStatus::Pass
                            | crate::models::CheckStatus::Warning
                            | crate::models::CheckStatus::Fail
                    )
                })
                .map(|factor| factor.weight)
                .sum();
            if evaluated > 0 {
                score = Some(((earned as f64 / evaluated as f64) * 100.0).round() as u8);
                score_label = scoring::label_for(score).to_string();
            }
            if let Some(score_value) = audit.score {
                score = Some(score_value);
                score_label = scoring::label_for(score).to_string();
            }
            findings = db
                .findings_for_audit(&audit.id)?
                .into_iter()
                .filter(|finding| finding_is_open(finding) || finding.resolved_at.is_some())
                .collect();
        }
    }

    findings = scoring::summarize_findings(findings);
    let counts = Finding::severity_counts(&findings);

    Ok(Dashboard {
        system,
        score,
        score_label,
        earned,
        evaluated,
        factors,
        findings,
        counts,
        last_audit,
        generated_at: now_rfc3339(),
    })
}

pub fn history(db: &Db, limit: u32) -> AppResult<Vec<AuditRecord>> {
    db.list_audits(limit)
}
