use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::db::Db;
use crate::error::{AppError, AppResult};
use crate::models::{now_rfc3339, AuditRecord, Finding, ScoreFactor};
use crate::security::filesystem::ensure_private_dir;
use crate::security::validate::html_escape;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportExport {
    pub path: String,
    pub format: String,
    pub bytes: u64,
    pub audit_id: String,
    pub warning: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonReport<'a> {
    product: &'a str,
    generated_at: String,
    warning: &'a str,
    audit: &'a AuditRecord,
    findings: &'a [Finding],
    factors: &'a [ScoreFactor],
}

pub fn export(
    db: &Db,
    reports_dir: &Path,
    audit_id: &str,
    format: &str,
) -> AppResult<ReportExport> {
    let format = crate::security::validate::report_format(format)?;
    if !db.audit_exists(audit_id)? {
        return Err(AppError::NotFound(format!("audit {audit_id}")));
    }
    let audit = db
        .list_audits(500)?
        .into_iter()
        .find(|candidate| candidate.id == audit_id)
        .ok_or_else(|| AppError::NotFound(format!("audit {audit_id}")))?;
    let findings = db.findings_for_audit(audit_id)?;
    let factors: Vec<ScoreFactor> = db
        .factors_for_audit(audit_id)?
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default();

    ensure_private_dir(reports_dir)?;
    let stamp = now_rfc3339().replace(':', "-");
    let path: PathBuf = reports_dir.join(format!(
        "cybergates-report-{stamp}-{}.{}",
        uuid::Uuid::new_v4(),
        format
    ));

    let warning = "This report may contain sensitive system information (hostnames, paths, accounts, and network details). Review before sharing.";
    let bytes = match format {
        "json" => {
            let report = JsonReport {
                product: "CyberGates",
                generated_at: now_rfc3339(),
                warning,
                audit: &audit,
                findings: &findings,
                factors: &factors,
            };
            let contents = serde_json::to_string_pretty(&report)
                .map_err(|err| AppError::Internal(err.to_string()))?;
            write_private_new(&path, contents.as_bytes())?;
            contents.len() as u64
        }
        "html" => {
            let contents = render_html(&audit, &findings, &factors, warning);
            write_private_new(&path, contents.as_bytes())?;
            contents.len() as u64
        }
        _ => unreachable!("format validated above"),
    };

    db.log_action(
        "report.export",
        &format!("audit={audit_id} format={format} path={}", path.display()),
        "success",
    )?;

    Ok(ReportExport {
        path: path.to_string_lossy().to_string(),
        format: format.to_string(),
        bytes,
        audit_id: audit_id.to_string(),
        warning: warning.to_string(),
    })
}

fn write_private_new(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

fn render_html(
    audit: &AuditRecord,
    findings: &[Finding],
    factors: &[ScoreFactor],
    warning: &str,
) -> String {
    let mut rows = String::new();
    for finding in findings {
        rows.push_str(&format!(
            "<tr><td class=\"{}\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(finding.severity.as_str()),
            html_escape(finding.severity.as_str()),
            html_escape(&finding.title),
            html_escape(&finding.evidence),
            html_escape(&finding.remediation),
            html_escape(&finding.status),
        ));
    }

    let mut factor_rows = String::new();
    for factor in factors {
        factor_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}/{}</td><td>{}</td></tr>",
            html_escape(&factor.title),
            html_escape(factor.status.as_str()),
            factor.earned,
            factor.weight,
            html_escape(&factor.evidence),
        ));
    }

    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>CyberGates Security Report</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0b1020;color:#e5edff;margin:0;padding:40px}}
h1{{margin:0 0 4px;font-size:28px}} .muted{{color:#93a4c7}} .warn{{background:#3b2a12;border:1px solid #8a5a15;padding:12px 16px;border-radius:8px;margin:20px 0}}
table{{width:100%;border-collapse:collapse;margin:16px 0}} th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #1e2942;vertical-align:top;font-size:13px}}
th{{color:#93a4c7;font-weight:600}} .critical{{color:#ff6b81}} .high{{color:#ff9f6b}} .medium{{color:#f2cc60}} .low{{color:#7ec8ff}} .info{{color:#9aa7bd}}
.score{{font-size:44px;font-weight:700;color:#67e8f9}}
</style></head><body>
<h1>CyberGates Security Report</h1>
<div class="muted">Audit {}</div>
<div class="muted">Platform: {} &middot; Started: {} &middot; Completed: {}</div>
<div class="score">{}</div>
<div class="muted">Score is derived from the weighted checks below. Unavailable checks are excluded.</div>
<div class="warn">{}</div>
<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Title</th><th>Evidence</th><th>Remediation</th><th>Status</th></tr></thead><tbody>{}</tbody></table>
<h2>Checks</h2>
<table><thead><tr><th>Check</th><th>Status</th><th>Earned</th><th>Evidence</th></tr></thead><tbody>{}</tbody></table>
<p class="muted">CyberGates does not test restores, exploit vulnerabilities, or guarantee that a remediation succeeded unless explicitly verified.</p>
</body></html>"#,
        html_escape(&audit.id),
        html_escape(&audit.platform),
        html_escape(&audit.started_at),
        html_escape(audit.finished_at.as_deref().unwrap_or("incomplete")),
        audit
            .score
            .map(|score| score.to_string())
            .unwrap_or_else(|| "N/A".to_string()),
        html_escape(warning),
        rows,
        factor_rows,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::filesystem::ensure_private_dir;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(unix)]
    #[test]
    fn exported_files_are_private_and_never_overwrite() {
        use std::os::unix::fs::PermissionsExt;

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("cybergates-report-test-{nonce}"));
        ensure_private_dir(&dir).unwrap();
        let path = dir.join("report.html");

        write_private_new(&path, b"report contents").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"report contents");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(write_private_new(&path, b"replacement").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"report contents");

        std::fs::remove_dir_all(dir).unwrap();
    }
}
