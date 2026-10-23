use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use chrono::{Duration, Utc};
use rusqlite::{params, params_from_iter, Connection, OptionalExtension, Row};
use rusqlite_migration::{Migrations, M};

use crate::error::{AppError, AppResult};
use crate::models::{now_rfc3339, AdvisoryRow, AuditRecord, Finding, Severity};

const MIGRATION_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS audits (
    id           TEXT PRIMARY KEY,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    score        INTEGER,
    status       TEXT NOT NULL,
    platform     TEXT NOT NULL,
    factors_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS findings (
    id           TEXT PRIMARY KEY,
    audit_id     TEXT NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    check_id     TEXT NOT NULL,
    title        TEXT NOT NULL,
    severity     TEXT NOT NULL,
    status       TEXT NOT NULL,
    category     TEXT NOT NULL,
    evidence     TEXT NOT NULL,
    explanation  TEXT NOT NULL,
    remediation  TEXT NOT NULL,
    verification TEXT NOT NULL,
    source       TEXT NOT NULL,
    detected_at  TEXT NOT NULL,
    resolved_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_audit ON findings(audit_id);
CREATE INDEX IF NOT EXISTS idx_findings_check ON findings(audit_id, check_id);
CREATE INDEX IF NOT EXISTS idx_audits_started ON audits(started_at DESC);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    at      TEXT NOT NULL,
    action  TEXT NOT NULL,
    detail  TEXT NOT NULL,
    outcome TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_at ON audit_log(at DESC);
"#;

const MIGRATION_V2_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS advisories (
    id              TEXT NOT NULL,
    package         TEXT NOT NULL,
    introduced      TEXT,
    fixed           TEXT,
    summary         TEXT NOT NULL,
    severity        TEXT,
    aliases_json    TEXT NOT NULL DEFAULT '[]',
    references_json TEXT NOT NULL DEFAULT '[]',
    modified        TEXT
);

CREATE INDEX IF NOT EXISTS idx_advisories_package ON advisories(package);
CREATE INDEX IF NOT EXISTS idx_advisories_id ON advisories(id);

CREATE TABLE IF NOT EXISTS advisory_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

fn migrations() -> Migrations<'static> {
    Migrations::new(vec![M::up(MIGRATION_SQL), M::up(MIGRATION_V2_SQL)])
}

#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
    path: PathBuf,
}

impl Db {
    pub fn open(path: &Path) -> AppResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        migrations().to_latest(&mut conn)?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
            path: path.to_path_buf(),
        };
        db.seed_defaults()?;
        db.recover_interrupted_audits()?;
        Ok(db)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn lock(&self) -> AppResult<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| AppError::Internal("database lock poisoned".to_string()))
    }

    fn seed_defaults(&self) -> AppResult<()> {
        let defaults = [
            ("theme", "dark"),
            ("telemetry", "false"),
            ("notifications", "true"),
            ("retentionDays", "90"),
            ("aiEnabled", "false"),
            ("aiProvider", "none"),
        ];
        let conn = self.lock()?;
        for (key, value) in defaults {
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?1, ?2)",
                params![key, value],
            )?;
        }
        Ok(())
    }

    fn recover_interrupted_audits(&self) -> AppResult<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE audits SET status = 'interrupted', finished_at = ?1 WHERE status = 'running'",
            params![now_rfc3339()],
        )?;
        Ok(())
    }

    pub fn start_audit(&self, platform: &str) -> AppResult<AuditRecord> {
        let audit = AuditRecord {
            id: uuid::Uuid::new_v4().to_string(),
            started_at: now_rfc3339(),
            finished_at: None,
            score: None,
            status: "running".to_string(),
            platform: platform.to_string(),
            findings_count: 0,
        };
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO audits (id, started_at, status, platform) VALUES (?1, ?2, ?3, ?4)",
            params![audit.id, audit.started_at, audit.status, audit.platform],
        )?;
        Ok(audit)
    }

    pub fn finish_audit(
        &self,
        id: &str,
        score: Option<u8>,
        status: &str,
        factors_json: &str,
    ) -> AppResult<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE audits SET finished_at = ?1, score = ?2, status = ?3, factors_json = ?4 WHERE id = ?5",
            params![now_rfc3339(), score, status, factors_json, id],
        )?;
        Ok(())
    }

    pub fn insert_findings(&self, findings: &[Finding]) -> AppResult<()> {
        if findings.is_empty() {
            return Ok(());
        }
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO findings (id, audit_id, check_id, title, severity, status, category,
                 evidence, explanation, remediation, verification, source, detected_at, resolved_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, NULL)",
            )?;
            for finding in findings {
                stmt.execute(params![
                    finding.id,
                    finding.audit_id,
                    finding.check_id,
                    finding.title,
                    finding.severity.as_str(),
                    finding.status,
                    finding.category,
                    finding.evidence,
                    finding.explanation,
                    finding.remediation,
                    finding.verification,
                    finding.source,
                    finding.detected_at,
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Resolve findings from the previous audit that are no longer reported by
    /// the new audit. Historical rows are kept and marked resolved.
    pub fn resolve_absent(
        &self,
        previous_audit_id: &str,
        current_check_ids: &[String],
    ) -> AppResult<u32> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let mut resolved = 0u32;
        let mut stale: Vec<(String, String)> = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT id, check_id FROM findings WHERE audit_id = ?1 AND resolved_at IS NULL",
            )?;
            let rows = stmt.query_map(params![previous_audit_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (id, check_id) = row?;
                if !current_check_ids.iter().any(|c| c == &check_id) {
                    stale.push((id, check_id));
                }
            }
        }
        let now = now_rfc3339();
        for (id, _) in stale {
            tx.execute(
                "UPDATE findings SET resolved_at = ?1, status = 'resolved' WHERE id = ?2",
                params![now, id],
            )?;
            resolved += 1;
        }
        tx.commit()?;
        Ok(resolved)
    }

    pub fn latest_audit(&self) -> AppResult<Option<AuditRecord>> {
        let conn = self.lock()?;
        let audit = conn
            .query_row(
                "SELECT a.id, a.started_at, a.finished_at, a.score, a.status, a.platform,
                        (SELECT COUNT(*) FROM findings f WHERE f.audit_id = a.id AND f.resolved_at IS NULL)
                 FROM audits a ORDER BY a.started_at DESC LIMIT 1",
                [],
                map_audit,
            )
            .optional()?;
        Ok(audit)
    }

    pub fn list_audits(&self, limit: u32) -> AppResult<Vec<AuditRecord>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT a.id, a.started_at, a.finished_at, a.score, a.status, a.platform,
                    (SELECT COUNT(*) FROM findings f WHERE f.audit_id = a.id AND f.resolved_at IS NULL)
             FROM audits a ORDER BY a.started_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit.clamp(1, 500)], map_audit)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(AppError::from)
    }

    pub fn findings_for_audit(&self, audit_id: &str) -> AppResult<Vec<Finding>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, audit_id, check_id, title, severity, status, category, evidence,
                    explanation, remediation, verification, source, detected_at, resolved_at
             FROM findings WHERE audit_id = ?1 ORDER BY detected_at DESC",
        )?;
        let rows = stmt.query_map(params![audit_id], map_finding)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(AppError::from)
    }

    pub fn list_open_findings(&self, limit: u32) -> AppResult<Vec<Finding>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, audit_id, check_id, title, severity, status, category, evidence,
                    explanation, remediation, verification, source, detected_at, resolved_at
             FROM findings WHERE resolved_at IS NULL
             ORDER BY detected_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit.clamp(1, 1000)], map_finding)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(AppError::from)
    }

    pub fn get_settings(&self) -> AppResult<Vec<(String, String)>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT key, value FROM settings ORDER BY key")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(AppError::from)
    }

    pub fn get_setting(&self, key: &str) -> AppResult<Option<String>> {
        let conn = self.lock()?;
        let value = conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> AppResult<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn log_action(&self, action: &str, detail: &str, outcome: &str) -> AppResult<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO audit_log (at, action, detail, outcome) VALUES (?1, ?2, ?3, ?4)",
            params![now_rfc3339(), action, detail, outcome],
        )?;
        Ok(())
    }

    pub fn list_audit_log(&self, limit: u32) -> AppResult<Vec<crate::models::AuditLogEntry>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(
            "SELECT id, at, action, detail, outcome FROM audit_log ORDER BY at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit.clamp(1, 1000)], |row| {
            Ok(crate::models::AuditLogEntry {
                id: row.get(0)?,
                at: row.get(1)?,
                action: row.get(2)?,
                detail: row.get(3)?,
                outcome: row.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(AppError::from)
    }

    pub fn prune(&self, retention_days: u32) -> AppResult<u32> {
        let cutoff = (Utc::now() - Duration::days(retention_days.clamp(1, 3650) as i64))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        let deleted = tx.execute("DELETE FROM audits WHERE started_at < ?1", params![cutoff])?;
        tx.execute("DELETE FROM audit_log WHERE at < ?1", params![cutoff])?;
        tx.commit()?;
        Ok(deleted as u32)
    }

    pub fn factors_for_audit(&self, id: &str) -> AppResult<Option<String>> {
        let conn = self.lock()?;
        let factors = conn
            .query_row(
                "SELECT factors_json FROM audits WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(factors)
    }

    pub fn audit_exists(&self, id: &str) -> AppResult<bool> {
        let conn = self.lock()?;
        let exists: Option<i64> = conn
            .query_row("SELECT 1 FROM audits WHERE id = ?1", params![id], |row| {
                row.get(0)
            })
            .optional()?;
        Ok(exists.is_some())
    }

    pub fn replace_advisories(
        &self,
        rows: &[AdvisoryRow],
        meta: &[(String, String)],
    ) -> AppResult<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM advisories", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO advisories
                 (id, package, introduced, fixed, summary, severity, aliases_json, references_json, modified)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            for row in rows {
                stmt.execute(params![
                    row.id,
                    row.package,
                    row.introduced,
                    row.fixed,
                    row.summary,
                    row.severity,
                    serde_json::to_string(&row.aliases)
                        .map_err(|err| AppError::Internal(err.to_string()))?,
                    serde_json::to_string(&row.references)
                        .map_err(|err| AppError::Internal(err.to_string()))?,
                    row.modified,
                ])?;
            }
        }
        tx.execute("DELETE FROM advisory_meta", [])?;
        for (key, value) in meta {
            tx.execute(
                "INSERT INTO advisory_meta (key, value) VALUES (?1, ?2)",
                params![key, value],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn advisory_meta(&self) -> AppResult<HashMap<String, String>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare("SELECT key, value FROM advisory_meta")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut meta = HashMap::new();
        for row in rows {
            let (key, value) = row?;
            meta.insert(key, value);
        }
        Ok(meta)
    }

    pub fn advisories_for(&self, packages: &[String]) -> AppResult<Vec<AdvisoryRow>> {
        if packages.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.lock()?;
        let mut result = Vec::new();
        for chunk in packages.chunks(400) {
            let placeholders = vec!["?"; chunk.len()].join(",");
            let sql = format!(
                "SELECT id, package, introduced, fixed, summary, severity,
                        aliases_json, references_json, modified
                 FROM advisories WHERE package IN ({placeholders})"
            );
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(params_from_iter(chunk.iter()), |row| {
                Ok(AdvisoryRow {
                    id: row.get(0)?,
                    package: row.get(1)?,
                    introduced: row.get(2)?,
                    fixed: row.get(3)?,
                    summary: row.get(4)?,
                    severity: row.get(5)?,
                    aliases: serde_json::from_str(&row.get::<_, String>(6)?).unwrap_or_default(),
                    references: serde_json::from_str(&row.get::<_, String>(7)?).unwrap_or_default(),
                    modified: row.get(8)?,
                })
            })?;
            for row in rows {
                result.push(row?);
            }
        }
        Ok(result)
    }

    pub fn db_size_bytes(&self) -> u64 {
        std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0)
    }
}

fn map_audit(row: &Row<'_>) -> rusqlite::Result<AuditRecord> {
    Ok(AuditRecord {
        id: row.get(0)?,
        started_at: row.get(1)?,
        finished_at: row.get(2)?,
        score: row.get::<_, Option<i64>>(3)?.map(|v| v.clamp(0, 100) as u8),
        status: row.get(4)?,
        platform: row.get(5)?,
        findings_count: row.get::<_, i64>(6)? as u32,
    })
}

fn map_finding(row: &Row<'_>) -> rusqlite::Result<Finding> {
    let severity: String = row.get(4)?;
    Ok(Finding {
        id: row.get(0)?,
        audit_id: row.get(1)?,
        check_id: row.get(2)?,
        title: row.get(3)?,
        severity: Severity::parse(&severity),
        status: row.get(5)?,
        category: row.get(6)?,
        evidence: row.get(7)?,
        explanation: row.get(8)?,
        remediation: row.get(9)?,
        verification: row.get(10)?,
        source: row.get(11)?,
        detected_at: row.get(12)?,
        resolved_at: row.get(13)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{now_rfc3339, Severity};

    fn temp_db() -> (Db, PathBuf) {
        let path =
            std::env::temp_dir().join(format!("cybergates-test-{}.db", uuid::Uuid::new_v4()));
        let db = Db::open(&path).expect("open db");
        (db, path)
    }

    #[test]
    fn migrations_and_defaults() {
        let (db, path) = temp_db();
        let settings = db.get_settings().unwrap();
        assert!(settings.iter().any(|(k, v)| k == "theme" && v == "dark"));
        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn audit_and_findings_roundtrip() {
        let (db, path) = temp_db();
        let audit = db.start_audit("macos").unwrap();
        let finding = Finding {
            id: uuid::Uuid::new_v4().to_string(),
            audit_id: audit.id.clone(),
            check_id: "firewall".to_string(),
            title: "Firewall disabled".to_string(),
            severity: Severity::High,
            status: "open".to_string(),
            category: "firewall".to_string(),
            evidence: "state=0".to_string(),
            explanation: "explanation".to_string(),
            remediation: "enable".to_string(),
            verification: "re-check".to_string(),
            source: "test".to_string(),
            detected_at: now_rfc3339(),
            resolved_at: None,
        };
        db.insert_findings(std::slice::from_ref(&finding)).unwrap();
        db.finish_audit(&audit.id, Some(80), "completed", "[]")
            .unwrap();
        let latest = db.latest_audit().unwrap().unwrap();
        assert_eq!(latest.score, Some(80));
        assert_eq!(latest.findings_count, 1);
        assert_eq!(db.findings_for_audit(&audit.id).unwrap().len(), 1);
        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolutions_mark_absent_findings() {
        let (db, path) = temp_db();
        let first = db.start_audit("macos").unwrap();
        let finding = Finding {
            id: uuid::Uuid::new_v4().to_string(),
            audit_id: first.id.clone(),
            check_id: "firewall".to_string(),
            title: "Firewall disabled".to_string(),
            severity: Severity::High,
            status: "open".to_string(),
            category: "firewall".to_string(),
            evidence: "state=0".to_string(),
            explanation: "e".to_string(),
            remediation: "r".to_string(),
            verification: "v".to_string(),
            source: "test".to_string(),
            detected_at: now_rfc3339(),
            resolved_at: None,
        };
        db.insert_findings(std::slice::from_ref(&finding)).unwrap();
        let second = db.start_audit("macos").unwrap();
        let resolved = db
            .resolve_absent(&first.id, &["other".to_string()])
            .unwrap();
        assert_eq!(resolved, 1);
        let findings = db.findings_for_audit(&first.id).unwrap();
        assert!(findings[0].resolved_at.is_some());
        assert_eq!(findings[0].status, "resolved");
        let _ = second;
        drop(db);
        let _ = std::fs::remove_file(&path);
    }
}
