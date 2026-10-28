use std::collections::HashSet;
use std::io::{Cursor, Read};
use std::time::Duration;

use version_compare::{compare, Cmp};

use crate::db::Db;
use crate::error::{AppError, AppResult};
use crate::models::{
    now_rfc3339, AdvisoryMatch, AdvisoryReport, AdvisoryRow, AdvisoryUpdate, InstalledApp,
};

const SOURCE_URL: &str =
    "https://codeload.github.com/Homebrew/advisory-database/tar.gz/refs/heads/main";
const OSV_QUERYBATCH_URL: &str = "https://api.osv.dev/v1/querybatch";
const SOURCE_NAME: &str = "Homebrew advisory database (OSV format)";
const SCOPE: &str = "Homebrew formula advisories. Automatically generated records use the currently shipped version as an approximate fixed boundary, not the exact fixing version; CyberGates treats these as unverified and does not report them as matches. Only non-generated records with a same-upstream-version revision patch are eligible for a match. This early Homebrew feed is not a complete vulnerability database.";
const MAX_DOWNLOAD_BYTES: u64 = 64 * 1024 * 1024;
const MAX_UNPACKED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_RECORD_BYTES: u64 = 2 * 1024 * 1024;
const MAX_OSV_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_OSV_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_OSV_QUERY_PACKAGES: usize = 5000;
const MAX_OSV_PAGES: usize = 10;

pub fn update(db: &Db) -> AppResult<AdvisoryUpdate> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent("CyberGates/0.1.0")
        .build()
        .map_err(|err| AppError::Internal(format!("could not create HTTP client: {err}")))?;

    let response = client
        .get(SOURCE_URL)
        .send()
        .map_err(|err| AppError::Internal(format!("advisory download failed: {err}")))?;
    if !response.status().is_success() {
        return Err(AppError::Internal(format!(
            "advisory download returned HTTP {}",
            response.status()
        )));
    }
    if let Some(length) = response.content_length() {
        if length > MAX_DOWNLOAD_BYTES {
            return Err(AppError::Internal(format!(
                "advisory archive is larger than the {} MiB limit",
                MAX_DOWNLOAD_BYTES / (1024 * 1024)
            )));
        }
    }

    let mut archive_bytes = Vec::new();
    response
        .take(MAX_DOWNLOAD_BYTES + 1)
        .read_to_end(&mut archive_bytes)
        .map_err(|err| AppError::Internal(format!("could not read advisory archive: {err}")))?;
    if archive_bytes.len() as u64 > MAX_DOWNLOAD_BYTES {
        return Err(AppError::Internal(format!(
            "advisory archive is larger than the {} MiB limit",
            MAX_DOWNLOAD_BYTES / (1024 * 1024)
        )));
    }

    let (rows, record_count, package_count, skipped_records) = parse_archive(&archive_bytes)?;
    if rows.is_empty() {
        return Err(AppError::Internal(
            "advisory archive contained no usable Homebrew records".to_string(),
        ));
    }

    let fetched_at = now_rfc3339();
    let meta = vec![
        ("source".to_string(), SOURCE_NAME.to_string()),
        ("sourceUrl".to_string(), SOURCE_URL.to_string()),
        ("fetchedAt".to_string(), fetched_at.clone()),
        ("recordCount".to_string(), record_count.to_string()),
        ("packageCount".to_string(), package_count.to_string()),
        ("scope".to_string(), SCOPE.to_string()),
    ];
    db.replace_advisories(&rows, &meta)?;

    Ok(AdvisoryUpdate {
        source: SOURCE_NAME.to_string(),
        fetched_at,
        record_count,
        package_count,
        bytes: archive_bytes.len() as u64,
        skipped_records,
    })
}

pub fn report(db: &Db, apps: &[InstalledApp]) -> AppResult<AdvisoryReport> {
    let meta = db.advisory_meta()?;
    let fetched_at = meta.get("fetchedAt").cloned();
    let available = fetched_at.is_some();

    let mut packages = Vec::new();
    let mut skipped_packages = Vec::new();
    for app in apps.iter().filter(|app| app.source == "Homebrew") {
        match app.version.as_deref() {
            None => skipped_packages.push(format!("{}: no version reported", app.name)),
            Some(version) if version.split_whitespace().count() != 1 => skipped_packages.push(
                format!("{}: multiple installed versions ({version})", app.name),
            ),
            Some(version) => packages.push((app.name.clone(), version.to_string())),
        }
    }

    let mut report = AdvisoryReport {
        available,
        source: meta
            .get("source")
            .cloned()
            .unwrap_or_else(|| SOURCE_NAME.to_string()),
        fetched_at: fetched_at.clone(),
        record_count: meta
            .get("recordCount")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        package_count: meta
            .get("packageCount")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0),
        checked_packages: packages.len() as u32,
        skipped_packages,
        uncompared_packages: Vec::new(),
        unverified_records: 0,
        matches: Vec::new(),
        scope: SCOPE.to_string(),
    };

    if !available {
        return Ok(report);
    }

    let names: Vec<String> = packages.iter().map(|(name, _)| name.clone()).collect();
    let rows = db.advisories_for(&names)?;
    let mut uncompared = HashSet::new();
    let mut unverified_records = 0u32;
    let mut matches = Vec::new();

    for (name, installed) in &packages {
        let mut matched_ids = HashSet::new();
        for row in rows.iter().filter(|row| row.package == *name) {
            let introduced_ok = match row.introduced.as_deref() {
                None => true,
                Some("0") => true,
                Some(introduced) => match compare(installed, introduced) {
                    Ok(Cmp::Lt) => false,
                    Ok(_) => true,
                    Err(()) => {
                        uncompared.insert(name.clone());
                        continue;
                    }
                },
            };
            if !introduced_ok {
                continue;
            }

            let Some(fixed) = row.fixed.as_deref() else {
                unverified_records += 1;
                continue;
            };
            let ordering = match compare(installed, fixed) {
                Ok(Cmp::Lt) => true,
                Ok(_) => false,
                Err(()) => {
                    uncompared.insert(name.clone());
                    continue;
                }
            };
            if !ordering {
                continue;
            }

            // The feed's "fixed" boundary can be the version shipped when the
            // record was generated, not the revision that actually applied the
            // patch. Only claim applicability for same-upstream-version revision
            // patches, where the installed revision is demonstrably below the
            // recorded patch revision. Version-bump records are counted as
            // unverified instead of being presented as matches.
            if !row.boundary_verified {
                unverified_records += 1;
                continue;
            }
            let (installed_base, installed_revision) = split_homebrew_version(installed);
            let (fixed_base, fixed_revision) = split_homebrew_version(fixed);
            let revision_patch = row.fix_kind.as_deref() == Some("patch")
                && installed_base == fixed_base
                && installed_revision < fixed_revision;
            if !revision_patch {
                unverified_records += 1;
                continue;
            }
            if !matched_ids.insert(row.id.clone()) {
                continue;
            }

            matches.push(AdvisoryMatch {
                package: name.clone(),
                installed_version: installed.clone(),
                id: row.id.clone(),
                aliases: row.aliases.clone(),
                summary: row.summary.clone(),
                severity: row.severity.clone(),
                introduced: row.introduced.clone(),
                fixed: row.fixed.clone(),
                modified: row.modified.clone(),
                references: row.references.clone(),
            });
        }
    }

    matches.sort_by(|a, b| a.package.cmp(&b.package).then(a.id.cmp(&b.id)));
    let mut uncompared_packages: Vec<String> = uncompared.into_iter().collect();
    uncompared_packages.sort();

    report.uncompared_packages = uncompared_packages;
    report.unverified_records = unverified_records;
    report.matches = matches;
    Ok(report)
}

/// Query the official OSV API for supported Debian packages. Package names,
/// source versions, and the Debian release ecosystem are sent to OSV only when
/// the user explicitly requests this check in the UI.
pub fn check_debian_packages(apps: &[InstalledApp]) -> AppResult<AdvisoryReport> {
    let mut skipped_packages = Vec::new();
    let mut query_packages = std::collections::BTreeMap::<(String, String, String), ()>::new();

    for app in apps
        .iter()
        .filter(|app| app.source == "Debian packages (dpkg)")
    {
        let (Some(ecosystem), Some(name), Some(version)) = (
            app.advisory_ecosystem.as_deref(),
            app.advisory_name.as_deref(),
            app.advisory_version.as_deref(),
        ) else {
            skipped_packages.push(format!(
                "{}: Debian release or source version unavailable",
                app.name
            ));
            continue;
        };
        if !ecosystem.starts_with("Debian:")
            || !valid_osv_package_name(name)
            || !valid_osv_package_version(version)
        {
            skipped_packages.push(format!("{}: unsupported Debian package metadata", app.name));
            continue;
        }
        query_packages
            .entry((ecosystem.to_string(), name.to_string(), version.to_string()))
            .or_insert(());
    }

    let mut report = AdvisoryReport {
        available: false,
        source: "OSV.dev query API (Debian packages)".to_string(),
        fetched_at: None,
        record_count: 0,
        package_count: 0,
        checked_packages: 0,
        skipped_packages,
        uncompared_packages: Vec::new(),
        unverified_records: 0,
        matches: Vec::new(),
        scope: "Supported Debian releases only. This manual online check sends Debian source package names, source versions, and the release ecosystem to api.osv.dev. OSV.dev evaluates Debian version ranges; the package inventory and returned results are not stored by CyberGates. No result is not proof of safety.".to_string(),
    };
    if query_packages.is_empty() {
        return Ok(report);
    }
    if query_packages.len() > MAX_OSV_QUERY_PACKAGES {
        return Err(AppError::Validation(format!(
            "the Debian advisory check is limited to {MAX_OSV_QUERY_PACKAGES} distinct package versions"
        )));
    }

    let queries: Vec<OsvQueryPackage> = query_packages
        .into_keys()
        .map(|(ecosystem, name, version)| OsvQueryPackage {
            ecosystem,
            name,
            version,
        })
        .collect();
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent("CyberGates/0.1.0")
        .build()
        .map_err(|err| AppError::Internal(format!("could not create OSV client: {err}")))?;

    let vulnerabilities = query_osv_batch(&client, &queries)?;
    let mut matches = Vec::new();
    let mut record_ids = HashSet::new();
    for (query, records) in queries.iter().zip(vulnerabilities) {
        for record in records {
            if !valid_osv_id(&record.id) {
                continue;
            }
            record_ids.insert(record.id.clone());
            matches.push(AdvisoryMatch {
                package: query.name.clone(),
                installed_version: query.version.clone(),
                id: record.id.clone(),
                aliases: Vec::new(),
                summary: "OSV.dev matched this Debian source package and version. Open the advisory for details.".to_string(),
                severity: None,
                introduced: None,
                fixed: None,
                modified: record.modified.clone(),
                references: vec![format!("https://osv.dev/vulnerability/{}", record.id)],
            });
        }
    }
    matches.sort_by(|left, right| {
        left.package
            .cmp(&right.package)
            .then(left.id.cmp(&right.id))
            .then(left.installed_version.cmp(&right.installed_version))
    });
    matches.dedup_by(|left, right| {
        left.package == right.package
            && left.id == right.id
            && left.installed_version == right.installed_version
    });

    report.available = true;
    report.fetched_at = Some(now_rfc3339());
    report.record_count = record_ids.len() as u32;
    report.package_count = queries.len() as u32;
    report.checked_packages = queries.len() as u32;
    report.matches = matches;
    Ok(report)
}

#[derive(Debug, Clone)]
struct OsvQueryPackage {
    ecosystem: String,
    name: String,
    version: String,
}

#[derive(serde::Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<String>,
}

#[derive(serde::Serialize)]
struct OsvPackage {
    ecosystem: String,
    name: String,
}

#[derive(serde::Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQuery>,
}

#[derive(serde::Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvQueryResult>,
}

#[derive(serde::Deserialize)]
struct OsvQueryResult {
    vulns: Option<Vec<OsvVulnerabilityRef>>,
    next_page_token: Option<String>,
}

#[derive(serde::Deserialize)]
struct OsvVulnerabilityRef {
    id: String,
    modified: Option<String>,
}

fn query_osv_batch(
    client: &reqwest::blocking::Client,
    packages: &[OsvQueryPackage],
) -> AppResult<Vec<Vec<OsvVulnerabilityRef>>> {
    let mut all_results: Vec<Vec<OsvVulnerabilityRef>> =
        (0..packages.len()).map(|_| Vec::new()).collect();
    let mut pending: Vec<(usize, Option<String>)> =
        (0..packages.len()).map(|index| (index, None)).collect();
    let mut pages = 0;
    while !pending.is_empty() {
        pages += 1;
        if pages > MAX_OSV_PAGES {
            return Err(AppError::Internal(
                "OSV.dev returned too many result pages; the advisory check was not completed"
                    .to_string(),
            ));
        }
        let body = OsvBatchRequest {
            queries: pending
                .iter()
                .map(|(index, page_token)| OsvQuery {
                    package: OsvPackage {
                        ecosystem: packages[*index].ecosystem.clone(),
                        name: packages[*index].name.clone(),
                    },
                    version: packages[*index].version.clone(),
                    page_token: page_token.clone(),
                })
                .collect(),
        };
        let request_bytes = serde_json::to_vec(&body)
            .map_err(|err| AppError::Internal(format!("could not encode OSV request: {err}")))?;
        if request_bytes.len() > MAX_OSV_REQUEST_BYTES {
            return Err(AppError::Validation(
                "Debian advisory request exceeded the 4 MiB safety limit".to_string(),
            ));
        }
        let response = client
            .post(OSV_QUERYBATCH_URL)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(request_bytes)
            .send()
            .map_err(|err| AppError::Internal(format!("OSV.dev query failed: {err}")))?;
        if !response.status().is_success() {
            return Err(AppError::Internal(format!(
                "OSV.dev returned HTTP {}",
                response.status()
            )));
        }
        let mut bytes = Vec::new();
        response
            .take(MAX_OSV_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|err| AppError::Internal(format!("could not read OSV.dev response: {err}")))?;
        if bytes.len() as u64 > MAX_OSV_RESPONSE_BYTES {
            return Err(AppError::Internal(
                "OSV.dev response exceeded the 16 MiB safety limit".to_string(),
            ));
        }
        let response: OsvBatchResponse = serde_json::from_slice(&bytes)
            .map_err(|err| AppError::Internal(format!("invalid OSV.dev response: {err}")))?;
        if response.results.len() != pending.len() {
            return Err(AppError::Internal(
                "OSV.dev returned a mismatched result count; the advisory check was not completed"
                    .to_string(),
            ));
        }
        let mut next_pending = Vec::new();
        for ((index, _), result) in pending.into_iter().zip(response.results) {
            all_results[index].extend(result.vulns.unwrap_or_default());
            if let Some(token) = result.next_page_token {
                if token.len() > 4096 || token.chars().any(char::is_control) {
                    return Err(AppError::Internal(
                        "OSV.dev returned an invalid pagination token".to_string(),
                    ));
                }
                next_pending.push((index, Some(token)));
            }
        }
        pending = next_pending;
    }
    Ok(all_results)
}

fn valid_osv_package_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".+_-".contains(&byte))
}

fn valid_osv_package_version(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

fn valid_osv_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":_.-".contains(&byte))
}

fn parse_archive(bytes: &[u8]) -> AppResult<(Vec<AdvisoryRow>, u32, u32, u32)> {
    let decoder = flate2::read::GzDecoder::new(Cursor::new(bytes));
    let mut unpacked = Vec::new();
    decoder
        .take(MAX_UNPACKED_BYTES + 1)
        .read_to_end(&mut unpacked)
        .map_err(|err| {
            AppError::Internal(format!("could not decompress advisory archive: {err}"))
        })?;
    if unpacked.len() as u64 > MAX_UNPACKED_BYTES {
        return Err(AppError::Internal(format!(
            "advisory archive expands beyond the {} MiB limit",
            MAX_UNPACKED_BYTES / (1024 * 1024)
        )));
    }
    let mut archive = tar::Archive::new(Cursor::new(unpacked));
    let mut rows = Vec::new();
    let mut ids = HashSet::new();
    let mut packages = HashSet::new();
    let mut skipped = 0u32;

    let entries = archive
        .entries()
        .map_err(|err| AppError::Internal(format!("invalid advisory archive: {err}")))?;
    for entry in entries {
        let mut entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        let path = match entry.path() {
            Ok(path) => path.to_string_lossy().to_string(),
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        if !path.contains("/advisories/") || !path.ends_with(".json") {
            continue;
        }
        if entry.header().size().unwrap_or(0) > MAX_RECORD_BYTES {
            let _ = std::io::copy(&mut entry, &mut std::io::sink());
            skipped += 1;
            continue;
        }

        let mut text = String::new();
        if entry
            .by_ref()
            .take(MAX_RECORD_BYTES + 1)
            .read_to_string(&mut text)
            .is_err()
        {
            let _ = std::io::copy(&mut entry, &mut std::io::sink());
            skipped += 1;
            continue;
        }
        if text.len() as u64 > MAX_RECORD_BYTES {
            let _ = std::io::copy(&mut entry, &mut std::io::sink());
            skipped += 1;
            continue;
        }

        match parse_record(&text) {
            Some(record) => {
                if record.rows.is_empty() {
                    skipped += 1;
                    continue;
                }
                ids.insert(record.id);
                for row in &record.rows {
                    packages.insert(row.package.clone());
                }
                rows.extend(record.rows);
            }
            None => skipped += 1,
        }
    }

    Ok((rows, ids.len() as u32, packages.len() as u32, skipped))
}

struct ParsedRecord {
    id: String,
    rows: Vec<AdvisoryRow>,
}

fn parse_record(text: &str) -> Option<ParsedRecord> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let id = value.get("id")?.as_str()?.to_string();
    let summary = value
        .get("summary")
        .and_then(|value| value.as_str())
        .unwrap_or("(no summary provided)")
        .to_string();
    let modified = value
        .get("modified")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let aliases = string_array(value.get("upstream").or_else(|| value.get("aliases")));
    let severity = value
        .get("severity")
        .and_then(|value| value.as_array())
        .and_then(|array| array.first())
        .and_then(|entry| entry.get("score"))
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let references: Vec<String> = value
        .get("references")
        .and_then(|value| value.as_array())
        .map(|array| {
            array
                .iter()
                .filter_map(|entry| entry.get("url").and_then(|value| value.as_str()))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    // Homebrew documents generated fixed boundaries as the version currently
    // shipped, which is only an upper bound until reviewed against history.
    let boundary_verified = value
        .get("database_specific")
        .and_then(|value| value.get("source"))
        .and_then(|value| value.as_str())
        != Some("generated");

    let mut rows = Vec::new();
    for affected in value.get("affected")?.as_array()? {
        let package = affected.get("package")?;
        if package.get("ecosystem").and_then(|value| value.as_str()) != Some("Homebrew") {
            continue;
        }
        let name = package
            .get("name")
            .and_then(|value| value.as_str())?
            .to_string();
        let fix_kind = affected
            .get("ecosystem_specific")
            .and_then(|value| value.get("fix"))
            .and_then(|value| value.as_str())
            .map(str::to_string);
        let ranges = affected
            .get("ranges")
            .and_then(|value| value.as_array())
            .cloned()
            .unwrap_or_default();
        for range in ranges {
            let events = range
                .get("events")
                .and_then(|value| value.as_array())
                .cloned()
                .unwrap_or_default();
            let mut introduced: Option<String> = None;
            for event in events {
                if let Some(value) = event.get("introduced").and_then(|value| value.as_str()) {
                    introduced = Some(value.to_string());
                }
                if let Some(value) = event.get("fixed").and_then(|value| value.as_str()) {
                    rows.push(AdvisoryRow {
                        id: id.clone(),
                        package: name.clone(),
                        introduced: introduced.clone(),
                        fixed: Some(value.to_string()),
                        fix_kind: fix_kind.clone(),
                        boundary_verified,
                        summary: summary.clone(),
                        severity: severity.clone(),
                        aliases: aliases.clone(),
                        references: references.clone(),
                        modified: modified.clone(),
                    });
                    introduced = None;
                }
            }
            if let Some(introduced) = introduced {
                rows.push(AdvisoryRow {
                    id: id.clone(),
                    package: name.clone(),
                    introduced: Some(introduced),
                    fixed: None,
                    fix_kind: fix_kind.clone(),
                    boundary_verified,
                    summary: summary.clone(),
                    severity: severity.clone(),
                    aliases: aliases.clone(),
                    references: references.clone(),
                    modified: modified.clone(),
                });
            }
        }
    }

    Some(ParsedRecord { id, rows })
}

fn split_homebrew_version(version: &str) -> (&str, u32) {
    match version.rsplit_once('_') {
        Some((base, revision)) if revision.chars().all(|c| c.is_ascii_digit()) => {
            (base, revision.parse().unwrap_or(0))
        }
        _ => (version, 0),
    }
}

fn string_array(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(|value| value.as_array())
        .map(|array| {
            array
                .iter()
                .filter_map(|value| value.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_osv_record_into_ranges() {
        let json = r#"{
          "id": "BREW-example-CVE-2026-1",
          "modified": "2026-10-20T08:59:43Z",
          "upstream": ["CVE-2026-1"],
          "summary": "Example vulnerability",
          "severity": [{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
          "references": [{"type":"WEB","url":"https://example.test/advisory"}],
          "affected": [{
            "package": {"ecosystem":"Homebrew","name":"example"},
            "ecosystem_specific": {"fix":"patch"},
            "ranges": [{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"fixed":"1.2_1"}]}]
          }]
        }"#;
        let record = parse_record(json).expect("record");
        assert_eq!(record.id, "BREW-example-CVE-2026-1");
        assert_eq!(record.rows.len(), 1);
        assert_eq!(record.rows[0].package, "example");
        assert_eq!(record.rows[0].introduced.as_deref(), Some("1.0"));
        assert_eq!(record.rows[0].fixed.as_deref(), Some("1.2_1"));
        assert_eq!(record.rows[0].fix_kind.as_deref(), Some("patch"));
        assert_eq!(record.rows[0].aliases, vec!["CVE-2026-1"]);
        assert_eq!(record.rows[0].references.len(), 1);
        assert!(record.rows[0].boundary_verified);
    }

    #[test]
    fn generated_homebrew_fixed_boundary_is_unverified() {
        let json = r#"{
          "id":"BREW-example-CVE-2026-3",
          "database_specific":{"source":"generated"},
          "affected":[{
            "package":{"ecosystem":"Homebrew","name":"example"},
            "ecosystem_specific":{"fix":"patch"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2_1"}]}]
          }]
        }"#;
        let record = parse_record(json).expect("record");
        assert_eq!(record.rows.len(), 1);
        assert!(!record.rows[0].boundary_verified);
    }

    #[test]
    fn splits_homebrew_revisions() {
        assert_eq!(split_homebrew_version("1.11.1_3"), ("1.11.1", 3));
        assert_eq!(split_homebrew_version("2026.1.29"), ("2026.1.29", 0));
        assert_eq!(split_homebrew_version("1.2.3_beta"), ("1.2.3_beta", 0));
    }

    #[test]
    fn homebrew_versions_compare_with_revisions() {
        assert_eq!(compare("1.81.6_5", "1.81.6_6"), Ok(Cmp::Lt));
        assert_eq!(compare("1.81.6_6", "1.82.0"), Ok(Cmp::Lt));
        assert_eq!(compare("2026.1.29", "2026.2.23"), Ok(Cmp::Lt));
    }

    #[test]
    #[ignore = "downloads the live Homebrew advisory database"]
    fn live_advisory_update_and_report() {
        let path =
            std::env::temp_dir().join(format!("cybergates-advisories-{}.db", uuid::Uuid::new_v4()));
        let db = Db::open(&path).expect("open db");
        let update = update(&db).expect("update advisories");
        assert!(update.record_count > 1000, "unexpectedly small feed");
        assert!(update.package_count > 100);

        let adapter = crate::platform::adapter();
        let apps = adapter.installed_apps().expect("installed apps");
        let report = report(&db, &apps).expect("advisory report");
        assert!(report.available);
        assert_eq!(report.record_count, update.record_count);
        println!(
            "records={} packages={} checked={} matches={} unverified={} skipped={}",
            report.record_count,
            report.package_count,
            report.checked_packages,
            report.matches.len(),
            report.unverified_records,
            report.skipped_packages.len()
        );
        for item in report.matches.iter().take(8) {
            println!(
                "{} {} -> {} (fixed {})",
                item.package,
                item.installed_version,
                item.id,
                item.fixed.as_deref().unwrap_or("open")
            );
        }

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn ignores_non_homebrew_affected_entries() {
        let json = r#"{
          "id":"BREW-example-CVE-2026-2",
          "affected":[{"package":{"ecosystem":"npm","name":"example"},"ranges":[{"events":[{"introduced":"0"}]}]}]
        }"#;
        let record = parse_record(json).expect("record");
        assert!(record.rows.is_empty());
    }
}
