use std::path::{Component, Path, PathBuf};

use crate::error::{AppError, AppResult};

pub const MAX_TEXT_LEN: usize = 256;

pub fn bounded_text(value: &str, field: &str, max_len: usize) -> AppResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AppError::Validation(format!("{field} must not be empty")));
    }
    if trimmed.len() > max_len {
        return Err(AppError::Validation(format!(
            "{field} exceeds the maximum length of {max_len}"
        )));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(AppError::Validation(format!(
            "{field} contains control characters"
        )));
    }
    Ok(trimmed.to_string())
}

pub fn setting_key(key: &str) -> AppResult<&str> {
    const ALLOWED: &[&str] = &[
        "theme",
        "telemetry",
        "notifications",
        "retentionDays",
        "aiEnabled",
        "aiProvider",
        "lastAuditId",
    ];
    let value = bounded_text(key, "setting key", MAX_TEXT_LEN)?;
    if !ALLOWED.contains(&value.as_str()) {
        return Err(AppError::Validation(format!(
            "unknown setting key: {value}"
        )));
    }
    Ok(key)
}

pub fn report_format(format: &str) -> AppResult<&str> {
    match format {
        "json" | "html" => Ok(format),
        _ => Err(AppError::Validation(
            "report format must be 'json' or 'html'".to_string(),
        )),
    }
}

/// Ensure a path is absolute, contains no traversal components, and does not
/// resolve through a symlink. Used before any future file operation.
pub fn safe_absolute_path(path: &str) -> AppResult<PathBuf> {
    let value = bounded_text(path, "path", 4096)?;
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(AppError::Validation("path must be absolute".to_string()));
    }
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(AppError::Validation(
            "path must not contain '.' or '..' components".to_string(),
        ));
    }
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(AppError::Validation(
            "refusing to operate on a symlink".to_string(),
        )),
        Ok(_) => Ok(path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(path),
        Err(err) => Err(AppError::Io(err)),
    }
}

pub fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn sanitize_for_log(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(512)
        .collect()
}

pub fn validate_url(value: &str) -> AppResult<()> {
    let value = bounded_text(value, "url", 2048)?;
    if !(value.starts_with("https://") || value.starts_with("http://")) {
        return Err(AppError::Validation(
            "only http(s) URLs are allowed".to_string(),
        ));
    }
    if value.contains('@') && value.split("://").nth(1).unwrap_or("").contains('@') {
        return Err(AppError::Validation(
            "credentials in URLs are not allowed".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal() {
        assert!(safe_absolute_path("/tmp/../etc/passwd").is_err());
        assert!(safe_absolute_path("relative/path").is_err());
    }

    #[test]
    fn accepts_normal_absolute_path() {
        assert!(safe_absolute_path("/tmp/cybergates-does-not-exist").is_ok());
    }

    #[test]
    fn validates_settings_allowlist() {
        assert!(setting_key("theme").is_ok());
        assert!(setting_key("rm -rf").is_err());
    }

    #[test]
    fn escapes_html() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
    }
}
