use std::path::{Component, PathBuf};

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

pub fn setting_key(key: &str) -> AppResult<String> {
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
    Ok(value)
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
/// resolve through an existing symlink component. This is validation only;
/// callers opening attacker-writable paths still need race-safe OS APIs.
#[allow(dead_code)]
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
    let components: Vec<_> = path.components().collect();
    let mut current = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(AppError::Validation(
                    "refusing to operate through a symlink".to_string(),
                ));
            }
            Ok(meta) if index + 1 < components.len() && !meta.is_dir() => {
                return Err(AppError::Validation(
                    "parent path components must be directories".to_string(),
                ));
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(AppError::Io(err)),
        }
    }
    Ok(path)
}

pub fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[allow(dead_code)]
pub fn sanitize_for_log(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(512)
        .collect()
}

#[allow(dead_code)]
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
        let temp = std::env::temp_dir().canonicalize().unwrap();
        let missing = temp.join("cybergates-does-not-exist");
        assert!(safe_absolute_path(missing.to_str().unwrap()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_parent_components() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("cybergates-path-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let target = root.join("target");
        let link = root.join("link");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();

        let path = link.join("child");
        assert!(safe_absolute_path(path.to_str().unwrap()).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn validates_settings_allowlist() {
        assert!(setting_key("theme").is_ok());
        assert!(setting_key("rm -rf").is_err());
        assert_eq!(setting_key("theme ").unwrap(), "theme");
    }

    #[test]
    fn escapes_html() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
    }
}
