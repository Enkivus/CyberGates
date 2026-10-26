use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::time::SystemTime;

use crate::models::{now_rfc3339, ApplicationLogSnapshot};

const LOG_PREFIX: &str = "cybergates.log.";
const MAX_LOG_FILES: usize = 7;
const MAX_LOG_FILE_BYTES: u64 = 1024 * 1024;
const MAX_LOG_LINES: usize = 500;
const MAX_LOG_LINE_BYTES: usize = 4096;

pub fn read_application_logs(log_dir: &Path, limit: usize) -> ApplicationLogSnapshot {
    let limit = limit.clamp(1, MAX_LOG_LINES);
    let mut warnings = Vec::new();
    if !fs::symlink_metadata(log_dir)
        .map(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return ApplicationLogSnapshot {
            available: false,
            lines: Vec::new(),
            fetched_at: now_rfc3339(),
            warnings: vec!["CyberGates application logs could not be read.".to_string()],
        };
    }
    let mut files = match fs::read_dir(log_dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let path = entry.path();
                let file_name = path.file_name()?.to_str()?;
                if !file_name.starts_with(LOG_PREFIX) {
                    return None;
                }
                let metadata = fs::symlink_metadata(&path).ok()?;
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return None;
                }
                Some((path, metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH)))
            })
            .collect::<Vec<_>>(),
        Err(_) => {
            return ApplicationLogSnapshot {
                available: false,
                lines: Vec::new(),
                fetched_at: now_rfc3339(),
                warnings: vec!["CyberGates application logs could not be read.".to_string()],
            };
        }
    };

    files.sort_by_key(|file| file.1);
    if files.len() > MAX_LOG_FILES {
        files.drain(..files.len() - MAX_LOG_FILES);
        warnings.push(format!(
            "Only the {MAX_LOG_FILES} most recently modified log files are included."
        ));
    }

    let mut lines = Vec::new();
    for (path, _) in files {
        match read_log_tail(&path) {
            Ok(file_lines) => lines.extend(file_lines),
            Err(_) => warnings.push("A CyberGates log file could not be read safely.".to_string()),
        }
    }
    if lines.len() > limit {
        lines.drain(..lines.len() - limit);
    }

    ApplicationLogSnapshot {
        available: true,
        lines,
        fetched_at: now_rfc3339(),
        warnings,
    }
}

fn open_log_file(path: &Path) -> std::io::Result<File> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "log path is not a regular file",
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "opened log target is not a regular file",
        ));
    }
    Ok(file)
}

fn read_log_tail(path: &Path) -> std::io::Result<Vec<String>> {
    let mut file = open_log_file(path)?;
    let size = file.metadata()?.len();
    let start = size.saturating_sub(MAX_LOG_FILE_BYTES);
    file.seek(SeekFrom::Start(start))?;

    let mut bytes = Vec::with_capacity(MAX_LOG_FILE_BYTES as usize);
    file.take(MAX_LOG_FILE_BYTES).read_to_end(&mut bytes)?;
    if start > 0 {
        if let Some(newline) = bytes.iter().position(|byte| *byte == b'\n') {
            bytes.drain(..=newline);
        } else {
            return Ok(Vec::new());
        }
    }

    Ok(bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            let clipped = &line[..line.len().min(MAX_LOG_LINE_BYTES)];
            String::from_utf8_lossy(clipped)
                .chars()
                .map(|character| {
                    if character.is_control() && character != '\t' {
                        '\u{fffd}'
                    } else {
                        character
                    }
                })
                .collect()
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_dir() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("cybergates-app-logs-{nonce}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn reads_only_recent_cybergates_log_files_and_applies_line_limit() {
        let dir = test_dir();
        fs::write(dir.join("cybergates.log.2026-01-01"), "old\n").unwrap();
        fs::write(dir.join("cybergates.log.2026-01-02"), "new-one\nnew-two\n").unwrap();
        fs::write(dir.join("unrelated.log"), "private unrelated data\n").unwrap();

        let snapshot = read_application_logs(&dir, 2);
        assert!(snapshot.available);
        assert_eq!(snapshot.lines, ["new-one", "new-two"]);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn clips_long_lines_and_replaces_control_characters() {
        let dir = test_dir();
        let mut line = "x".repeat(MAX_LOG_LINE_BYTES + 10);
        line.push('\u{1b}');
        fs::write(dir.join("cybergates.log.2026-01-01"), format!("{line}\n")).unwrap();

        let snapshot = read_application_logs(&dir, MAX_LOG_LINES + 5);
        assert_eq!(snapshot.lines.len(), 1);
        assert_eq!(snapshot.lines[0].len(), MAX_LOG_LINE_BYTES);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn ignores_symlinked_log_files() {
        use std::os::unix::fs::symlink;

        let dir = test_dir();
        let target = dir.join("target.txt");
        fs::write(&target, "do not expose\n").unwrap();
        symlink(&target, dir.join("cybergates.log.2026-01-01")).unwrap();

        let snapshot = read_application_logs(&dir, 10);
        assert!(snapshot.lines.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlinked_log_directory() {
        use std::os::unix::fs::symlink;

        let dir = test_dir();
        let outside = test_dir();
        fs::write(outside.join("cybergates.log.2026-01-01"), "outside\n").unwrap();
        let link = dir.join("linked-logs");
        symlink(&outside, &link).unwrap();

        let snapshot = read_application_logs(&link, 10);
        assert!(!snapshot.available);
        assert!(snapshot.lines.is_empty());
        fs::remove_dir_all(dir).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn unavailable_log_directory_returns_a_safe_message() {
        let snapshot = read_application_logs(Path::new("/path/that/does/not/exist"), 10);
        assert!(!snapshot.available);
        assert!(snapshot.lines.is_empty());
        assert_eq!(
            snapshot.warnings,
            ["CyberGates application logs could not be read."]
        );
    }
}
