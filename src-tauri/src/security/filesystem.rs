use std::fs::{self, OpenOptions};
use std::io;
use std::path::Path;

/// Create a private local-data directory and reject a symlink at its boundary.
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private data directory must be a real directory, not a symlink",
        ));
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Ensure a private regular file exists before a database or report writer opens it.
/// `create_new` prevents following a preexisting symlink for new files.
pub fn prepare_private_file(path: &Path) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    match options.open(path) {
        Ok(file) => drop(file),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "private data file must be a regular file, not a symlink",
                ));
            }
            #[cfg(unix)]
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Err(error) => return Err(error),
    }
    Ok(())
}

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_dir() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("cybergates-permissions-{nonce}"))
    }

    #[test]
    fn private_directory_and_file_permissions_are_restricted() {
        let dir = test_dir();
        ensure_private_dir(&dir).unwrap();
        let file = dir.join("data.db");
        prepare_private_file(&file).unwrap();

        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_file_helper_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = test_dir();
        ensure_private_dir(&dir).unwrap();
        let target = dir.join("target");
        let link = dir.join("linked.db");
        fs::write(&target, "contents").unwrap();
        symlink(&target, &link).unwrap();
        assert!(prepare_private_file(&link).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
