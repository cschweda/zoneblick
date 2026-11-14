//! Files only their owner may read: the database and the API token.
//!
//! On Unix that is the file mode, set where the file is made. Windows has
//! no mode: a new file takes the permissions of its directory, which
//! often let other users of the machine read it. There the file's
//! inherited permissions are replaced with one entry for the current user.

use std::path::Path;

/// Make an existing file readable and writable by the current user only.
/// On Unix this sets mode 0600. On Windows it runs `icacls`, which is
/// part of the system.
pub fn restrict(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(windows)]
    {
        use std::process::{Command, Stdio};
        // Run the system's own tools by full path, not whatever is first
        // on PATH.
        let system = std::env::var_os("SystemRoot")
            .map(|root| Path::new(&root).join("System32"))
            .unwrap_or_default();
        let who = Command::new(system.join("whoami.exe"))
            .stdin(Stdio::null())
            .output()?;
        let user = String::from_utf8_lossy(&who.stdout).trim().to_string();
        if !who.status.success() || user.is_empty() {
            return Err(std::io::Error::other(
                "whoami did not name the current user",
            ));
        }
        // Drop what the directory hands down, then grant this user alone.
        let status = Command::new(system.join("icacls.exe"))
            .arg(path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(format!("{user}:F"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(
                "icacls could not set the permissions",
            ))
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_restricted_file_is_for_its_owner_only() {
        let dir = std::env::temp_dir().join(format!("zoneblick-private-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret");
        std::fs::write(&path, "x").unwrap();
        restrict(&path).unwrap();
        // The owner can still read it.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "x");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        #[cfg(windows)]
        {
            let system = std::env::var_os("SystemRoot")
                .map(|root| Path::new(&root).join("System32"))
                .unwrap_or_default();
            let out = std::process::Command::new(system.join("icacls.exe"))
                .arg(&path)
                .output()
                .unwrap();
            let listing = String::from_utf8_lossy(&out.stdout).to_string();
            // Nothing inherited from the directory is left, and exactly
            // one entry remains.
            assert!(!listing.contains("(I)"), "{listing}");
            let entries = listing.lines().filter(|l| l.contains(":(")).count();
            assert_eq!(entries, 1, "{listing}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
