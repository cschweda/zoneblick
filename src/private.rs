//! Files only their owner may read: the database and the API token.
//!
//! On Unix that is the file mode, set as the file is made. Windows has
//! no mode: a new file takes the permissions of its directory, which
//! often let other users of the machine read it. Narrowing them after
//! the file exists leaves a moment in which another user can open the
//! file and keep it open. So there the file is made inside a new
//! directory that is already limited to the current user, and only then
//! moved into place.

use std::io::Write;
use std::path::Path;

/// Make a new file with these contents that only the current user may
/// read or write. Fails when the file already exists, and, on Windows,
/// when its permissions cannot be limited: the contents are then never
/// written where others could read them.
pub fn write_new(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents)
    }
    #[cfg(windows)]
    {
        if path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "the file already exists",
            ));
        }
        let name = path
            .file_name()
            .ok_or_else(|| std::io::Error::other("the path names no file"))?;
        // A directory of our own making, beside the file so that the move
        // stays on one volume. `create_dir` fails if it is already there,
        // so nobody else can have made it for us.
        let mut dir_name = name.to_owned();
        dir_name.push(format!(".new-{}", std::process::id()));
        let dir = path.with_file_name(dir_name);
        std::fs::create_dir(&dir)?;
        let made = (|| {
            windows::limit(&dir, true)?;
            // Made here, the file has the directory's permissions from
            // its first moment.
            let inside = dir.join(name);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&inside)?;
            file.write_all(contents)?;
            file.sync_all()?;
            drop(file);
            // Give the file permissions of its own, so that it keeps them
            // in its new place, then move it there.
            windows::limit(&inside, false)?;
            std::fs::rename(&inside, path)
        })();
        let _ = std::fs::remove_dir_all(&dir);
        made
    }
    #[cfg(not(any(unix, windows)))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(contents)
    }
}

/// Limit an existing file to the current user. For a file that an older
/// version may have made with wider permissions; whoever opened it before
/// this keeps that access.
pub fn restrict(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(windows)]
    {
        windows::limit(path, false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(windows)]
mod windows {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    /// The system's own tools by full path, not whatever is first on PATH.
    fn tool(name: &str) -> PathBuf {
        std::env::var_os("SystemRoot")
            .map(|root| Path::new(&root).join("System32"))
            .unwrap_or_default()
            .join(name)
    }

    /// Replace what the directory hands down with a grant for the current
    /// user, and take away any grant to everyone, to signed-in users and
    /// to the Users group. The system account and administrators, who can
    /// read any file anyway, may keep theirs.
    pub fn limit(path: &Path, directory: bool) -> std::io::Result<()> {
        let who = Command::new(tool("whoami.exe"))
            .stdin(Stdio::null())
            .output()?;
        let user = String::from_utf8_lossy(&who.stdout).trim().to_string();
        if !who.status.success() || user.is_empty() {
            return Err(std::io::Error::other(
                "whoami did not name the current user",
            ));
        }
        // For a directory, the grant also covers what is made inside it.
        let grant = if directory {
            format!("{user}:(OI)(CI)F")
        } else {
            format!("{user}:F")
        };
        let status = Command::new(tool("icacls.exe"))
            .arg(path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(grant)
            .arg("/remove:g")
            .arg("*S-1-1-0")
            .arg("*S-1-5-11")
            .arg("*S-1-5-32-545")
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

    /// The permissions of a file as `icacls` lists them, for tests.
    #[cfg(test)]
    pub fn listing(path: &Path) -> String {
        let out = Command::new(tool("icacls.exe")).arg(path).output().unwrap();
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    /// Let the Users group read a directory and all that is made in it,
    /// as many data directories do. For tests.
    #[cfg(test)]
    pub fn open_to_users(dir: &Path) {
        let status = Command::new(tool("icacls.exe"))
            .arg(dir)
            .arg("/grant")
            .arg("*S-1-5-32-545:(OI)(CI)R")
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("zoneblick-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(windows)]
        windows::open_to_users(&dir);
        dir
    }

    /// Only the owner, and on Windows the accounts that can read any
    /// file, may have access.
    fn assert_private(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        #[cfg(windows)]
        {
            let listing = windows::listing(path);
            assert!(!listing.contains("(I)"), "inherited entry left: {listing}");
            for broad in ["Users", "Everyone"] {
                assert!(!listing.contains(broad), "{broad} has access: {listing}");
            }
        }
        #[cfg(not(any(unix, windows)))]
        let _ = path;
    }

    #[test]
    fn a_new_file_is_for_its_owner_only() {
        let dir = scratch("private-new");
        let path = dir.join("secret");
        write_new(&path, b"token\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "token\n");
        assert_private(&path);
        // It never replaces a file that is already there.
        assert!(write_new(&path, b"other").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "token\n");
        // Nothing is left beside it.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_existing_file_can_be_narrowed() {
        let dir = scratch("private-old");
        let path = dir.join("secret");
        std::fs::write(&path, "x").unwrap();
        #[cfg(windows)]
        assert!(windows::listing(&path).contains("Users"));
        restrict(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "x");
        assert_private(&path);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
