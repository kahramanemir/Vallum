//! Private (`0600`) append-file helper shared by the audit and stats writers.

use std::fs::{File, OpenOptions};
use std::path::Path;

/// Open a file for append, creating it with owner-only (0600) permissions on unix.
/// `.mode()` only affects newly created files, so existing files keep their perms.
#[cfg(unix)]
pub fn open_append_private(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
pub fn open_append_private(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// Open read+write (create 0600 on unix, no truncate) — for small state
/// files that are rewritten in place under a lock.
#[cfg(unix)]
pub fn open_rw_private(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
pub fn open_rw_private(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

/// Take an exclusive advisory lock (`flock(LOCK_EX)`) on an open file. Blocks
/// until acquired; released when the file is dropped. No-op on non-unix.
#[cfg(unix)]
pub(crate) fn lock_exclusive(file: &File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn lock_exclusive(_file: &File) -> std::io::Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn creates_file_with_0600() {
        let dir = std::env::temp_dir().join(format!(
            "vallum_fsutil_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("f.log");
        let _ = open_append_private(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rw_private_creates_file_with_0600() {
        let dir = std::env::temp_dir().join(format!(
            "vallum_fsutil_rw_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.state");
        let _ = open_rw_private(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
