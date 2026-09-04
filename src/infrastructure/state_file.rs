//! Private, crash-durable file publication for local `FWDeck` state.
//!
//! Writers create and fsync a process-unique temporary file in the destination
//! directory before publishing it. Unique files use a hard link for atomic
//! no-replace semantics, so readers never observe an empty reservation.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Creates `dir` and clamps it to `0700` on Unix.
pub(crate) fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)
}

/// Atomically replaces `path` with private, fully synced contents.
pub(crate) fn write_private_atomic_replace(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
    })?;
    let temp = write_private_temp(dir, bytes)?;
    std::fs::rename(temp.path(), path)?;
    temp.disarm();
    sync_dir(dir)
}

/// Atomically publishes `path` without replacing an existing file.
pub(crate) fn write_private_atomic_create(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
    })?;
    let temp = write_private_temp(dir, bytes)?;
    std::fs::hard_link(temp.path(), path)?;
    temp.remove()?;
    sync_dir(dir)
}

/// Publishes a new private file without overwriting an existing candidate.
///
/// `candidate` receives a collision counter. Publication uses `link(2)`, so
/// the final path appears only after all bytes and metadata have been synced.
pub(crate) fn write_private_atomic_unique(
    dir: &Path,
    bytes: &[u8],
    mut candidate: impl FnMut(u32) -> PathBuf,
) -> std::io::Result<PathBuf> {
    let temp = write_private_temp(dir, bytes)?;
    let mut collision = 0u32;
    loop {
        let path = candidate(collision);
        match std::fs::hard_link(temp.path(), &path) {
            Ok(()) => {
                let cleanup = temp.remove();
                let sync = sync_dir(dir);
                cleanup?;
                sync?;
                return Ok(path);
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                collision = collision.checked_add(1).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "unique state-file name space exhausted",
                    )
                })?;
            }
            Err(err) => return Err(err),
        }
    }
}

/// Atomically moves an existing file to a unique destination without replace.
///
/// The source remains available until its completed inode has been linked at
/// the destination. A crash between link and unlink can leave a duplicate but
/// never loses the data.
pub(crate) fn move_atomic_unique(
    source: &Path,
    mut candidate: impl FnMut(u32) -> PathBuf,
) -> std::io::Result<PathBuf> {
    let dir = source.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "source has no parent")
    })?;
    let mut collision = 0u32;
    loop {
        let path = candidate(collision);
        match std::fs::hard_link(source, &path) {
            Ok(()) => {
                std::fs::remove_file(source)?;
                sync_dir(dir)?;
                return Ok(path);
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                collision = collision.checked_add(1).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "unique state-file name space exhausted",
                    )
                })?;
            }
            Err(err) => return Err(err),
        }
    }
}

fn write_private_temp(dir: &Path, bytes: &[u8]) -> std::io::Result<TempPath> {
    loop {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!(".fwdeck-{}-{sequence}.tmp", std::process::id()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                let temp = TempPath::new(path);
                file.write_all(bytes)?;
                file.sync_all()?;
                drop(file);
                return Ok(temp);
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err),
        }
    }
}

#[cfg(unix)]
pub(crate) fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
pub(crate) fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

struct TempPath {
    path: PathBuf,
    armed: bool,
}

impl TempPath {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(mut self) {
        self.armed = false;
    }

    fn remove(mut self) -> std::io::Result<()> {
        std::fs::remove_file(&self.path)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fwdeck-state-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        create_private_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn atomic_replace_is_exact_private_and_leaves_no_temp() {
        let dir = scratch("replace");
        let path = dir.join("export.json");
        write_private_atomic_replace(&path, b"old").unwrap();
        write_private_atomic_replace(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(dir_mode & 0o777, 0o700);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn existing_directory_permissions_are_clamped_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = scratch("directory-mode");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        create_private_dir(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unique_publish_never_exposes_a_placeholder() {
        let dir = scratch("unique");
        let candidate = |collision| dir.join(format!("snapshot-1-{collision}.json"));
        let first = write_private_atomic_unique(&dir, b"first", candidate).unwrap();
        let second = write_private_atomic_unique(&dir, b"second", candidate).unwrap();
        assert_ne!(first, second);
        assert_eq!(std::fs::read(first).unwrap(), b"first");
        assert_eq!(std::fs::read(second).unwrap(), b"second");
        assert!(std::fs::read_dir(&dir).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".fwdeck-")
        }));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn concurrent_unique_publishers_never_clobber_each_other() {
        let dir = scratch("concurrent");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let publish = |contents: &'static [u8]| {
            let dir = dir.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                write_private_atomic_unique(&dir, contents, |collision| {
                    dir.join(format!("snapshot-1-{collision}.json"))
                })
                .unwrap()
            })
        };
        let first = publish(b"first");
        let second = publish(b"second");
        barrier.wait();
        let first = first.join().unwrap();
        let second = second.join().unwrap();
        assert_ne!(first, second);
        let mut contents = vec![
            std::fs::read(first).unwrap(),
            std::fs::read(second).unwrap(),
        ];
        contents.sort();
        assert_eq!(contents, vec![b"first".to_vec(), b"second".to_vec()]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_publish_cleans_up_the_temporary_file() {
        let dir = scratch("failure");
        let missing = dir.join("missing");
        let result = write_private_atomic_unique(&dir, b"data", |_| missing.join("state.json"));
        assert!(result.is_err());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unique_move_preserves_contents_and_never_replaces() {
        let dir = scratch("move");
        let source = dir.join("audit.jsonl");
        std::fs::write(&source, "audit").unwrap();
        std::fs::write(dir.join("audit-1.jsonl"), "existing").unwrap();
        let moved = move_atomic_unique(&source, |collision| {
            dir.join(format!("audit-{}.jsonl", collision + 1))
        })
        .unwrap();
        assert_eq!(moved, dir.join("audit-2.jsonl"));
        assert!(!source.exists());
        assert_eq!(std::fs::read_to_string(moved).unwrap(), "audit");
        assert_eq!(
            std::fs::read_to_string(dir.join("audit-1.jsonl")).unwrap(),
            "existing"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
