use super::*;
use crate::domain::{TrafficSuiteId, TrafficSuiteRevision};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);
struct Root(std::path::PathBuf);
impl Root {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "fwdeck-default-adapter-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        )))
    }
    fn adapter(&self) -> DefaultTrafficSuiteStorage {
        DefaultTrafficSuiteStorage::new(&self.0)
    }
    fn path(&self) -> std::path::PathBuf {
        self.0.join("traffic-tests/default.toml")
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn suite() -> TrafficSuite {
    TrafficSuite {
        id: TrafficSuiteId::parse("default").unwrap(),
        name: "Default".into(),
        revision: TrafficSuiteRevision::new(1).unwrap(),
        scenarios: vec![],
    }
}
fn expectation(
    loaded: LoadedTrafficSuite<TrafficSuiteFingerprint>,
) -> TrafficSaveExpectation<TrafficSuiteFingerprint> {
    match loaded {
        LoadedTrafficSuite::Available { suite, fingerprint } => TrafficSaveExpectation::Existing {
            revision: suite.revision,
            fingerprint,
        },
        _ => panic!("expected available"),
    }
}

#[test]
fn missing_load_is_inert_and_create_reload_is_private() {
    let root = Root::new();
    let adapter = root.adapter();
    assert!(matches!(
        adapter.load_default().unwrap(),
        LoadedTrafficSuite::Missing
    ));
    assert!(!root.0.exists());
    adapter
        .save_default(&suite(), TrafficSaveExpectation::Missing)
        .unwrap();
    let LoadedTrafficSuite::Available { suite: loaded, .. } = adapter.load_default().unwrap()
    else {
        panic!("missing")
    };
    assert_eq!(*loaded, suite());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(root.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(root.path().parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}

#[test]
fn malformed_and_future_content_are_preserved() {
    let root = Root::new();
    let adapter = root.adapter();
    let expected = expectation(
        adapter
            .save_default(&suite(), TrafficSaveExpectation::Missing)
            .unwrap(),
    );
    for (bytes, future) in [
        ("schema_version = 1\nname = [", false),
        ("schema_version = 999\nid = 'default'\n", true),
    ] {
        std::fs::write(root.path(), bytes).unwrap();
        if future {
            assert!(matches!(
                adapter.load_default().unwrap(),
                LoadedTrafficSuite::UnsupportedSchema(999)
            ));
            assert_eq!(
                adapter
                    .save_default(&suite(), expected.clone())
                    .unwrap_err(),
                TrafficStorageError::UnsupportedSchema(999)
            );
        } else {
            assert_eq!(
                adapter.load_default().unwrap_err(),
                TrafficStorageError::InvalidData
            );
        }
        assert_eq!(std::fs::read_to_string(root.path()).unwrap(), bytes);
    }
}

#[test]
fn exact_bytes_and_revision_both_guard_overwrite() {
    let root = Root::new();
    let adapter = root.adapter();
    let expected = expectation(
        adapter
            .save_default(&suite(), TrafficSaveExpectation::Missing)
            .unwrap(),
    );
    let original = std::fs::read_to_string(root.path()).unwrap();
    std::fs::write(root.path(), format!("{original}\n# external edit\n")).unwrap();
    assert_eq!(
        adapter.save_default(&suite(), expected).unwrap_err(),
        TrafficStorageError::Conflict
    );
    let expected = expectation(adapter.load_default().unwrap());
    std::fs::write(
        root.path(),
        original.replace("revision = 1", "revision = 2"),
    )
    .unwrap();
    assert_eq!(
        adapter.save_default(&suite(), expected).unwrap_err(),
        TrafficStorageError::Conflict
    );
}

#[test]
fn non_default_identity_never_creates_a_second_file() {
    let root = Root::new();
    let mut draft = suite();
    draft.id = TrafficSuiteId::parse("other").unwrap();
    assert_eq!(
        root.adapter()
            .save_default(&draft, TrafficSaveExpectation::Missing)
            .unwrap_err(),
        TrafficStorageError::InvalidSuite
    );
    assert!(!root.0.exists());
}
