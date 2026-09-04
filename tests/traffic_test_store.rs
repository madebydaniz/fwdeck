#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::atomic::{AtomicU64, Ordering};

use fwdeck::domain::{
    PortSelector, SourceAddress, TrafficConnectionState, TrafficDestination, TrafficDirection,
    TrafficExpectation, TrafficScenario, TrafficScenarioId, TrafficSeverity, TrafficSuite,
    TrafficSuiteId, TrafficSuiteRevision, TrafficTransport,
};
use fwdeck::infrastructure::traffic_test_store::{
    MAX_TRAFFIC_SUITE_FILE_BYTES, StoredTrafficSuite, TRAFFIC_SUITE_SCHEMA_VERSION,
    TrafficSuiteFileName, TrafficSuiteLoad, TrafficSuiteStore, TrafficSuiteStoreError,
    TrafficSuiteWriteExpectation, default_suite_path, default_suite_path_from,
};

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn scratch(label: &str) -> std::path::PathBuf {
    let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "fwdeck-traffic-store-{label}-{}-{sequence}",
        std::process::id()
    ))
}

fn scenario(id: &str) -> TrafficScenario {
    TrafficScenario {
        id: TrafficScenarioId::parse(id).unwrap(),
        name: format!("Scenario {id}"),
        enabled: true,
        direction: TrafficDirection::ToHost,
        source: SourceAddress::parse("192.0.2.0/24").unwrap(),
        ingress_interface: None,
        ingress_zone: None,
        destination: TrafficDestination::LocalHost,
        egress_interface: None,
        egress_zone: None,
        transport: TrafficTransport::Tcp,
        destination_port: Some("22".parse::<PortSelector>().unwrap()),
        source_port: None,
        connection_state: TrafficConnectionState::New,
        expectation: TrafficExpectation::Allow,
        severity: TrafficSeverity::Critical,
        required_safety_gate: true,
        note: Some("Keep the administration path reachable".to_owned()),
    }
}

fn suite(revision: u64) -> TrafficSuite {
    TrafficSuite {
        id: TrafficSuiteId::parse("default").unwrap(),
        name: "Default host checks".to_owned(),
        revision: TrafficSuiteRevision::new(revision).unwrap(),
        scenarios: vec![scenario("keep-ssh")],
    }
}

fn loaded(stored: TrafficSuiteLoad) -> StoredTrafficSuite {
    match stored {
        TrafficSuiteLoad::Available(stored) => stored,
        TrafficSuiteLoad::FutureSchema(future) => {
            panic!(
                "expected schema v1, got future schema v{}",
                future.schema_version
            )
        }
    }
}

#[test]
fn schema_v1_round_trip_is_deterministic_private_and_uses_the_default_suffix() {
    let root = scratch("round-trip");
    let store = TrafficSuiteStore::new(root.clone());
    let expected = suite(1);

    let first = store
        .save(&expected, TrafficSuiteWriteExpectation::Missing)
        .unwrap();
    let first_bytes = std::fs::read(&first.path).unwrap();
    let round_trip = loaded(store.load(&TrafficSuiteFileName::default()).unwrap());

    assert_eq!(round_trip.suite, expected);
    assert_eq!(round_trip.fingerprint, first.fingerprint);
    assert_eq!(round_trip.fingerprint.to_string().len(), 32);
    assert_eq!(round_trip.path, first.path);
    assert!(
        std::str::from_utf8(&first_bytes)
            .unwrap()
            .starts_with("schema_version = 1\n")
    );
    assert_eq!(
        default_suite_path_from(std::path::Path::new("/config")),
        std::path::Path::new("/config/fwdeck/traffic-tests/default.toml")
    );

    let second = store
        .save(
            &expected,
            TrafficSuiteWriteExpectation::Existing {
                revision: round_trip.suite.revision,
                fingerprint: round_trip.fingerprint,
            },
        )
        .unwrap();
    assert_eq!(std::fs::read(second.path).unwrap(), first_bytes);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&first.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn schema_zero_and_malformed_schema_one_are_rejected() {
    let root = scratch("invalid-schemas");
    std::fs::create_dir_all(&root).unwrap();
    let store = TrafficSuiteStore::new(root.clone());
    let name = TrafficSuiteFileName::default();
    let path = root.join(name.as_str());

    std::fs::write(&path, "schema_version = 0\n").unwrap();
    assert!(matches!(
        store.load(&name),
        Err(TrafficSuiteStoreError::UnsupportedSchema { schema_version: 0 })
    ));
    std::fs::write(&path, "schema_version = 1\nid = \"default\"\n").unwrap();
    assert!(matches!(
        store.load(&name),
        Err(TrafficSuiteStoreError::InvalidSchema(_))
    ));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn missing_and_non_directory_store_roots_are_typed() {
    let missing = scratch("missing-root");
    let store = TrafficSuiteStore::new(missing);
    assert!(matches!(
        store.load(&TrafficSuiteFileName::default()),
        Err(TrafficSuiteStoreError::NotFound)
    ));

    let file_root = scratch("file-root");
    std::fs::write(&file_root, b"not a directory").unwrap();
    let store = TrafficSuiteStore::new(file_root.clone());
    assert!(matches!(
        store.load(&TrafficSuiteFileName::default()),
        Err(TrafficSuiteStoreError::NotRegularFile)
    ));
    let _ = std::fs::remove_file(file_root);
}

#[test]
fn platform_default_path_and_valid_but_oversized_encoding_are_bounded() {
    assert!(default_suite_path().is_some());
    let root = scratch("encoded-size");
    let mut oversized = suite(1);
    oversized.scenarios = (0..1000)
        .map(|index| {
            let mut scenario = scenario(&format!("large-{index}"));
            scenario.note = Some("x".repeat(1024));
            scenario
        })
        .collect();
    oversized.validate().unwrap();
    assert!(matches!(
        TrafficSuiteStore::new(root.clone())
            .save(&oversized, TrafficSuiteWriteExpectation::Missing),
        Err(TrafficSuiteStoreError::FileTooLarge { .. })
    ));
    assert!(!root.exists());
}

#[test]
fn replace_is_same_directory_atomic_and_leaves_no_temporary_file() {
    let root = scratch("replace");
    let store = TrafficSuiteStore::new(root.clone());
    let first = store
        .save(&suite(1), TrafficSuiteWriteExpectation::Missing)
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&first.path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let updated = suite(2);

    let saved = store
        .save(
            &updated,
            TrafficSuiteWriteExpectation::Existing {
                revision: TrafficSuiteRevision::new(1).unwrap(),
                fingerprint: first.fingerprint,
            },
        )
        .unwrap();

    assert_eq!(
        loaded(store.load(&TrafficSuiteFileName::default()).unwrap()).suite,
        updated
    );
    assert_eq!(saved.path.parent(), Some(root.as_path()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&saved.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(std::fs::read_dir(&root).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp")
    }));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn filenames_are_validated_and_cannot_escape_the_store() {
    assert_eq!(
        TrafficSuiteFileName::parse("default.toml").unwrap(),
        TrafficSuiteFileName::default()
    );
    for invalid in [
        "",
        ".toml",
        "../default.toml",
        "nested/default.toml",
        "nested\\default.toml",
        "default",
        "default.json",
        ".hidden.toml",
        "bad name.toml",
    ] {
        assert!(
            TrafficSuiteFileName::parse(invalid).is_err(),
            "accepted {invalid}"
        );
    }
}

#[test]
fn load_rejects_symlinks_and_non_regular_files() {
    let root = scratch("file-kind");
    std::fs::create_dir_all(&root).unwrap();
    let store = TrafficSuiteStore::new(root.clone());
    let name = TrafficSuiteFileName::default();
    std::fs::create_dir(root.join(name.as_str())).unwrap();
    assert!(matches!(
        store.load(&name),
        Err(TrafficSuiteStoreError::NotRegularFile)
    ));
    std::fs::remove_dir(root.join(name.as_str())).unwrap();

    #[cfg(unix)]
    {
        std::fs::write(root.join("target.toml"), "schema_version = 1\n").unwrap();
        std::os::unix::fs::symlink(root.join("target.toml"), root.join(name.as_str())).unwrap();
        assert!(matches!(
            store.load(&name),
            Err(TrafficSuiteStoreError::SymlinkRejected)
        ));
    }
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn save_rejects_a_symlink_without_modifying_its_target() {
    let root = scratch("save-symlink");
    std::fs::create_dir_all(&root).unwrap();
    let store = TrafficSuiteStore::new(root.clone());
    let target = root.join("external.toml");
    std::fs::write(&target, "external bytes\n").unwrap();
    std::os::unix::fs::symlink(&target, root.join("default.toml")).unwrap();

    assert!(matches!(
        store.save(&suite(1), TrafficSuiteWriteExpectation::Missing),
        Err(TrafficSuiteStoreError::SymlinkRejected)
    ));
    assert_eq!(std::fs::read(&target).unwrap(), b"external bytes\n");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn load_rejects_files_larger_than_one_mebibyte_before_parsing() {
    let root = scratch("size");
    std::fs::create_dir_all(&root).unwrap();
    let store = TrafficSuiteStore::new(root.clone());
    std::fs::write(
        root.join(TrafficSuiteFileName::default().as_str()),
        vec![b'x'; MAX_TRAFFIC_SUITE_FILE_BYTES + 1],
    )
    .unwrap();

    assert!(matches!(
        store.load(&TrafficSuiteFileName::default()),
        Err(TrafficSuiteStoreError::FileTooLarge { .. })
    ));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn supported_schema_rejects_a_filename_and_suite_identity_mismatch() {
    let root = scratch("identity-mismatch");
    let store = TrafficSuiteStore::new(root.clone());
    let saved = store
        .save(&suite(1), TrafficSuiteWriteExpectation::Missing)
        .unwrap();
    let mismatched = std::fs::read_to_string(&saved.path)
        .unwrap()
        .replace("id = \"default\"", "id = \"other\"");
    std::fs::write(&saved.path, mismatched).unwrap();

    assert!(matches!(
        store.load(&TrafficSuiteFileName::default()),
        Err(TrafficSuiteStoreError::SuiteIdentityMismatch)
    ));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn save_rejects_more_than_one_thousand_scenarios_before_writing() {
    let root = scratch("scenario-limit");
    let store = TrafficSuiteStore::new(root.clone());
    let mut oversized = suite(1);
    oversized.scenarios = (0..=1000)
        .map(|index| scenario(&format!("scenario-{index}")))
        .collect();

    assert!(matches!(
        store.save(&oversized, TrafficSuiteWriteExpectation::Missing),
        Err(TrafficSuiteStoreError::InvalidSuite(_))
    ));
    assert!(!root.join("default.toml").exists());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn save_detects_expected_revision_conflicts_without_overwriting() {
    let root = scratch("revision-conflict");
    let store = TrafficSuiteStore::new(root.clone());
    let existing = store
        .save(&suite(1), TrafficSuiteWriteExpectation::Missing)
        .unwrap();
    let before = std::fs::read(&existing.path).unwrap();

    assert!(matches!(
        store.save(
            &suite(2),
            TrafficSuiteWriteExpectation::Existing {
                revision: TrafficSuiteRevision::new(9).unwrap(),
                fingerprint: existing.fingerprint,
            }
        ),
        Err(TrafficSuiteStoreError::RevisionConflict { .. })
    ));
    assert_eq!(std::fs::read(&existing.path).unwrap(), before);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn save_detects_external_content_changes_with_the_same_revision() {
    let root = scratch("fingerprint-conflict");
    let store = TrafficSuiteStore::new(root.clone());
    let existing = store
        .save(&suite(1), TrafficSuiteWriteExpectation::Missing)
        .unwrap();
    let original = std::fs::read_to_string(&existing.path).unwrap();
    let edited = original.replace("Default host checks", "Externally edited");
    std::fs::write(&existing.path, edited.as_bytes()).unwrap();

    assert!(matches!(
        store.save(
            &suite(2),
            TrafficSuiteWriteExpectation::Existing {
                revision: TrafficSuiteRevision::new(1).unwrap(),
                fingerprint: existing.fingerprint,
            }
        ),
        Err(TrafficSuiteStoreError::FingerprintConflict { .. })
    ));
    assert_eq!(std::fs::read(&existing.path).unwrap(), edited.as_bytes());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn future_schema_is_metadata_only_read_only_and_byte_preserved() {
    let root = scratch("future-schema");
    std::fs::create_dir_all(&root).unwrap();
    let store = TrafficSuiteStore::new(root.clone());
    let name = TrafficSuiteFileName::default();
    let path = root.join(name.as_str());
    let future = format!(
        "schema_version = {}\nid = \"default\"\nname = \"Future suite\"\nrevision = 7\nscenarios = \"unknown future body\"\nfuture_only = \"keep me\"\n",
        TRAFFIC_SUITE_SCHEMA_VERSION + 1
    );
    std::fs::write(&path, future.as_bytes()).unwrap();

    let loaded = store.load(&name).unwrap();
    let TrafficSuiteLoad::FutureSchema(metadata) = loaded else {
        panic!("future schema was decoded as a supported suite");
    };
    assert_eq!(metadata.schema_version, TRAFFIC_SUITE_SCHEMA_VERSION + 1);
    assert_eq!(metadata.id.as_deref(), Some("default"));
    assert_eq!(metadata.name.as_deref(), Some("Future suite"));
    assert_eq!(metadata.revision, Some(7));
    assert_eq!(std::fs::read(&path).unwrap(), future.as_bytes());

    assert!(matches!(
        store.save(
            &suite(8),
            TrafficSuiteWriteExpectation::Existing {
                revision: TrafficSuiteRevision::new(7).unwrap(),
                fingerprint: metadata.fingerprint,
            }
        ),
        Err(TrafficSuiteStoreError::FutureSchema { .. })
    ));
    assert_eq!(std::fs::read(&path).unwrap(), future.as_bytes());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn future_schema_tolerates_changed_metadata_types_without_decoding_the_body() {
    let root = scratch("future-metadata");
    std::fs::create_dir_all(&root).unwrap();
    let store = TrafficSuiteStore::new(root.clone());
    let name = TrafficSuiteFileName::default();
    let path = root.join(name.as_str());
    let future = format!(
        "schema_version = {}\nid = 42\nname = [\"future\"]\nrevision = \"next\"\nscenarios = \"unknown future body\"\n",
        TRAFFIC_SUITE_SCHEMA_VERSION + 1
    );
    std::fs::write(&path, future.as_bytes()).unwrap();

    let TrafficSuiteLoad::FutureSchema(metadata) = store.load(&name).unwrap() else {
        panic!("future schema was decoded as a supported suite");
    };
    assert_eq!(metadata.id, None);
    assert_eq!(metadata.name, None);
    assert_eq!(metadata.revision, None);
    assert_eq!(std::fs::read(&path).unwrap(), future.as_bytes());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn missing_expectation_never_overwrites_an_existing_suite() {
    let root = scratch("create-conflict");
    let store = TrafficSuiteStore::new(root.clone());
    let existing = store
        .save(&suite(1), TrafficSuiteWriteExpectation::Missing)
        .unwrap();
    let before = std::fs::read(&existing.path).unwrap();

    assert!(matches!(
        store.save(&suite(2), TrafficSuiteWriteExpectation::Missing),
        Err(TrafficSuiteStoreError::AlreadyExists)
    ));
    assert_eq!(std::fs::read(&existing.path).unwrap(), before);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn store_root_symlink_is_rejected_for_load_and_save() {
    let parent = scratch("root-symlink");
    let target = parent.join("target");
    let link = parent.join("link");
    std::fs::create_dir_all(&target).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let store = TrafficSuiteStore::new(link);

    assert!(matches!(
        store.load(&TrafficSuiteFileName::default()),
        Err(TrafficSuiteStoreError::SymlinkRejected)
    ));
    assert!(matches!(
        store.save(&suite(1), TrafficSuiteWriteExpectation::Missing),
        Err(TrafficSuiteStoreError::SymlinkRejected)
    ));
    assert!(std::fs::read_dir(&target).unwrap().next().is_none());
    let _ = std::fs::remove_dir_all(parent);
}

#[test]
fn concurrent_existing_saves_allow_only_one_observed_fingerprint() {
    let root = scratch("concurrent-existing");
    let initial = TrafficSuiteStore::new(root.clone())
        .save(&suite(1), TrafficSuiteWriteExpectation::Missing)
        .unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let handles = [2, 3].map(|revision| {
        let root = root.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        std::thread::spawn(move || {
            let store = TrafficSuiteStore::new(root);
            barrier.wait();
            store.save(
                &suite(revision),
                TrafficSuiteWriteExpectation::Existing {
                    revision: TrafficSuiteRevision::new(1).unwrap(),
                    fingerprint: initial.fingerprint,
                },
            )
        })
    });
    barrier.wait();
    let outcomes = handles.map(|handle| handle.join().unwrap());

    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_err()).count(),
        1
    );
    assert!(outcomes.iter().any(|outcome| matches!(
        outcome,
        Err(TrafficSuiteStoreError::RevisionConflict { actual: 2 | 3, .. })
    )));
    let final_revision = loaded(
        TrafficSuiteStore::new(root.clone())
            .load(&TrafficSuiteFileName::default())
            .unwrap(),
    )
    .suite
    .revision
    .get();
    assert!(matches!(final_revision, 2 | 3));
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
#[allow(clippy::disallowed_methods)]
fn malicious_lock_symlink_and_fifo_are_rejected_without_following_or_blocking() {
    let root = scratch("malicious-lock");
    std::fs::create_dir_all(&root).unwrap();
    let lock = root.join(".fwdeck-traffic-test-store.lock");
    let target = root.join("target");
    std::fs::write(&target, b"untouched").unwrap();
    std::os::unix::fs::symlink(&target, &lock).unwrap();
    let store = TrafficSuiteStore::new(root.clone());
    assert!(matches!(
        store.save(&suite(1), TrafficSuiteWriteExpectation::Missing),
        Err(TrafficSuiteStoreError::SymlinkRejected)
    ));
    assert_eq!(std::fs::read(&target).unwrap(), b"untouched");

    std::fs::remove_file(&lock).unwrap();
    let status = std::process::Command::new("mkfifo")
        .arg(&lock)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(matches!(
        store.save(&suite(1), TrafficSuiteWriteExpectation::Missing),
        Err(TrafficSuiteStoreError::NotRegularFile)
    ));
    assert!(!root.join("default.toml").exists());
    let _ = std::fs::remove_dir_all(root);
}
