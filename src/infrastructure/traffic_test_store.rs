//! Versioned, bounded, private persistence for traffic-test suites.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::domain::{
    MAX_TRAFFIC_NAME_BYTES, TrafficSuite, TrafficSuiteId, TrafficSuiteRevision,
    TrafficValidationError,
};

/// Current traffic-suite file schema.
pub const TRAFFIC_SUITE_SCHEMA_VERSION: u32 = 1;
/// Maximum accepted or emitted suite-file size.
pub const MAX_TRAFFIC_SUITE_FILE_BYTES: usize = 1024 * 1024;

/// A validated filename inside the traffic-suite directory.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrafficSuiteFileName(String);

impl TrafficSuiteFileName {
    /// Validates a single `.toml` filename derived from a suite identifier.
    pub fn parse(raw: &str) -> Result<Self, TrafficSuiteFileNameError> {
        let Some(stem) = raw.strip_suffix(".toml") else {
            return Err(TrafficSuiteFileNameError);
        };
        if stem.is_empty()
            || stem.starts_with('.')
            || raw.contains('/')
            || raw.contains('\\')
            || raw.chars().any(char::is_whitespace)
        {
            return Err(TrafficSuiteFileNameError);
        }
        TrafficSuiteId::parse(stem).map_err(|_| TrafficSuiteFileNameError)?;
        Ok(Self(raw.to_owned()))
    }

    fn from_suite_id(id: &TrafficSuiteId) -> Result<Self, TrafficSuiteFileNameError> {
        Self::parse(&format!("{}.toml", id.as_str()))
    }

    /// Returns the validated filename.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for TrafficSuiteFileName {
    fn default() -> Self {
        Self("default.toml".to_owned())
    }
}

/// Invalid suite filename.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid traffic-suite filename")]
pub struct TrafficSuiteFileNameError;

/// Stable fingerprint of the exact file bytes used for optimistic concurrency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrafficSuiteFingerprint(u128);

impl TrafficSuiteFingerprint {
    fn from_bytes(bytes: &[u8]) -> Self {
        const OFFSET: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
        const PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;
        let mut digest = OFFSET;
        for byte in bytes {
            digest ^= u128::from(*byte);
            digest = digest.wrapping_mul(PRIME);
        }
        Self(digest)
    }
}

impl std::fmt::Display for TrafficSuiteFingerprint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{:032x}", self.0)
    }
}

/// A supported suite loaded from private storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTrafficSuite {
    /// Validated suite contents.
    pub suite: TrafficSuite,
    /// Fingerprint of the exact serialized bytes.
    pub fingerprint: TrafficSuiteFingerprint,
    /// File that supplied the suite.
    pub path: PathBuf,
}

/// Bounded metadata retained from an unsupported future schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FutureTrafficSuite {
    /// Unsupported schema version.
    pub schema_version: u32,
    /// Suite identifier when it fits current metadata bounds.
    pub id: Option<String>,
    /// Suite name when it fits current metadata bounds.
    pub name: Option<String>,
    /// Persisted revision when present.
    pub revision: Option<u64>,
    /// Fingerprint of the byte-preserved file.
    pub fingerprint: TrafficSuiteFingerprint,
    /// File that supplied the metadata.
    pub path: PathBuf,
}

/// Result of two-stage suite loading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficSuiteLoad {
    /// Current schema decoded and validated successfully.
    Available(StoredTrafficSuite),
    /// Newer schema retained only as read-only metadata.
    FutureSchema(FutureTrafficSuite),
}

/// Expected state for an optimistic-concurrency save.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficSuiteWriteExpectation {
    /// The suite must not exist.
    Missing,
    /// The existing suite must match both values.
    Existing {
        /// Revision observed by the caller.
        revision: TrafficSuiteRevision,
        /// Exact content fingerprint observed by the caller.
        fingerprint: TrafficSuiteFingerprint,
    },
}

/// Traffic-suite storage failure.
#[derive(Debug, thiserror::Error)]
pub enum TrafficSuiteStoreError {
    /// Filename is not a safe suite filename.
    #[error(transparent)]
    InvalidFileName(#[from] TrafficSuiteFileNameError),
    /// Suite content violates the domain contract.
    #[error("invalid traffic suite: {0}")]
    InvalidSuite(#[from] TrafficValidationError),
    /// The requested suite does not exist.
    #[error("traffic suite does not exist")]
    NotFound,
    /// A create-only save found an existing path.
    #[error("traffic suite already exists")]
    AlreadyExists,
    /// Symlinks are never followed.
    #[error("traffic suite symlink rejected")]
    SymlinkRejected,
    /// The path does not identify a regular file.
    #[error("traffic suite is not a regular file")]
    NotRegularFile,
    /// The file changed while its safe handle was being acquired.
    #[error("traffic suite changed while opening")]
    ChangedWhileOpening,
    /// Input or output crossed the hard size limit.
    #[error("traffic suite is {actual} bytes; maximum is {max}")]
    FileTooLarge {
        /// Observed byte count.
        actual: u64,
        /// Maximum accepted byte count.
        max: usize,
    },
    /// The version envelope could not be decoded.
    #[error("invalid traffic-suite envelope: {0}")]
    InvalidEnvelope(String),
    /// The supported schema body could not be decoded.
    #[error("invalid traffic-suite schema v1: {0}")]
    InvalidSchema(String),
    /// A schema older than v1 has no supported migration.
    #[error("traffic-suite schema v{schema_version} is unsupported")]
    UnsupportedSchema {
        /// Unsupported schema version.
        schema_version: u32,
    },
    /// A newer schema is read-only and cannot be overwritten.
    #[error("traffic-suite schema v{schema_version} is newer and read-only")]
    FutureSchema {
        /// Newer schema version.
        schema_version: u32,
    },
    /// Filename and decoded suite identity disagree.
    #[error("traffic-suite filename does not match suite ID")]
    SuiteIdentityMismatch,
    /// Existing revision differs from the caller's observation.
    #[error("traffic-suite revision conflict: expected {expected}, found {actual}")]
    RevisionConflict {
        /// Caller-observed revision.
        expected: u64,
        /// Current persisted revision.
        actual: u64,
    },
    /// Existing bytes differ from the caller's observation.
    #[error("traffic-suite fingerprint conflict")]
    FingerprintConflict {
        /// Caller-observed fingerprint.
        expected: TrafficSuiteFingerprint,
        /// Current persisted fingerprint.
        actual: TrafficSuiteFingerprint,
    },
    /// TOML serialization failed.
    #[error("could not serialize traffic suite: {0}")]
    Serialization(String),
    /// Filesystem operation failed.
    #[error("traffic-suite storage failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Private directory containing versioned traffic-test suites.
#[derive(Debug, Clone)]
pub struct TrafficSuiteStore {
    directory: PathBuf,
}

impl TrafficSuiteStore {
    /// Creates a store rooted at `directory`.
    #[must_use]
    pub fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    /// Loads one validated filename without following links.
    pub fn load(
        &self,
        name: &TrafficSuiteFileName,
    ) -> Result<TrafficSuiteLoad, TrafficSuiteStoreError> {
        load_path(&self.directory.join(name.as_str()), name)
    }

    /// Validates and durably saves one suite with optimistic concurrency.
    pub fn save(
        &self,
        suite: &TrafficSuite,
        expectation: TrafficSuiteWriteExpectation,
    ) -> Result<StoredTrafficSuite, TrafficSuiteStoreError> {
        suite.validate()?;
        let name = TrafficSuiteFileName::from_suite_id(&suite.id)?;
        let path = self.directory.join(name.as_str());
        let encoded = encode_suite(suite)?;
        if encoded.len() > MAX_TRAFFIC_SUITE_FILE_BYTES {
            return Err(TrafficSuiteStoreError::FileTooLarge {
                actual: u64::try_from(encoded.len()).unwrap_or(u64::MAX),
                max: MAX_TRAFFIC_SUITE_FILE_BYTES,
            });
        }

        super::state_file::create_private_dir(&self.directory)?;
        match expectation {
            TrafficSuiteWriteExpectation::Missing => {
                reject_existing_create_target(&path)?;
                match super::state_file::write_private_atomic_create(&path, &encoded) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        return Err(TrafficSuiteStoreError::AlreadyExists);
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            TrafficSuiteWriteExpectation::Existing {
                revision,
                fingerprint,
            } => {
                let current = match self.load(&name)? {
                    TrafficSuiteLoad::Available(current) => current,
                    TrafficSuiteLoad::FutureSchema(future) => {
                        return Err(TrafficSuiteStoreError::FutureSchema {
                            schema_version: future.schema_version,
                        });
                    }
                };
                if current.suite.revision != revision {
                    return Err(TrafficSuiteStoreError::RevisionConflict {
                        expected: revision.get(),
                        actual: current.suite.revision.get(),
                    });
                }
                if current.fingerprint != fingerprint {
                    return Err(TrafficSuiteStoreError::FingerprintConflict {
                        expected: fingerprint,
                        actual: current.fingerprint,
                    });
                }
                super::state_file::write_private_atomic_replace(&path, &encoded)?;
            }
        }

        Ok(StoredTrafficSuite {
            suite: suite.clone(),
            fingerprint: TrafficSuiteFingerprint::from_bytes(&encoded),
            path,
        })
    }
}

/// Returns the default suite path below an XDG configuration root.
#[must_use]
pub fn default_suite_path_from(config_home: &Path) -> PathBuf {
    config_home.join("fwdeck/traffic-tests/default.toml")
}

/// Returns the platform configuration path for the default suite.
#[must_use]
pub fn default_suite_path() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|dirs| default_suite_path_from(dirs.config_dir()))
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TrafficSuiteFileV1 {
    schema_version: u32,
    #[serde(flatten)]
    suite: TrafficSuite,
}

#[derive(Debug, serde::Deserialize)]
struct TrafficSuiteEnvelopeMetadata {
    schema_version: u32,
    id: Option<toml::Value>,
    name: Option<toml::Value>,
    revision: Option<toml::Value>,
}

fn encode_suite(suite: &TrafficSuite) -> Result<Vec<u8>, TrafficSuiteStoreError> {
    let envelope = TrafficSuiteFileV1 {
        schema_version: TRAFFIC_SUITE_SCHEMA_VERSION,
        suite: suite.clone(),
    };
    toml::to_string_pretty(&envelope)
        .map(String::into_bytes)
        .map_err(|error| TrafficSuiteStoreError::Serialization(error.to_string()))
}

fn load_path(
    path: &Path,
    name: &TrafficSuiteFileName,
) -> Result<TrafficSuiteLoad, TrafficSuiteStoreError> {
    let mut file = open_regular_file(path)?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_TRAFFIC_SUITE_FILE_BYTES as u64 {
        return Err(TrafficSuiteStoreError::FileTooLarge {
            actual: metadata.len(),
            max: MAX_TRAFFIC_SUITE_FILE_BYTES,
        });
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.by_ref()
        .take((MAX_TRAFFIC_SUITE_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_TRAFFIC_SUITE_FILE_BYTES {
        return Err(TrafficSuiteStoreError::FileTooLarge {
            actual: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            max: MAX_TRAFFIC_SUITE_FILE_BYTES,
        });
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| TrafficSuiteStoreError::InvalidEnvelope(error.to_string()))?;
    let envelope: TrafficSuiteEnvelopeMetadata = toml::from_str(text)
        .map_err(|error| TrafficSuiteStoreError::InvalidEnvelope(error.to_string()))?;
    let fingerprint = TrafficSuiteFingerprint::from_bytes(&bytes);

    if envelope.schema_version > TRAFFIC_SUITE_SCHEMA_VERSION {
        return Ok(TrafficSuiteLoad::FutureSchema(FutureTrafficSuite {
            schema_version: envelope.schema_version,
            id: bounded_metadata(envelope.id),
            name: bounded_metadata(envelope.name),
            revision: envelope.revision.and_then(|value| {
                value
                    .as_integer()
                    .and_then(|revision| u64::try_from(revision).ok())
            }),
            fingerprint,
            path: path.to_path_buf(),
        }));
    }
    if envelope.schema_version < TRAFFIC_SUITE_SCHEMA_VERSION {
        return Err(TrafficSuiteStoreError::UnsupportedSchema {
            schema_version: envelope.schema_version,
        });
    }

    let decoded: TrafficSuiteFileV1 = toml::from_str(text)
        .map_err(|error| TrafficSuiteStoreError::InvalidSchema(error.to_string()))?;
    decoded.suite.validate()?;
    if format!("{}.toml", decoded.suite.id.as_str()) != name.as_str() {
        return Err(TrafficSuiteStoreError::SuiteIdentityMismatch);
    }
    Ok(TrafficSuiteLoad::Available(StoredTrafficSuite {
        suite: decoded.suite,
        fingerprint,
        path: path.to_path_buf(),
    }))
}

fn bounded_metadata(value: Option<toml::Value>) -> Option<String> {
    value
        .and_then(|value| value.as_str().map(str::to_owned))
        .filter(|value| {
            !value.is_empty()
                && value.len() <= MAX_TRAFFIC_NAME_BYTES
                && !value.chars().any(char::is_control)
        })
}

fn reject_existing_create_target(path: &Path) -> Result<(), TrafficSuiteStoreError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(TrafficSuiteStoreError::SymlinkRejected)
        }
        Ok(_) => Err(TrafficSuiteStoreError::AlreadyExists),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn open_regular_file(path: &Path) -> Result<std::fs::File, TrafficSuiteStoreError> {
    let link_metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(TrafficSuiteStoreError::NotFound);
        }
        Err(error) => return Err(error.into()),
    };
    if link_metadata.file_type().is_symlink() {
        return Err(TrafficSuiteStoreError::SymlinkRejected);
    }
    if !link_metadata.file_type().is_file() {
        return Err(TrafficSuiteStoreError::NotRegularFile);
    }

    let file = std::fs::File::open(path)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.file_type().is_file() {
        return Err(TrafficSuiteStoreError::NotRegularFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if link_metadata.dev() != opened_metadata.dev()
            || link_metadata.ino() != opened_metadata.ino()
        {
            return Err(TrafficSuiteStoreError::ChangedWhileOpening);
        }
    }
    Ok(file)
}
