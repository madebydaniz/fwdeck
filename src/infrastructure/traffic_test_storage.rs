//! Default-only adapter retaining the existing private atomic suite store.

use super::traffic_test_store::{
    TrafficSuiteFileName, TrafficSuiteFingerprint, TrafficSuiteLoad, TrafficSuiteStore,
    TrafficSuiteStoreError, TrafficSuiteWriteExpectation,
};
use crate::{
    application::{
        LoadedTrafficSuite, TrafficSaveExpectation, TrafficStorageError, TrafficSuiteStorage,
    },
    domain::TrafficSuite,
};
use std::{path::Path, sync::Arc};

/// Storage rooted below the explicitly supplied application configuration directory.
#[derive(Debug, Clone)]
pub struct DefaultTrafficSuiteStorage {
    store: TrafficSuiteStore,
}

impl DefaultTrafficSuiteStorage {
    /// Constructs an inert adapter; does not resolve platform paths or create files.
    #[must_use]
    pub fn new(config_directory: &Path) -> Self {
        Self {
            store: TrafficSuiteStore::new(config_directory.join("traffic-tests")),
        }
    }
}

impl TrafficSuiteStorage for DefaultTrafficSuiteStorage {
    type Version = TrafficSuiteFingerprint;
    fn load_default(&self) -> Result<LoadedTrafficSuite<Self::Version>, TrafficStorageError> {
        match self.store.load(&TrafficSuiteFileName::default()) {
            Ok(TrafficSuiteLoad::Available(stored)) => Ok(LoadedTrafficSuite::Available {
                suite: Arc::new(stored.suite),
                fingerprint: stored.fingerprint,
            }),
            Ok(TrafficSuiteLoad::FutureSchema(future)) => {
                Ok(LoadedTrafficSuite::UnsupportedSchema(future.schema_version))
            }
            Err(TrafficSuiteStoreError::NotFound) => Ok(LoadedTrafficSuite::Missing),
            Err(error) => Err(map_error(error)),
        }
    }
    fn save_default(
        &self,
        suite: &TrafficSuite,
        expected: TrafficSaveExpectation<Self::Version>,
    ) -> Result<LoadedTrafficSuite<Self::Version>, TrafficStorageError> {
        if suite.id.as_str() != "default" {
            return Err(TrafficStorageError::InvalidSuite);
        }
        let expected = match expected {
            TrafficSaveExpectation::Missing => TrafficSuiteWriteExpectation::Missing,
            TrafficSaveExpectation::Existing {
                revision,
                fingerprint,
            } => TrafficSuiteWriteExpectation::Existing {
                revision,
                fingerprint,
            },
        };
        let stored = self.store.save(suite, expected).map_err(map_error)?;
        Ok(LoadedTrafficSuite::Available {
            suite: Arc::new(stored.suite),
            fingerprint: stored.fingerprint,
        })
    }
}

fn map_error(error: TrafficSuiteStoreError) -> TrafficStorageError {
    use TrafficSuiteStoreError as E;
    match error {
        E::InvalidFileName(_) | E::SymlinkRejected | E::NotRegularFile => {
            TrafficStorageError::UnsafePath
        }
        E::InvalidSuite(_) | E::SuiteIdentityMismatch => TrafficStorageError::InvalidSuite,
        E::NotFound
        | E::AlreadyExists
        | E::ChangedWhileOpening
        | E::RevisionConflict { .. }
        | E::FingerprintConflict { .. } => TrafficStorageError::Conflict,
        E::FileTooLarge { .. } => TrafficStorageError::TooLarge,
        E::InvalidEnvelope(_) | E::InvalidSchema(_) | E::Serialization(_) => {
            TrafficStorageError::InvalidData
        }
        E::UnsupportedSchema { schema_version } | E::FutureSchema { schema_version } => {
            TrafficStorageError::UnsupportedSchema(schema_version)
        }
        E::Io(error) => match error.kind() {
            std::io::ErrorKind::PermissionDenied => TrafficStorageError::PermissionDenied,
            std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::NotFound => {
                TrafficStorageError::Conflict
            }
            _ => TrafficStorageError::Io,
        },
    }
}

#[cfg(test)]
#[path = "traffic_test_storage/tests.rs"]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests;
