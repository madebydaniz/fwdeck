//! Filesystem-independent default-suite persistence boundary.

use crate::domain::{TrafficSuite, TrafficSuiteRevision};
use std::sync::Arc;

/// Blocking persistence operations; callers must provide an owned blocking worker.
pub trait TrafficSuiteStorage: Send + Sync + 'static {
    /// Opaque exact-content identity owned by the adapter.
    type Version: Clone + Send + Sync + 'static;
    /// Reads the default suite without creating it.
    fn load_default(&self) -> Result<LoadedTrafficSuite<Self::Version>, TrafficStorageError>;
    /// Atomically saves the default suite under an optimistic concurrency guard.
    fn save_default(
        &self,
        suite: &TrafficSuite,
        expected: TrafficSaveExpectation<Self::Version>,
    ) -> Result<LoadedTrafficSuite<Self::Version>, TrafficStorageError>;
}

/// Trusted state from the last accepted load or save.
#[derive(Debug, Clone)]
pub enum TrafficSaveExpectation<V> {
    /// Creation only.
    Missing,
    /// Both revision and exact content must match.
    Existing {
        /// Last persisted revision.
        revision: TrafficSuiteRevision,
        /// Adapter-owned exact-content identity.
        fingerprint: V,
    },
}

/// Bounded result without paths or operating-system diagnostics.
#[derive(Debug, Clone)]
pub enum LoadedTrafficSuite<V> {
    /// No suite exists.
    Missing,
    /// Valid supported content and its exact storage identity.
    Available {
        /// Immutable persisted suite.
        suite: Arc<TrafficSuite>,
        /// Exact-content identity.
        fingerprint: V,
    },
    /// Preserved unsupported schema.
    UnsupportedSchema(u32),
}

/// Public persistence failures never contain arbitrary file data or diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrafficStorageError {
    #[error("invalid traffic suite")]
    /// Domain validation or default identity failed.
    InvalidSuite,
    #[error("invalid traffic suite data")]
    /// Decoding or serialization failed.
    InvalidData,
    #[error("traffic suite storage conflict")]
    /// Persisted state no longer matches the expectation.
    Conflict,
    #[error("unsupported traffic suite schema {0}")]
    /// Schema cannot be edited.
    UnsupportedSchema(u32),
    #[error("unsafe traffic suite path")]
    /// Path failed safe-file checks.
    UnsafePath,
    #[error("traffic suite is too large")]
    /// Bounded storage limit exceeded.
    TooLarge,
    #[error("traffic suite permission denied")]
    /// Filesystem access denied.
    PermissionDenied,
    #[error("traffic suite storage failed")]
    /// Indeterminate I/O failure.
    Io,
    #[error("traffic suite worker failed")]
    /// Blocking worker or adapter contract failed.
    WorkerFailed,
}
