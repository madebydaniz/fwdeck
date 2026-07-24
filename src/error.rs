//! Top-level application errors. Layer-specific errors (`ValidationError`,
//! `FirewallError`, `ProcessError`, `ParseError`) map into this at
//! the application boundary; `anyhow` is used only in `main`.

use crate::domain::ValidationError;

/// Top-level application error, produced at the application boundary.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Terminal setup/teardown or other I/O failed.
    #[error("terminal error: {0}")]
    Terminal(#[from] std::io::Error),
    /// The config file could not be read, parsed, or validated.
    #[error("configuration error ({path}): {message}")]
    Config {
        /// The offending config file path (or `<defaults>`).
        path: String,
        /// What went wrong.
        message: String,
    },
    /// Domain-level input validation failed.
    #[error(transparent)]
    Validation(#[from] ValidationError),
}
