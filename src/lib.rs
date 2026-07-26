#![warn(missing_docs)]
//! `FWDeck` — a safety-first terminal UI for firewalld.
//!
//! `FWDeck` is distributed as an application; the shipped artifact is the
//! `fwdeck` binary. This library target exists so integration tests (and later
//! benches) can reach the parsers and backend — its API is internal and
//! **not** covered by semantic-versioning guarantees. Do not depend on it.
//!
//! User documentation lives at <https://madebydaniz.github.io/fwdeck/docs/>.

pub mod cli;
pub mod config;
pub mod domain;
pub mod error;

// Internal plumbing: reachable by the binary and the test suite, but hidden
// from the rendered docs.rs surface — this crate is an application, not a
// library. `#[doc(hidden)]` also lifts the `missing_docs` obligation on these
// modules while keeping them fully accessible in-tree.
#[doc(hidden)]
pub mod application;
#[doc(hidden)]
pub mod bootstrap;
#[doc(hidden)]
pub mod infrastructure;
#[doc(hidden)]
pub mod ui;
