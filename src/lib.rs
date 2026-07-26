#![warn(missing_docs)]
//! `FWDeck` — a safety-first terminal UI for firewalld.
//!
//! `FWDeck` is distributed as an application; the shipped artifact is the
//! `fwdeck` binary. This library target exists so integration tests (and later
//! benches)
//! can reach the parsers and backend — its API is internal and **not** covered
//! by semantic-versioning guarantees.

pub mod application;
pub mod bootstrap;
pub mod cli;
pub mod config;
pub mod domain;
pub mod error;
pub mod infrastructure;
pub mod ui;
