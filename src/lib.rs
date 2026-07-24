#![warn(missing_docs)]
//! `FWDeck` — a safety-first terminal UI for firewalld.
//!
//! Library target exists so integration tests (and later benches) can reach
//! the parsers and backend; the shipped artifact is the `fwdeck` binary.

pub mod application;
pub mod bootstrap;
pub mod cli;
pub mod config;
pub mod domain;
pub mod error;
pub mod infrastructure;
pub mod ui;
