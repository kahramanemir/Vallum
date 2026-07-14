//! # Vallum
//!
//! A security boundary between AI coding agents (Claude Code, and any agent via
//! `vallum run`) and your shell. When an agent runs a command, Vallum redacts secrets,
//! neutralizes prompt-injection attempts, wraps the result as untrusted data,
//! preserves the child exit code, and audits everything — so what reaches the
//! model is exactly what you intend it to see. As a side benefit it strips
//! ANSI noise and compresses long output, which also saves tokens.
//!
//! ## This crate is a CLI
//!
//! Vallum is primarily the **`vallum` command-line tool**. Install it with
//! `cargo install vallum` (or via shell installer, Homebrew, or npm — see the
//! [README]) and run, for example, `vallum run -- cargo test`. The full
//! pipeline, configuration, security model, and Claude Code integration are
//! documented in the [README] and the threat model in [SECURITY.md].
//!
//! ## Library surface
//!
//! The modules below are published so the crate's integration tests can drive
//! the pipeline internals. They are **not a stable public API**: semver applies
//! to the CLI's behavior, not to these items, which may change between
//! releases. Build on the `vallum` binary, not on this crate.
//!
//! [README]: https://github.com/kahramanemir/Vallum
//! [SECURITY.md]: https://github.com/kahramanemir/Vallum/blob/main/SECURITY.md

// src/lib.rs — library surface so integration tests can exercise internals.
pub mod ansi;
pub mod audit;
pub mod breaker;
pub mod cli;
pub mod config;
pub mod doctor;
#[doc(hidden)]
pub mod eval;
pub mod executor;
pub mod fsutil;
pub mod hook;
pub mod install_hook;
pub mod logchain;
pub mod mcp;
pub mod metrics;
pub mod optimizer;
pub mod policy;
pub mod scrubber;
pub mod stats;
pub mod tokenizer;
pub mod truncator;
pub mod update;
pub mod welcome;
pub mod whitespace;
