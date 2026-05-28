// src/lib.rs — library surface so integration tests can exercise internals.
pub mod ansi;
pub mod audit;
pub mod cli;
pub mod config;
pub mod executor;
pub mod fsutil;
pub mod hook;
pub mod install_hook;
pub mod metrics;
pub mod optimizer;
pub mod scrubber;
pub mod stats;
pub mod tokenizer;
pub mod truncator;
pub mod whitespace;
