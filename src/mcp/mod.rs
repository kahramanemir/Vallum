//! Static MCP configuration scanner: discover config files and flag embedded
//! secrets, risky launch commands, and injection in embedded descriptions.
//! Read-only — connects to nothing, launches nothing, modifies nothing.

pub mod discover;
pub mod model;
pub mod scan;

pub use scan::{CheckKind, Finding, Severity};
