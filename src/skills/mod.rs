//! Static scanner for agent skill files (`SKILL.md`) and agent context files
//! (`CLAUDE.md`, `AGENTS.md`, …). Read-only; reuses Vallum's scrubber, policy,
//! and injection engines — no new detection logic lives here.

pub mod discover;
pub mod model;
pub mod report;
pub mod scan;
