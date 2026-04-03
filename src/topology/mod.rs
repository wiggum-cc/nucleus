//! Compose-equivalent topology management for multi-container deployments.
//!
//! Provides declarative multi-container topology with dependency ordering,
//! shared networks, volume management, and a reconciliation loop — equivalent
//! to Docker Compose but native to Nucleus and Nix.
//!
//! # Architecture
//!
//! - **Config**: TOML-based topology definition with services, networks, volumes
//! - **DAG**: Dependency graph with topological sort for startup ordering
//! - **Reconcile**: Diff running vs desired state, apply changes with zero-downtime
//! - **DNS**: Lightweight per-topology DNS for container name resolution

mod config;
mod dag;
mod dns;
mod reconcile;

pub use config::*;
pub use dag::*;
pub use dns::*;
pub use reconcile::*;
