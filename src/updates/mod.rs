//! Update orchestration and reusable artifact services.
//!
//! Release-specific policy lives in resolvers; downloading, verification, staging, and
//! replacement are isolated so managed cores can reuse the same safety-critical code.

mod application;
pub mod artifact;
pub mod installer;
pub mod platform;
pub mod release;

pub use application::update_application;
