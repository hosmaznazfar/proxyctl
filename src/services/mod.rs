//! Application services.
//!
//! Services contain use-case logic and coordinate domain interfaces. They must not depend on
//! clap's CLI types.

pub mod benchmark;
pub mod cores;
pub mod nodes;
pub mod updates;
pub mod validation;
