//! Embedded persistence and repository implementations.
//!
//! Keep redb-specific details behind this module. Each command owns its database handle for the
//! duration of its operation; benchmark services will explicitly close it before network tests.

mod nodes;

pub use nodes::{AddNodeOutcome, NodeDatabase, NodeRecord, default_database_path};
