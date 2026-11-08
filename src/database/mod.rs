//! Embedded persistence and repository implementations.
//!
//! Keep redb-specific details behind repository interfaces. Database handles should be scoped to
//! the operation that needs them rather than held for the application's lifetime.
