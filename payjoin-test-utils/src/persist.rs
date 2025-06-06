use std::sync::{Arc, RwLock};

#[derive(Clone, Default)]
pub struct InMemoryTestPersister<T> {
    pub inner: Arc<RwLock<InnerStorage<T>>>,
}

#[derive(Clone, Default)]
pub struct InnerStorage<T> {
    pub events: Vec<T>,
    pub is_closed: bool,
}

#[derive(Debug, Clone, PartialEq)]
/// Dummy error type for testing
pub struct InMemoryTestError {}

impl std::error::Error for InMemoryTestError {}

impl std::fmt::Display for InMemoryTestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InMemoryTestError")
    }
}
