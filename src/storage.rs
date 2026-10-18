use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use chrono::prelude::*;

use crate::money::Cents;

// Temporary in-memory storage. Amounts are integer cents.
// Temporary storage for credentials and transaction history
pub type Credentials = HashMap<String, String>;
pub type TransactionHistory = HashMap<String, Vec<(DateTime<Utc>, Cents)>>;

#[derive(Debug)]
pub struct Storage {
    pub credentials: Credentials,
    pub transactions: TransactionHistory,
}

/// Shared, thread-safe application state.
pub type SharedStorage = Mutex<Storage>;

/// Lock the storage, recovering from a poisoned mutex instead of panicking.
///
/// A panic in one request handler while holding the lock would otherwise
/// poison it and make every subsequent request panic as well.
pub fn lock(state: &SharedStorage) -> MutexGuard<'_, Storage> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}
