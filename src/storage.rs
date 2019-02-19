use std::collections::HashMap;

use chrono::prelude::*;

// Temporary storage for credentials and transaction history
pub type Credentials = HashMap<String, String>;
pub type TransactionHistory = HashMap<String, Vec<(DateTime<Utc>, f64)>>;

#[derive(Debug)]
pub struct Storage {
    pub credentials: Credentials,
    pub transactions: TransactionHistory,
}
