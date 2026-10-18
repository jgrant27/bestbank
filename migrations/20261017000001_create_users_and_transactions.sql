-- Users and their transaction history. Amounts are integer cents and
-- timestamps are Unix epoch milliseconds (UTC).
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE TABLE transactions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    amount_cents INTEGER NOT NULL CHECK (amount_cents <> 0),
    created_at   INTEGER NOT NULL
);

CREATE INDEX transactions_by_user ON transactions (user_id, id);
