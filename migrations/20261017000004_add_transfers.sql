-- Transfers between users: each transaction gets a kind, and transfers
-- record the other party.
ALTER TABLE transactions ADD COLUMN kind TEXT NOT NULL DEFAULT 'deposit'
    CHECK (kind IN ('deposit', 'withdrawal', 'transfer_out', 'transfer_in'));
ALTER TABLE transactions ADD COLUMN counterparty_id INTEGER
    REFERENCES users (id) ON DELETE SET NULL;
UPDATE transactions SET kind = 'withdrawal' WHERE amount_cents < 0;
