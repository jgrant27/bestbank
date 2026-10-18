-- Server-side sessions. `id` is the SHA-256 (hex) of the random session
-- token held in the client's encrypted cookie, so a database leak doesn't
-- expose usable tokens. Timestamps are Unix epoch milliseconds (UTC).
CREATE TABLE sessions (
    id         TEXT    PRIMARY KEY NOT NULL,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX sessions_by_user ON sessions (user_id);
CREATE INDEX sessions_by_expiry ON sessions (expires_at);
