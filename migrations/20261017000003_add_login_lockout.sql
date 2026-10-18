-- Account lockout after repeated failed logins.
ALTER TABLE users ADD COLUMN failed_logins INTEGER NOT NULL DEFAULT 0;
-- Unix epoch milliseconds until which logins are refused (NULL = not locked).
ALTER TABLE users ADD COLUMN locked_until INTEGER;
