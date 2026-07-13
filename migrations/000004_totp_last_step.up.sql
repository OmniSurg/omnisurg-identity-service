-- totp_last_step records the highest TOTP time-step counter already accepted for
-- this user, so a code cannot be replayed within the +/-1 skew window (RFC 6238
-- section 5.2). NULL means no code has been accepted yet.
ALTER TABLE users ADD COLUMN totp_last_step BIGINT;
