-- Security: emailed one-time codes (password reset, sign-up verification) are stored as the hex SHA-256 of the code,
-- like the magic-link tokens; the plain code exists only in the email. The codes are random UUIDs, so a plain hash is
-- enough (no salt or KDF). Codes pending at the upgrade are hashed in place, so their links keep working until they
-- expire. A stored value that is already 64 lower-case hex characters is a hash (a plain code never is).
UPDATE notification_code SET code = encode(sha256(convert_to(code, 'UTF8')), 'hex')
WHERE code !~ '^[0-9a-f]{64}$';
