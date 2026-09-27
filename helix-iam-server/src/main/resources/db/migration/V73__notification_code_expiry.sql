-- Security: one-time codes sent by email (password reset, sign-up verification) now expire. A code issued before
-- this column existed expires its TTL after creation_date (NotificationCodePolicy).
ALTER TABLE notification_code ADD COLUMN IF NOT EXISTS expires_at timestamp;
