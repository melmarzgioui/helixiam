-- Item E4: when an organization is hinted on the authorization request (organization=<id or name>), a sign-in by a
-- user who is not a member is refused (access_denied to the client) instead of only branded. Off by default.
ALTER TABLE organization ADD COLUMN IF NOT EXISTS require_membership boolean DEFAULT false NOT NULL;
