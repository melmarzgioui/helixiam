-- 1.0 security (item 1): admin-managed allowlist of profile attributes a user may edit themselves via the
-- self-service Account API. NULL/empty = nothing is self-editable (everything else is admin-only).
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS self_editable_attributes text;
