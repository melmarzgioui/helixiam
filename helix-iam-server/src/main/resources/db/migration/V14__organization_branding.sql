-- 1.0 item 7 (branding): per-organization logo and primary colour, shown on the login, consent and MFA pages
-- when the organization is in context. display_name already exists. Values are validated by the admin API
-- (https logo URL, #RRGGBB colour); no raw CSS or HTML is ever stored.
ALTER TABLE organization ADD COLUMN IF NOT EXISTS logo_url character varying(2048) DEFAULT NULL;
ALTER TABLE organization ADD COLUMN IF NOT EXISTS primary_color character varying(7) DEFAULT NULL;
