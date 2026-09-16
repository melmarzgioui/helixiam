-- Helix IAM (federation): per-execution admin config for flow steps, stored as a JSON object string.
-- Backs the "Identity Provider Redirector" step (providerAlias + mode), and is available to any future
-- authenticator that declares a config schema. Nullable so all existing executions are unaffected.
ALTER TABLE auth_flow_execution ADD COLUMN IF NOT EXISTS config text DEFAULT NULL;
