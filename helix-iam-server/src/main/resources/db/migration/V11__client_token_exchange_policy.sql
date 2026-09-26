-- 1.0 item 5: RFC 8693 token-exchange target policy. Comma-joined client ids that may obtain a token for this
-- client with audience=<this client>. NULL/empty = nobody may exchange to it.
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS token_exchange_allowed_clients character varying(2000) DEFAULT NULL;
