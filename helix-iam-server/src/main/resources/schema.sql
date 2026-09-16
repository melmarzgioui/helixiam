-- TENANT TABLES --
CREATE TABLE IF NOT EXISTS tenant (
    tenant_id             character varying(255) NOT NULL PRIMARY KEY,
    name                  character varying(255) DEFAULT NULL,
    creation_date         timestamp DEFAULT CURRENT_TIMESTAMP,
    modify_date           timestamp DEFAULT CURRENT_TIMESTAMP
    );

-- REALM CONFIG (Helix IAM E1.3) --
-- Per-realm settings. A realm maps 1:1 to a tenant (realm_id == tenant_id), so this is
-- additive over the existing tenant model -- no migration of existing data. Holds the
-- per-realm knobs later epics attach to (issuer, token lifetimes, password policy, MFA
-- requirement, branding); per-realm signing keys land in E1.4.
CREATE TABLE IF NOT EXISTS realm_config (
    realm_id                  character varying(255) NOT NULL PRIMARY KEY,
    display_name              character varying(255) DEFAULT NULL,
    issuer                    character varying(512) DEFAULT NULL,
    access_token_ttl_seconds  integer DEFAULT 3600 NOT NULL,
    refresh_token_ttl_seconds integer DEFAULT 5184000 NOT NULL,
    reuse_refresh_tokens      boolean DEFAULT false NOT NULL,
    require_mfa               boolean DEFAULT false NOT NULL,
    password_min_length       integer DEFAULT 12 NOT NULL,
    enabled                   boolean DEFAULT true NOT NULL,
    subject_claim             character varying(255) DEFAULT NULL,
    sso_session_idle_timeout_seconds integer DEFAULT 1800 NOT NULL,
    sso_session_max_lifetime_seconds integer DEFAULT 36000 NOT NULL,
    remember_me               boolean DEFAULT false NOT NULL,
    remember_me_lifetime_seconds integer DEFAULT 2592000 NOT NULL,
    registration_enabled      boolean DEFAULT true NOT NULL,
    creation_date             timestamp DEFAULT CURRENT_TIMESTAMP,
    modify_date               timestamp DEFAULT CURRENT_TIMESTAMP
    );
-- SSO P3: per-realm SSO session policies on existing deployments.
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS sso_session_idle_timeout_seconds integer DEFAULT 1800 NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS sso_session_max_lifetime_seconds integer DEFAULT 36000 NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS remember_me boolean DEFAULT false NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS remember_me_lifetime_seconds integer DEFAULT 2592000 NOT NULL;
-- Per-realm self-registration switch on existing deployments.
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS registration_enabled boolean DEFAULT true NOT NULL;

-- REALM SIGNING KEYS (Helix IAM E1.4) --
-- Per-realm JWT signing keys with rotation. The private key is encrypted at rest
-- (AttributeEncryption). Status: ACTIVE (signs new tokens), ROTATED (kept in JWKS for
-- verification during the overlap window), RETIRED (removed from JWKS). Keeping ROTATED
-- keys published gives zero-downtime rotation.
CREATE TABLE IF NOT EXISTS realm_key (
    key_id        character varying(255) NOT NULL PRIMARY KEY,
    realm_id      character varying(255) NOT NULL,
    algorithm     character varying(20)  DEFAULT 'RSA' NOT NULL,
    public_key    text                   NOT NULL,
    private_key   text                   NOT NULL,
    status        character varying(20)  DEFAULT 'ACTIVE' NOT NULL,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP,
    rotated_date  timestamp DEFAULT NULL
    );
CREATE INDEX IF NOT EXISTS realm_key_realm_status_idx ON realm_key (realm_id, status);

-- HELIX IAM E2.5: per-realm authentication flows (data-driven, editable from the admin console).
-- A flow is an ordered tree of executions; nesting is by parent_id, ordering by priority.
CREATE TABLE IF NOT EXISTS auth_flow (
    flow_id       character varying(255) NOT NULL PRIMARY KEY,
    realm_id      character varying(255) NOT NULL,
    alias         character varying(255) NOT NULL,
    built_in      boolean DEFAULT false NOT NULL,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP
    );
CREATE UNIQUE INDEX IF NOT EXISTS auth_flow_realm_alias_idx ON auth_flow (realm_id, alias);

CREATE TABLE IF NOT EXISTS auth_flow_execution (
    execution_id     character varying(255) NOT NULL PRIMARY KEY,
    flow_id          character varying(255) NOT NULL,
    parent_id        character varying(255) DEFAULT NULL,
    authenticator_id character varying(255) DEFAULT NULL,
    requirement      character varying(20)  NOT NULL,
    is_condition     boolean DEFAULT false NOT NULL,
    priority         integer DEFAULT 0 NOT NULL,
    config           text DEFAULT NULL
    );
CREATE INDEX IF NOT EXISTS auth_flow_execution_flow_idx ON auth_flow_execution (flow_id);
-- IdP redirect flow step: per-execution config (JSON) on existing deployments (CREATE ... IF NOT EXISTS
-- above is a no-op when the table already exists, so add the column idempotently for the sql.init path).
ALTER TABLE auth_flow_execution ADD COLUMN IF NOT EXISTS config text DEFAULT NULL;

-- HELIX IAM E3.2: single-use MFA recovery (backup) codes. Only the hash is stored; a code is
-- burned (used=true) on first successful use.
CREATE TABLE IF NOT EXISTS mfa_recovery_code (
    code_id       character varying(255) NOT NULL PRIMARY KEY,
    user_id       character varying(255) NOT NULL,
    code_hash     character varying(255) NOT NULL,
    used          boolean DEFAULT false NOT NULL,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP
    );
CREATE INDEX IF NOT EXISTS mfa_recovery_code_user_idx ON mfa_recovery_code (user_id, used);

-- HELIX IAM E3.4: HMAC-based (counter) OTP credential. Secret stored encrypted at rest; the
-- counter advances on each successful verification (with a small look-ahead window).
CREATE TABLE IF NOT EXISTS mfa_hotp (
    user_id character varying(255) NOT NULL PRIMARY KEY,
    secret  text                   NOT NULL,
    counter bigint DEFAULT 0 NOT NULL
    );

-- HELIX IAM E3.3: WebAuthn / FIDO2 (passkey) credentials. The attested credential data (COSE
-- public key + aaguid + credential id) is stored Base64-encoded; sign_count advances on each
-- successful assertion (clone-detection).
CREATE TABLE IF NOT EXISTS webauthn_credential (
    credential_id           character varying(512) NOT NULL PRIMARY KEY,
    user_id                 character varying(255) NOT NULL,
    attested_credential     text                   NOT NULL,
    sign_count              bigint DEFAULT 0 NOT NULL,
    creation_date           timestamp DEFAULT CURRENT_TIMESTAMP
    );
CREATE INDEX IF NOT EXISTS webauthn_credential_user_idx ON webauthn_credential (user_id);

-- HELIX IAM E4.1: VeridPay-style device-factor signing credentials. The device's non-exportable
-- P-256 public key (SPKI, base64) is stored after platform attestation; assertions are verified by
-- ES256 over single-use server challenges, so no shared secret is held.
CREATE TABLE IF NOT EXISTS device_credential (
    device_id               character varying(255) NOT NULL PRIMARY KEY,
    user_id                 character varying(255) NOT NULL,
    public_key              text                   NOT NULL,
    platform                character varying(64)  NOT NULL,
    biometric               boolean DEFAULT false  NOT NULL,
    creation_date           timestamp DEFAULT CURRENT_TIMESTAMP,
    last_used_date          timestamp
    );
CREATE INDEX IF NOT EXISTS device_credential_user_idx ON device_credential (user_id);

-- HELIX IAM E5: federated identity links — maps an external IdP subject (idp_alias + external_subject)
-- to a local user, the persistence behind the broker's account linking. The surrogate id is
-- "idp_alias|external_subject" so the (alias, subject) pair is unique.
CREATE TABLE IF NOT EXISTS federated_link (
    id                character varying(700) NOT NULL PRIMARY KEY,
    idp_alias         character varying(255) NOT NULL,
    external_subject  character varying(512) NOT NULL,
    user_id           character varying(255) NOT NULL,
    creation_date     timestamp DEFAULT CURRENT_TIMESTAMP
    );
CREATE INDEX IF NOT EXISTS federated_link_user_idx ON federated_link (user_id);

-- IDENTITY PROVIDER CONFIG (Helix IAM E8.1) --
-- Per-realm identity-provider connections the admin console (E8.2) manages and the
-- federation registry (E8.3) loads. id = "realm_id|alias"; protocol-specific settings
-- live in config_json so the table stays stable as provider types grow. No FK on
-- realm_id (realm rows may be transient defaults), matching realm_key.
CREATE TABLE IF NOT EXISTS identity_provider (
    id                character varying(512) NOT NULL PRIMARY KEY,
    realm_id          character varying(255) NOT NULL,
    alias             character varying(255) NOT NULL,
    protocol          character varying(40)  NOT NULL,
    display_name      character varying(255) DEFAULT NULL,
    config_json       text                   NOT NULL,
    enabled           boolean DEFAULT true NOT NULL,
    creation_date     timestamp DEFAULT CURRENT_TIMESTAMP,
    modify_date       timestamp DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (realm_id, alias)
    );
CREATE INDEX IF NOT EXISTS identity_provider_realm_idx ON identity_provider (realm_id);



-- SP TABLES --
CREATE TABLE IF NOT EXISTS service_provider_oauth (
    service_provider_id             character varying(255) NOT NULL PRIMARY KEY,
    client_id                       varchar(100) NOT NULL,
    client_id_issued_at             timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret                   varchar(200) DEFAULT NULL,
    client_secret_expires_at        timestamp DEFAULT NULL,
    client_authentication_methods   varchar(1000) DEFAULT NULL,
    authorization_grant_types       varchar(1000) DEFAULT NULL,
    redirect_uris                   varchar(1000) DEFAULT NULL,
    post_logout_redirect_uris       varchar(1000) DEFAULT NULL,
    scopes                          varchar(1000) DEFAULT NULL,
    client_settings                 varchar(2000) DEFAULT NULL,
    token_settings                  varchar(2000) DEFAULT NULL,
    creation_date                   timestamp DEFAULT CURRENT_TIMESTAMP,
    modify_date                     timestamp DEFAULT CURRENT_TIMESTAMP,
    deleted                         boolean default false,
    subject_claim                   character varying(255) DEFAULT NULL,
    tenant_id                       character varying(255) NOT NULL,
    -- Helix IAM multi-tenant (MT-3): the realm (URL path slug) this client is reachable under.
    -- Defaults to the admin realm so existing/platform-created clients stay reachable at /realms/master.
    realm_id                        character varying(255) NOT NULL DEFAULT 'master',
    -- Helix IAM (named flows): per-client override of the realm's browser login flow. NULL = inherit the
    -- realm default ("browser"); otherwise the alias of a named flow this client's interactive login runs.
    auth_flow_alias                 character varying(255) DEFAULT NULL,
    -- Helix IAM (client detail page): display name + description (cosmetic; name also fills
    -- the OIDC client_name / consent screen). NULL = fall back to the client_id.
    name                            character varying(255) DEFAULT NULL,
    description                     character varying(1000) DEFAULT NULL,
    -- Helix IAM (CORS): comma-joined browser origins allowed to call this realm's OAuth/OIDC endpoints
    -- cross-origin (SPAs using authorization_code + PKCE). Enforced by RealmClientCorsConfigurationSource.
    web_origins                     character varying(2000) DEFAULT NULL,
    -- Helix IAM (parity Wave 1): access type + login settings + URLs.
    public_client                   boolean DEFAULT false,   -- true = no secret, PKCE required (SPA/native)
    consent_required                boolean DEFAULT false,   -- show the OAuth consent screen
    display_on_consent_screen       boolean DEFAULT true,
    login_theme                     character varying(255) DEFAULT NULL,
    root_url                        character varying(1000) DEFAULT NULL,
    home_url                        character varying(1000) DEFAULT NULL,
    admin_url                       character varying(1000) DEFAULT NULL,
    always_display_in_console       boolean DEFAULT false,
    -- Helix IAM (parity Wave 2): per-client token tuning / fine-grain OIDC.
    access_token_lifespan           integer DEFAULT NULL,   -- seconds; null = realm default (3600)
    refresh_token_lifespan          integer DEFAULT NULL,   -- seconds; null = default
    id_token_signature_alg          character varying(16) DEFAULT NULL,  -- RS256/RS384/RS512/ES256…; null = RS256
    reuse_refresh_tokens            boolean DEFAULT false,
    UNIQUE (service_provider_id),
    UNIQUE (client_id),
    FOREIGN KEY(tenant_id) REFERENCES tenant(tenant_id) ON DELETE CASCADE
);
-- Idempotent for pre-existing DBs (CREATE TABLE IF NOT EXISTS above won't ALTER an existing table).
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS realm_id character varying(255) NOT NULL DEFAULT 'master';
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS auth_flow_alias character varying(255) DEFAULT NULL;
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS name character varying(255) DEFAULT NULL;
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS description character varying(1000) DEFAULT NULL;
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS web_origins character varying(2000) DEFAULT NULL;
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS public_client boolean DEFAULT false;
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS consent_required boolean DEFAULT false;
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS display_on_consent_screen boolean DEFAULT true;
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS login_theme character varying(255) DEFAULT NULL;
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS root_url character varying(1000) DEFAULT NULL;
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS home_url character varying(1000) DEFAULT NULL;
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS admin_url character varying(1000) DEFAULT NULL;
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS always_display_in_console boolean DEFAULT false;
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS access_token_lifespan integer DEFAULT NULL;
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS refresh_token_lifespan integer DEFAULT NULL;
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS id_token_signature_alg character varying(16) DEFAULT NULL;
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS reuse_refresh_tokens boolean DEFAULT false;
-- Wave 5: signed-JWT (private_key_jwt) client authentication — auth method + the client's JWKS URL.
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS token_endpoint_auth_method character varying(32) DEFAULT NULL;
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS jwks_url character varying(1000) DEFAULT NULL;
-- Helix IAM SSO P6: OIDC back-channel / front-channel logout endpoints per client.
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS backchannel_logout_uri character varying(1000) DEFAULT NULL;
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS frontchannel_logout_uri character varying(1000) DEFAULT NULL;
CREATE INDEX IF NOT EXISTS service_provider_oauth_realm_idx ON service_provider_oauth (realm_id);

-- Helix IAM (parity Wave 3): per-client protocol mappers. Each maps a source (a user-profile
-- attribute, or a hardcoded value) into a named claim in the access and/or ID token at issuance.
CREATE TABLE IF NOT EXISTS client_protocol_mapper (
    mapper_id            character varying(255) NOT NULL PRIMARY KEY,
    realm_id             character varying(255) NOT NULL DEFAULT 'master',
    client_id            character varying(100) NOT NULL,        -- the client's clientId (not surrogate id)
    name                 character varying(255) NOT NULL,
    mapper_type          character varying(32)  NOT NULL,        -- USER_ATTRIBUTE | HARDCODED
    source               character varying(512) DEFAULT NULL,    -- attribute key, or the hardcoded value
    claim_name           character varying(255) NOT NULL,        -- target claim
    add_to_access_token  boolean DEFAULT true,
    add_to_id_token      boolean DEFAULT true,
    creation_date        timestamp DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS client_protocol_mapper_client_idx ON client_protocol_mapper (realm_id, client_id);

-- Helix IAM Wave 4: roles defined ON a client (client roles), and roles granted to a client's
-- service account (the identity behind its client_credentials tokens).
CREATE TABLE IF NOT EXISTS client_role (
    role_id          character varying(255) NOT NULL PRIMARY KEY,
    realm_id         character varying(255) NOT NULL DEFAULT 'master',
    client_id        character varying(100) NOT NULL,        -- the owning client's clientId
    name             character varying(255) NOT NULL,
    description      character varying(255) DEFAULT NULL,
    creation_date    timestamp DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (realm_id, client_id, name)
);
CREATE INDEX IF NOT EXISTS client_role_client_idx ON client_role (realm_id, client_id);

CREATE TABLE IF NOT EXISTS client_service_account_role (
    id               character varying(255) NOT NULL PRIMARY KEY,
    realm_id         character varying(255) NOT NULL DEFAULT 'master',
    client_id        character varying(100) NOT NULL,        -- the service account's owning client
    role_name        character varying(255) NOT NULL,        -- the granted role's name (realm or client role)
    role_type        character varying(16)  NOT NULL DEFAULT 'REALM',  -- REALM | CLIENT
    role_client_id   character varying(100) DEFAULT NULL,    -- for CLIENT roles: the role's owning client
    creation_date    timestamp DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (realm_id, client_id, role_name, role_type, role_client_id)
);
CREATE INDEX IF NOT EXISTS client_service_account_role_idx ON client_service_account_role (realm_id, client_id);

-- Helix IAM Wave 6: Authorization Services (UMA-style fine-grained authorization). A client can act as a
-- resource server with protected resources + scopes, role-based policies, and permissions binding them.
CREATE TABLE IF NOT EXISTS authz_resource_server (
    id                character varying(255) NOT NULL PRIMARY KEY,
    client_id         character varying(100) NOT NULL,
    realm_id          character varying(255) NOT NULL DEFAULT 'master',
    enabled           boolean DEFAULT true,
    decision_strategy character varying(16)  NOT NULL DEFAULT 'UNANIMOUS',  -- UNANIMOUS | AFFIRMATIVE
    UNIQUE (realm_id, client_id)
);
CREATE TABLE IF NOT EXISTS authz_scope (
    id                character varying(255) NOT NULL PRIMARY KEY,
    realm_id          character varying(255) NOT NULL DEFAULT 'master',
    client_id         character varying(100) NOT NULL,
    name              character varying(255) NOT NULL,
    UNIQUE (realm_id, client_id, name)
);
CREATE TABLE IF NOT EXISTS authz_resource (
    id                character varying(255) NOT NULL PRIMARY KEY,
    realm_id          character varying(255) NOT NULL DEFAULT 'master',
    client_id         character varying(100) NOT NULL,
    name              character varying(255) NOT NULL,
    uris              character varying(2000) DEFAULT NULL,   -- csv
    scopes            character varying(2000) DEFAULT NULL,   -- csv of scope names
    UNIQUE (realm_id, client_id, name)
);
CREATE TABLE IF NOT EXISTS authz_policy (
    id                character varying(255) NOT NULL PRIMARY KEY,
    realm_id          character varying(255) NOT NULL DEFAULT 'master',
    client_id         character varying(100) NOT NULL,
    name              character varying(255) NOT NULL,
    type              character varying(32)  NOT NULL DEFAULT 'ROLE',   -- ROLE (others reserved)
    logic             character varying(16)  NOT NULL DEFAULT 'POSITIVE',  -- POSITIVE | NEGATIVE
    roles             character varying(2000) DEFAULT NULL,   -- csv of role names (ROLE policy)
    UNIQUE (realm_id, client_id, name)
);
CREATE TABLE IF NOT EXISTS authz_permission (
    id                character varying(255) NOT NULL PRIMARY KEY,
    realm_id          character varying(255) NOT NULL DEFAULT 'master',
    client_id         character varying(100) NOT NULL,
    name              character varying(255) NOT NULL,
    type              character varying(16)  NOT NULL DEFAULT 'RESOURCE', -- RESOURCE | SCOPE
    resource_name     character varying(255) DEFAULT NULL,
    scope_name        character varying(255) DEFAULT NULL,
    policies          character varying(2000) DEFAULT NULL,   -- csv of policy names
    decision_strategy character varying(16)  NOT NULL DEFAULT 'UNANIMOUS',
    UNIQUE (realm_id, client_id, name)
);
CREATE INDEX IF NOT EXISTS authz_scope_idx ON authz_scope (realm_id, client_id);
CREATE INDEX IF NOT EXISTS authz_resource_idx ON authz_resource (realm_id, client_id);
CREATE INDEX IF NOT EXISTS authz_policy_idx ON authz_policy (realm_id, client_id);
CREATE INDEX IF NOT EXISTS authz_permission_idx ON authz_permission (realm_id, client_id);


-- USER TABLES --
CREATE TABLE IF NOT EXISTS user_credentials (
    user_id character varying(255) PRIMARY KEY,
    --user_id character varying(255) PRIMARY KEY,
    username character varying(255) NOT NULL,
    email character varying(255),
    password character varying(255),
    password_salt_value character varying(31),
    email_verified boolean default false,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP,
    modify_date timestamp DEFAULT CURRENT_TIMESTAMP,
    account_locked boolean default true,
    account_disabled boolean default true,
    deleted boolean default false,
    mfa_enabled boolean default false,
    mfa_secret character varying(255),
    UNIQUE (username)
);
-- Helix IAM "login with email": optional email identifier on existing deployments. Nullable + unique
-- (NULLs are not constrained), so accounts without an email coexist while emails stay one-per-account.
ALTER TABLE user_credentials ADD COLUMN IF NOT EXISTS email character varying(255);
CREATE UNIQUE INDEX IF NOT EXISTS ux_user_credentials_email ON user_credentials (email);

CREATE TABLE IF NOT EXISTS user_profile (
    user_id          character varying(255) NOT NULL,
    name             character varying(255) NOT NULL,
    value            character varying(255),
    creation_date    timestamp DEFAULT CURRENT_TIMESTAMP,
    modify_date      timestamp DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (name, user_id),
    FOREIGN KEY(user_id) REFERENCES user_credentials(user_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS user_roles (
    role_id          character varying(255) PRIMARY KEY,
    name             character varying(255) NOT NULL,
    description      character varying(255),
    creation_date    timestamp DEFAULT CURRENT_TIMESTAMP,
    modify_date      timestamp DEFAULT CURRENT_TIMESTAMP,
    tenant_id        character varying(255) NOT NULL,
    UNIQUE (name, tenant_id),
    FOREIGN KEY(tenant_id) REFERENCES tenant(tenant_id) ON DELETE CASCADE
);
-- Curated default-role flags (DR): a protected system role (admin/user/auditor) and the realm's
-- auto-assigned default role. Mirrors Flyway V6 for the legacy sql.init path.
ALTER TABLE user_roles ADD COLUMN IF NOT EXISTS system_role boolean NOT NULL DEFAULT false;
ALTER TABLE user_roles ADD COLUMN IF NOT EXISTS default_role boolean NOT NULL DEFAULT false;
-- USER IN TENANT -- (must precede user_in_role: that table has an FK to tenant_user, and a fresh
-- Postgres running schema.sql top-to-bottom requires the referenced table to exist first).
CREATE TABLE IF NOT EXISTS tenant_user (
    tenant_user_id        character varying(255) NOT NULL PRIMARY KEY,
    tenant_id             character varying(255) DEFAULT NULL,
    user_id               character varying(255) DEFAULT NULL,
    creation_date         timestamp DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES user_credentials(user_id) ON DELETE CASCADE,
    FOREIGN KEY(tenant_id) REFERENCES tenant(tenant_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_in_role (
    role_id          character varying(255) NOT NULL,
    user_id          character varying(255) NOT NULL,
    creation_date    timestamp DEFAULT CURRENT_TIMESTAMP,
    tenant_user_id   character varying(255) NOT NULL,
    UNIQUE (role_id, user_id),
    FOREIGN KEY(user_id) REFERENCES user_credentials(user_id) ON DELETE CASCADE,
    FOREIGN KEY(role_id) REFERENCES user_roles(role_id) ON DELETE CASCADE,
    FOREIGN KEY(tenant_user_id) REFERENCES tenant_user(tenant_user_id) ON DELETE CASCADE
);

-- HELIX IAM E8.5-S4: hierarchical user groups (realm-scoped, parent_id nests them), with member
-- and group-role mappings. Users in a group inherit the group's role mappings.
CREATE TABLE IF NOT EXISTS user_group (
    group_id      character varying(255) NOT NULL PRIMARY KEY,
    name          character varying(255) NOT NULL,
    parent_id     character varying(255) DEFAULT NULL,
    tenant_id     character varying(255) NOT NULL,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(tenant_id) REFERENCES tenant(tenant_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS user_group_tenant_idx ON user_group (tenant_id);

CREATE TABLE IF NOT EXISTS user_group_member (
    id            character varying(255) NOT NULL PRIMARY KEY,
    group_id      character varying(255) NOT NULL,
    user_id       character varying(255) NOT NULL,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (group_id, user_id),
    FOREIGN KEY(group_id) REFERENCES user_group(group_id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES user_credentials(user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_group_role (
    id            character varying(255) NOT NULL PRIMARY KEY,
    group_id      character varying(255) NOT NULL,
    role_id       character varying(255) NOT NULL,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (group_id, role_id),
    FOREIGN KEY(group_id) REFERENCES user_group(group_id) ON DELETE CASCADE,
    FOREIGN KEY(role_id) REFERENCES user_roles(role_id) ON DELETE CASCADE
);

-- HELIX IAM E8.5: claim catalogue (the supported claim *types*), client scopes (named bundles of
-- claims a client can request), and the scope->claim mappings. All realm-scoped; seeded on first use.
CREATE TABLE IF NOT EXISTS claim_def (
    claim_id      character varying(255) NOT NULL PRIMARY KEY,
    tenant_id     character varying(255) NOT NULL,
    claim_key     character varying(255) NOT NULL,
    label         character varying(255) NOT NULL,
    placeholder   character varying(255) DEFAULT NULL,
    mandatory     boolean DEFAULT false NOT NULL,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id, claim_key),
    FOREIGN KEY(tenant_id) REFERENCES tenant(tenant_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS claim_def_tenant_idx ON claim_def (tenant_id);

CREATE TABLE IF NOT EXISTS client_scope (
    scope_id      character varying(255) NOT NULL PRIMARY KEY,
    tenant_id     character varying(255) NOT NULL,
    name          character varying(255) NOT NULL,
    description   character varying(500) DEFAULT NULL,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id, name),
    FOREIGN KEY(tenant_id) REFERENCES tenant(tenant_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS client_scope_tenant_idx ON client_scope (tenant_id);

CREATE TABLE IF NOT EXISTS scope_claim (
    id            character varying(255) NOT NULL PRIMARY KEY,
    scope_id      character varying(255) NOT NULL,
    claim_id      character varying(255) NOT NULL,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (scope_id, claim_id),
    FOREIGN KEY(scope_id) REFERENCES client_scope(scope_id) ON DELETE CASCADE,
    FOREIGN KEY(claim_id) REFERENCES claim_def(claim_id) ON DELETE CASCADE
);
-- Helix IAM notifications (N1): per-realm SMS/email/push provider config + message templates.
CREATE TABLE IF NOT EXISTS messaging_provider (
    id            character varying(255) NOT NULL PRIMARY KEY,
    realm_id      character varying(255) NOT NULL,
    channel       character varying(16)  NOT NULL,   -- SMS | EMAIL | PUSH
    driver        character varying(32)  NOT NULL,   -- TWILIO|HTTP | SMTP|HTTP | FCM|APNS
    enabled       boolean DEFAULT false NOT NULL,
    from_address  character varying(320) DEFAULT NULL,
    from_name     character varying(255) DEFAULT NULL,
    config        text DEFAULT NULL,
    secret        text DEFAULT NULL,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP,
    modify_date   timestamp DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (realm_id, channel, driver)
);
CREATE INDEX IF NOT EXISTS messaging_provider_realm_idx ON messaging_provider (realm_id);

CREATE TABLE IF NOT EXISTS message_template (
    id            character varying(255) NOT NULL PRIMARY KEY,
    realm_id      character varying(255) NOT NULL,
    template_key  character varying(64)  NOT NULL,
    channel       character varying(16)  NOT NULL,
    subject       character varying(512) DEFAULT NULL,
    body          text DEFAULT NULL,
    enabled       boolean DEFAULT true NOT NULL,
    html          boolean DEFAULT false NOT NULL,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP,
    modify_date   timestamp DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (realm_id, template_key)
);
CREATE INDEX IF NOT EXISTS message_template_realm_idx ON message_template (realm_id);
ALTER TABLE message_template ADD COLUMN IF NOT EXISTS html boolean DEFAULT false NOT NULL;

CREATE TABLE IF NOT EXISTS device_push_token (
    id            character varying(255) NOT NULL PRIMARY KEY,
    realm_id      character varying(255) NOT NULL,
    user_id       character varying(255) NOT NULL,
    platform      character varying(16)  NOT NULL,
    token         character varying(512) NOT NULL,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP,
    modify_date   timestamp DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (realm_id, user_id, platform, token)
);
CREATE INDEX IF NOT EXISTS device_push_token_user_idx ON device_push_token (realm_id, user_id);

CREATE TABLE IF NOT EXISTS helix_authorization (
    id             character varying(255) NOT NULL PRIMARY KEY,
    principal_name character varying(255),
    grant_type     character varying(64),
    blob           text,
    expires_at     bigint
);
CREATE TABLE IF NOT EXISTS helix_authorization_token (
    token_hash       character varying(64)  NOT NULL PRIMARY KEY,
    authorization_id character varying(255) NOT NULL
);
CREATE INDEX IF NOT EXISTS helix_authorization_token_authz_idx ON helix_authorization_token (authorization_id);

CREATE TABLE IF NOT EXISTS helix_http_session (
    session_id           character varying(128) NOT NULL PRIMARY KEY,
    principal_name       character varying(255),
    blob                 text,
    creation_time        bigint,
    last_access_time     bigint,
    max_inactive_seconds integer,
    expiry_time          bigint
);
CREATE INDEX IF NOT EXISTS helix_http_session_principal_idx ON helix_http_session (principal_name);
CREATE INDEX IF NOT EXISTS helix_http_session_expiry_idx ON helix_http_session (expiry_time);

-- Helix IAM: SAML2 relying parties (service providers) registered against the SAML IdP role,
-- partitioned per realm. Managed via the admin API + console; read by the SAML IdP at request time.
CREATE TABLE IF NOT EXISTS saml_relying_party (
    id                              character varying(512) NOT NULL PRIMARY KEY,
    realm_id                        character varying(255) NOT NULL,
    entity_id                       character varying(512) NOT NULL,
    assertion_consumer_service_url  character varying(1000) NOT NULL,
    default_authn_context_class_ref character varying(255) DEFAULT NULL,
    single_logout_service_url       character varying(1000) DEFAULT NULL,
    signing_certificate             text DEFAULT NULL,
    enabled                         boolean DEFAULT true NOT NULL,
    creation_date                   timestamp DEFAULT CURRENT_TIMESTAMP,
    modify_date                     timestamp DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (realm_id, entity_id)
);
CREATE INDEX IF NOT EXISTS saml_relying_party_realm_idx ON saml_relying_party (realm_id);

-- Helix IAM: the Application (Service Provider) — the protocol-agnostic top-level object (WSO2/Okta
-- model). An OIDC client (service_provider_oauth) and/or a SAML relying party (saml_relying_party) hang
-- below one application via a nullable application_id; shared policy (subject claim, login flow) lives
-- here and applies to whichever protocol the app uses. Partitioned per realm; name unique per realm.
CREATE TABLE IF NOT EXISTS application (
    id              character varying(512) NOT NULL PRIMARY KEY,  -- realmId|name
    realm_id        character varying(255) NOT NULL,
    name            character varying(255) NOT NULL,
    display_name    character varying(255) DEFAULT NULL,  -- human label shown in the UI; name stays the stable id
    description     character varying(1000) DEFAULT NULL,
    subject_claim   character varying(255) DEFAULT NULL,
    auth_flow_alias character varying(255) DEFAULT NULL,
    enabled         boolean DEFAULT true NOT NULL,
    creation_date   timestamp DEFAULT CURRENT_TIMESTAMP,
    modify_date     timestamp DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (realm_id, name)
);
CREATE INDEX IF NOT EXISTS application_realm_idx ON application (realm_id);

-- The protocol records link UP to their application (nullable; no DB FK constraint — the join is a
-- per-realm string key, app-side. Existing rows stay NULL and behave exactly as before until linked).
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS application_id character varying(512) DEFAULT NULL;
ALTER TABLE saml_relying_party     ADD COLUMN IF NOT EXISTS application_id character varying(512) DEFAULT NULL;
-- Human-friendly label for an application, added after the table shipped (existing rows fall back to name).
ALTER TABLE application            ADD COLUMN IF NOT EXISTS display_name character varying(255) DEFAULT NULL;

-- WSO2-class advanced SAML2 options per relying party (all nullable; NULL = the IdP default, so SPs
-- registered before these existed keep behaving exactly as before).
ALTER TABLE saml_relying_party ADD COLUMN IF NOT EXISTS sign_assertion boolean DEFAULT NULL;
ALTER TABLE saml_relying_party ADD COLUMN IF NOT EXISTS sign_response boolean DEFAULT NULL;
ALTER TABLE saml_relying_party ADD COLUMN IF NOT EXISTS want_authn_requests_signed boolean DEFAULT NULL;
ALTER TABLE saml_relying_party ADD COLUMN IF NOT EXISTS want_logout_requests_signed boolean DEFAULT NULL;
ALTER TABLE saml_relying_party ADD COLUMN IF NOT EXISTS encrypt_assertion boolean DEFAULT NULL;
ALTER TABLE saml_relying_party ADD COLUMN IF NOT EXISTS encryption_certificate text DEFAULT NULL;
ALTER TABLE saml_relying_party ADD COLUMN IF NOT EXISTS signature_algorithm character varying(64) DEFAULT NULL;
ALTER TABLE saml_relying_party ADD COLUMN IF NOT EXISTS digest_algorithm character varying(64) DEFAULT NULL;
ALTER TABLE saml_relying_party ADD COLUMN IF NOT EXISTS name_id_format character varying(255) DEFAULT NULL;
ALTER TABLE saml_relying_party ADD COLUMN IF NOT EXISTS include_attributes boolean DEFAULT NULL;
ALTER TABLE saml_relying_party ADD COLUMN IF NOT EXISTS additional_acs_urls text DEFAULT NULL;
ALTER TABLE saml_relying_party ADD COLUMN IF NOT EXISTS extra_audiences text DEFAULT NULL;
ALTER TABLE saml_relying_party ADD COLUMN IF NOT EXISTS extra_recipients text DEFAULT NULL;
ALTER TABLE saml_relying_party ADD COLUMN IF NOT EXISTS back_channel_slo_enabled boolean DEFAULT NULL;
ALTER TABLE saml_relying_party ADD COLUMN IF NOT EXISTS idp_initiated_sso_enabled boolean DEFAULT NULL;
ALTER TABLE saml_relying_party ADD COLUMN IF NOT EXISTS assertion_lifetime_seconds integer DEFAULT NULL;

-- ===========================================================================================
-- IAM GAP PROGRAM — WAVE 1 (critical security): account lockout / brute-force, password policy,
-- breached-password history, CAPTCHA, concurrent-session limits, SCIM/DCR provisioning.
-- All additive: new realm_config columns default to "off" so existing realms behave as before.
-- ===========================================================================================

-- (1) Account lockout / brute-force; (2) password policy; (3) breached-password; (5) CAPTCHA;
-- (17) concurrent-session limits — all per-realm policy on realm_config.
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS lockout_enabled boolean DEFAULT false NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS max_login_failures integer DEFAULT 5 NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS lockout_duration_seconds integer DEFAULT 900 NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS failure_reset_seconds integer DEFAULT 900 NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS permanent_lockout boolean DEFAULT false NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS password_require_uppercase boolean DEFAULT false NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS password_require_lowercase boolean DEFAULT false NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS password_require_digit boolean DEFAULT false NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS password_require_special boolean DEFAULT false NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS password_not_username boolean DEFAULT false NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS password_history_count integer DEFAULT 0 NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS breached_password_check boolean DEFAULT false NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS captcha_provider character varying(32) DEFAULT 'none' NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS captcha_site_key character varying(512) DEFAULT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS captcha_secret_key character varying(512) DEFAULT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS max_concurrent_sessions integer DEFAULT 0 NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS concurrent_session_evict_oldest boolean DEFAULT true NOT NULL;

-- (1) Per-realm, per-user brute-force counter (sliding window + lockout instant).
CREATE TABLE IF NOT EXISTS login_failure (
    id            character varying(36) NOT NULL PRIMARY KEY,
    realm_id      character varying(255) NOT NULL,
    user_id       character varying(255) NOT NULL,
    failure_count integer NOT NULL DEFAULT 0,
    last_failure  timestamp DEFAULT NULL,
    locked_until  timestamp DEFAULT NULL,
    CONSTRAINT uq_login_failure_realm_user UNIQUE (realm_id, user_id)
    );

-- (2/3) Prior password hashes for the no-reuse history rule (stores only Argon2id hashes).
CREATE TABLE IF NOT EXISTS password_history (
    id            character varying(36) NOT NULL PRIMARY KEY,
    user_id       character varying(255) NOT NULL,
    password_hash character varying(512) NOT NULL,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP
    );
CREATE INDEX IF NOT EXISTS password_history_user_idx ON password_history (user_id);

-- (7/11) Per-realm provisioning config: SCIM bearer token (hashed) + DCR open/gated policy.
CREATE TABLE IF NOT EXISTS realm_provisioning_config (
    realm_id        character varying(255) NOT NULL PRIMARY KEY,
    scim_token_hash character varying(128) DEFAULT NULL,
    dcr_open        boolean DEFAULT false NOT NULL
    );

-- (11) Dynamic Client Registration (RFC 7591/7592): client ↔ registration_access_token (hashed).
CREATE TABLE IF NOT EXISTS dcr_registration (
    registration_id         character varying(64) NOT NULL PRIMARY KEY,
    realm_id                character varying(255) NOT NULL,
    client_internal_id      character varying(255) DEFAULT NULL,
    client_id               character varying(255) DEFAULT NULL,
    registration_token_hash character varying(128) DEFAULT NULL
    );
CREATE INDEX IF NOT EXISTS dcr_registration_realm_idx ON dcr_registration (realm_id);

-- (11) DCR initial access tokens (RFC 7591 §1.2): single-use, hashed, consumed on use.
CREATE TABLE IF NOT EXISTS dcr_initial_access_token (
    token_id   character varying(64) NOT NULL PRIMARY KEY,
    realm_id   character varying(255) NOT NULL,
    token_hash character varying(128) DEFAULT NULL
    );
CREATE INDEX IF NOT EXISTS dcr_initial_access_token_realm_idx ON dcr_initial_access_token (realm_id);

-- ===========================================================================================
-- IAM GAP PROGRAM — WAVE 2: Organizations/B2B, fine-grained admin RBAC, Resource Indicators
-- (RFC 8707), risk-based adaptive authentication. All additive; defaults preserve current behaviour.
-- ===========================================================================================

-- (9) Organizations: B2B tenant grouping of users within a realm (Keycloak Organizations / WorkOS-class).
CREATE TABLE IF NOT EXISTS organization (
    org_id        character varying(255) NOT NULL PRIMARY KEY,
    tenant_id     character varying(255) NOT NULL,
    name          character varying(255) NOT NULL,
    display_name  character varying(255) DEFAULT NULL,
    domains       character varying(1024) DEFAULT NULL,
    enabled       boolean NOT NULL DEFAULT true,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id, name),
    FOREIGN KEY(tenant_id) REFERENCES tenant(tenant_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS organization_tenant_idx ON organization (tenant_id);

CREATE TABLE IF NOT EXISTS organization_member (
    id            character varying(255) NOT NULL PRIMARY KEY,
    org_id        character varying(255) NOT NULL,
    user_id       character varying(255) NOT NULL,
    role          character varying(64) NOT NULL DEFAULT 'member',
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (org_id, user_id),
    FOREIGN KEY(org_id) REFERENCES organization(org_id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES user_credentials(user_id) ON DELETE CASCADE
);

-- (19) Fine-grained admin RBAC: realm admin-role → admin-permission grants (permission stored by enum name()).
CREATE TABLE IF NOT EXISTS admin_role_permission (
    id            character varying(36) NOT NULL PRIMARY KEY,
    realm_id      character varying(255) NOT NULL,
    role_id       character varying(255) NOT NULL,
    permission    character varying(64)  NOT NULL,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(role_id) REFERENCES user_roles(role_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS admin_role_permission_realm_idx ON admin_role_permission (realm_id);
CREATE UNIQUE INDEX IF NOT EXISTS admin_role_permission_uq ON admin_role_permission (realm_id, role_id, permission);

-- (18) Resource Indicators (RFC 8707): per-client allow-list of absolute resource URIs the client may
-- request via the `resource` parameter (sets the access-token aud). NULL/blank = no allow-list (any).
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS allowed_resources character varying(2000) DEFAULT NULL;

-- (B11) FAPI completeness. mTLS (RFC 8705): bind access tokens to the client cert (cnf.x5t#S256).
-- JAR (RFC 9101): require the authorization request to be a signed Request Object (request/request_uri).
-- JARM: the JWT-secured authorization response mode (NULL = plain; jwt/query.jwt/fragment.jwt/form_post.jwt).
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS x509_certificate_bound_access_tokens boolean DEFAULT false;
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS require_signed_request_object boolean DEFAULT false;
ALTER TABLE service_provider_oauth ADD COLUMN IF NOT EXISTS jarm_response_mode character varying(32) DEFAULT NULL;

-- (8) Adaptive auth: per-user remembered-device + recent-login-IP history backing the risk signals.
CREATE TABLE IF NOT EXISTS risk_known_device (
    id          character varying(36) NOT NULL PRIMARY KEY,
    realm_id    character varying(255) NOT NULL,
    user_id     character varying(255) NOT NULL,
    fingerprint character varying(128) NOT NULL,
    user_agent  character varying(512) DEFAULT NULL,
    first_seen  timestamp DEFAULT NULL,
    last_seen   timestamp DEFAULT NULL,
    CONSTRAINT uq_risk_known_device UNIQUE (realm_id, user_id, fingerprint)
    );
CREATE INDEX IF NOT EXISTS risk_known_device_realm_user_idx ON risk_known_device (realm_id, user_id);

CREATE TABLE IF NOT EXISTS risk_known_ip (
    id         character varying(36) NOT NULL PRIMARY KEY,
    realm_id   character varying(255) NOT NULL,
    user_id    character varying(255) NOT NULL,
    ip         character varying(64) NOT NULL,
    country    character varying(8) DEFAULT NULL,
    first_seen timestamp DEFAULT NULL,
    last_seen  timestamp DEFAULT NULL,
    CONSTRAINT uq_risk_known_ip UNIQUE (realm_id, user_id, ip)
    );
CREATE INDEX IF NOT EXISTS risk_known_ip_realm_user_idx ON risk_known_ip (realm_id, user_id);

-- (8) Per-realm risk policy on realm_config (default OFF → login unchanged).
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS risk_policy_enabled boolean DEFAULT false NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS risk_medium_threshold integer DEFAULT 40 NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS risk_high_threshold integer DEFAULT 70 NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS risk_low_action character varying(16) DEFAULT 'allow' NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS risk_medium_action character varying(16) DEFAULT 'step_up' NOT NULL;
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS risk_high_action character varying(16) DEFAULT 'deny' NOT NULL;
-- B2: per-realm login theming/branding (all nullable; null → built-in defaults).
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS logo_url character varying(1000);
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS primary_color character varying(32);
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS background_color character varying(32);
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS welcome_text character varying(512);
ALTER TABLE realm_config ADD COLUMN IF NOT EXISTS custom_css text;

-- ===========================================================================================
-- IAM GAP PROGRAM — WAVE 3: GDPR data-subject rights (Art. 7/15/17). i18n, observability,
-- OpenAPI and realm import/export need no schema changes. All additive.
-- ===========================================================================================

-- (16, Art. 7) Per-user, per-client consent ledger. Grants append; withdrawals stamp withdrawn_at
-- (rows are kept for audit). scopes is a comma-joined string.
CREATE TABLE IF NOT EXISTS consent_ledger (
    id            character varying(255) NOT NULL PRIMARY KEY,
    realm_id      character varying(255) NOT NULL,
    user_id       character varying(255) NOT NULL,
    client_id     character varying(255) NOT NULL,
    scopes        character varying(2000) DEFAULT '',
    granted_at    timestamp DEFAULT CURRENT_TIMESTAMP,
    withdrawn_at  timestamp DEFAULT NULL,
    FOREIGN KEY(user_id) REFERENCES user_credentials(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS consent_ledger_realm_user_idx ON consent_ledger (realm_id, user_id);
CREATE INDEX IF NOT EXISTS consent_ledger_active_idx ON consent_ledger (realm_id, user_id, client_id, withdrawn_at);

-- (16, Art. 17) Anonymization marker on the credential (set by the anonymize path; hard-delete removes the row).
ALTER TABLE user_credentials ADD COLUMN IF NOT EXISTS anonymized_at timestamp DEFAULT NULL;

-- ===========================================================================================
-- IAM GAP — B3: persisted + searchable audit log. The publisher emits every audit event to
-- stdout + the SIEM webhook AND (now) over the queue to here, so the console can search/filter
-- login + admin history in-product. Additive; bounded retention is an operator concern.
-- ===========================================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id            character varying(255) NOT NULL PRIMARY KEY,
    occurred_at   timestamp DEFAULT CURRENT_TIMESTAMP,
    ts_iso        character varying(40),
    kind          character varying(32),
    category      character varying(32),
    type          character varying(96),
    realm_id      character varying(255),
    actor         character varying(255),
    source_ip     character varying(64),
    resource_type character varying(96),
    resource_id   character varying(255),
    outcome       character varying(32),
    detail        character varying(2000)
);
CREATE INDEX IF NOT EXISTS audit_log_realm_time_idx ON audit_log (realm_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS audit_log_realm_type_idx ON audit_log (realm_id, type);

-- ===========================================================================================
-- B6: Outbound webhooks / event-listener SPI. Per-realm subscriptions that fan out audit
-- events (HMAC-signed) to external endpoints. The signing secret is encrypted at rest.
-- ===========================================================================================
CREATE TABLE IF NOT EXISTS webhook_subscription (
    id            character varying(255) NOT NULL PRIMARY KEY,
    realm_id      character varying(255) NOT NULL,
    name          character varying(255),
    url           character varying(2000) NOT NULL,
    secret        character varying(4000),
    event_types   character varying(2000) DEFAULT '',
    enabled       boolean DEFAULT true NOT NULL,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS webhook_subscription_realm_idx ON webhook_subscription (realm_id);

-- B1: required actions a user must complete at next login (CSV; null = none).
ALTER TABLE user_credentials ADD COLUMN IF NOT EXISTS required_actions text DEFAULT NULL;

-- B7: per-realm outbound SCIM 2.0 provisioning targets (downstream service providers Helix pushes
-- user lifecycle to). token = bearer credential, stored encrypted at rest.
CREATE TABLE IF NOT EXISTS scim_target (
    id            character varying(255) NOT NULL PRIMARY KEY,
    realm_id      character varying(255) NOT NULL,
    name          character varying(255),
    base_url      character varying(2000) NOT NULL,
    token         character varying(4000),
    event_types   character varying(2000) DEFAULT '',
    enabled       boolean DEFAULT true NOT NULL,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS scim_target_realm_idx ON scim_target (realm_id);

-- WIF: Workload Identity Federation credentials. A trust policy binding an external OIDC token's
-- (issuer, subject, audience) to a Helix client identity so a workload (K8s pod, CI job) can exchange
-- an issuer-signed JWT for a Helix access token with NO client secret. No field is secret → nothing
-- encrypted at rest.
CREATE TABLE IF NOT EXISTS workload_identity_credential (
    id            character varying(255) NOT NULL PRIMARY KEY,
    realm_id      character varying(255) NOT NULL,
    name          character varying(255) NOT NULL,
    issuer        character varying(2000) NOT NULL,
    jwks_uri      character varying(2000),
    subject       character varying(2000) NOT NULL,
    audience      character varying(2000) NOT NULL,
    client_id     character varying(255) NOT NULL,
    scopes        character varying(2000),
    enabled       boolean DEFAULT true NOT NULL,
    creation_date timestamp DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS workload_identity_credential_realm_idx ON workload_identity_credential (realm_id);
CREATE INDEX IF NOT EXISTS workload_identity_credential_resolve_idx ON workload_identity_credential (realm_id, issuer, enabled);

-- Agent / NHI: a first-class non-human identity (automation, service, AI agent) registered in a realm and
-- owned by an accountable human. (realm_id, name) is the natural key. Carries a lifecycle status
-- (ACTIVE | SUSPENDED | EXPIRED | REVOKED) and an auth_method (FEDERATED | SECRET | JWT), and may bind an
-- OIDC client_id for token issuance. Registry record only → no field is secret, nothing encrypted at rest.
CREATE TABLE IF NOT EXISTS agent_identity (
    id           character varying(255) NOT NULL PRIMARY KEY,
    realm_id     character varying(255) NOT NULL,
    name         character varying(255) NOT NULL,
    display_name character varying(255),
    description  character varying(2000),
    owner        character varying(255) NOT NULL,
    status       character varying(32) DEFAULT 'ACTIVE' NOT NULL,
    auth_method  character varying(32) DEFAULT 'SECRET' NOT NULL,
    client_id    character varying(255),
    scopes       character varying(2000),
    roles        character varying(2000),
    created_at   timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at   timestamp,
    last_used_at timestamp,
    enabled      boolean DEFAULT true NOT NULL
);
CREATE INDEX IF NOT EXISTS agent_identity_realm_idx ON agent_identity (realm_id);
CREATE UNIQUE INDEX IF NOT EXISTS agent_identity_realm_name_idx ON agent_identity (realm_id, name);
