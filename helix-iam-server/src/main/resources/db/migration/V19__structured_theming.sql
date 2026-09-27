-- Structured theming (spec §1, §7): one validated theme layer per realm and per organization, stored as the
-- canonical JSON of the Theme model (colours, typography, shape, assets, layout, texts, links and the restricted
-- custom-CSS escape hatch). Never raw CSS apart from the validated customCss inside it. The legacy branding columns
-- (realm_config.logo_url/primary_color/background_color/welcome_text/custom_css, organization.logo_url/primary_color)
-- are moved into these tables by the Java migration V20 and are no longer read.
CREATE TABLE IF NOT EXISTS realm_theme (
    realm_id   character varying(255) NOT NULL PRIMARY KEY,
    theme_json text NOT NULL,
    updated_at timestamp DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (realm_id) REFERENCES realm_config(realm_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS organization_theme (
    org_id     character varying(255) NOT NULL PRIMARY KEY,
    realm_id   character varying(255) NOT NULL,
    theme_json text NOT NULL,
    updated_at timestamp DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organization(org_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS organization_theme_realm_idx ON organization_theme (realm_id);
