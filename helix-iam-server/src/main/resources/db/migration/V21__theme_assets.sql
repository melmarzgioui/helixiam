-- Structured theming, fonts and assets (spec §3): fonts (woff2) and images (svg, png, webp) uploaded through the
-- admin API and served from /realms/{realm}/theme/assets/{id}.{ext}. The bytes are stored here (bytea) behind the
-- ThemeAssetStore interface; every lookup is scoped to realm_id. The upload rules (magic bytes, size limits, SVG
-- validation, per-realm counts) are enforced by the application; the constraints below are a backstop.
CREATE TABLE IF NOT EXISTS theme_asset (
    asset_id     character varying(64)  NOT NULL PRIMARY KEY,
    realm_id     character varying(255) NOT NULL,
    kind         character varying(16)  NOT NULL,
    name         character varying(64)  NOT NULL,
    extension    character varying(8)   NOT NULL,
    content_type character varying(64)  NOT NULL,
    font_weight  character varying(16),
    font_style   character varying(16),
    size_bytes   integer NOT NULL,
    sha256       character varying(64)  NOT NULL,
    content      bytea NOT NULL,
    created_at   timestamp DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (realm_id) REFERENCES realm_config(realm_id) ON DELETE CASCADE,
    CONSTRAINT theme_asset_kind_chk CHECK (kind IN ('font', 'image')),
    CONSTRAINT theme_asset_extension_chk CHECK ((kind = 'font' AND extension = 'woff2')
        OR (kind = 'image' AND extension IN ('svg', 'png', 'webp'))),
    CONSTRAINT theme_asset_size_chk CHECK (size_bytes > 0 AND size_bytes <= 524288)
);
CREATE INDEX IF NOT EXISTS theme_asset_realm_idx ON theme_asset (realm_id, kind);
CREATE UNIQUE INDEX IF NOT EXISTS theme_asset_font_face_uq ON theme_asset (realm_id, name, font_weight, font_style)
    WHERE kind = 'font';
