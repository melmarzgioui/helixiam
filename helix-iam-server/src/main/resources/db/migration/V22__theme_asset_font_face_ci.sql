-- Review M3: CSS matches font-family names ASCII case-insensitively, so "Inter" and "inter" are one family in the
-- browser. A realm's font faces are therefore unique on (realm, lower(name), weight, style); the application also
-- refuses a second spelling of an existing family.
DROP INDEX IF EXISTS theme_asset_font_face_uq;
CREATE UNIQUE INDEX IF NOT EXISTS theme_asset_font_face_ci_uq
    ON theme_asset (realm_id, lower(name), font_weight, font_style) WHERE kind = 'font';
