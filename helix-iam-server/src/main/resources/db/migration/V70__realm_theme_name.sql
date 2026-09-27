-- File themes (structured theming spec §5): the file theme from helix.theme.directory that a realm uses as its
-- base layer. Database theme fields override the file's values. NULL = no file theme.
ALTER TABLE realm_theme ADD COLUMN IF NOT EXISTS theme_name character varying(64);
