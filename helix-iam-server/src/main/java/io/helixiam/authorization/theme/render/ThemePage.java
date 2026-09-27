/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.render;

import java.util.List;

/**
 * What the shared page fragment ({@code templates/fragments/theme.html}) needs to brand a user-facing page, resolved
 * for one realm, organization (when in context) and locale. Every value is plain data that the templates escape
 * ({@code th:text}/{@code th:href}/{@code th:src}); URLs have been re-checked (https, or the realm's own uploaded
 * asset) and anything else is dropped.
 *
 * <p>Text fields: {@code null} means "use the built-in message"; an empty string means "show nothing".
 *
 * @param realmId         the realm whose {@code theme.css} the page links
 * @param orgId           the organization in context (added as {@code ?org=}), or null
 * @param orgName         the organization's display name, or null
 * @param cssVersion      cache-busting version of the realm's {@code theme.css} ({@code ?v=})
 * @param preview         only for the admin preview: the stylesheet inlined and its per-response CSP; null otherwise
 * @param layout          {@code split} (brand panel + form) or {@code centered} (form only)
 * @param branded         true when the theme sets a logo or anything else above the HelixIAM default (the HelixIAM
 *                        wordmark, favicon and artwork are then hidden)
 * @param brandName       the name for titles and the logo's alt text: the organization, the realm's display name
 *                        when branded, {@code HelixIAM} when not branded, or empty
 * @param badges          brand badges; null = the built-in ones, empty = none
 * @param locales         language-switcher entries (empty = no switcher)
 */
public record ThemePage(String realmId, String orgId, String orgName, String cssVersion, Preview preview,
                        String layout, boolean branded, String brandName,
                        String logoUrl, String logoDarkUrl, String faviconUrl, String brandImageUrl,
                        String themeColorLight, String themeColorDark,
                        String brandHeadline, String brandSubhead, String brandByline, String welcomeText,
                        String footerText, List<String> badges,
                        String privacyUrl, String termsUrl, String supportUrl,
                        List<LocaleOption> locales) {

    /**
     * The admin preview ({@code POST /admin/realms/{realm}/theme/preview}) renders the page with a proposed theme that
     * is not saved, so it cannot link {@code theme.css}: the stylesheet travels in the page as a {@code data:} URL,
     * allowed by a per-response CSP nonce. The page also carries that CSP in a {@code <meta>} tag (so it holds when
     * the console shows the HTML in an {@code iframe srcdoc}) and a {@code <base>} pointing at the server, so the base
     * stylesheets and assets load from HelixIAM whatever document embeds the preview.
     */
    public record Preview(String cssDataUrl, String nonce, String csp, String baseHref) {
    }

    /** A language-switcher entry. */
    public record LocaleOption(String tag, String label, boolean current) {
    }

    /** True for the split layout (brand panel next to the form). */
    public boolean split() {
        return !"centered".equals(layout);
    }

    /** True when the page footer has something to show (a footer text or a legal/support link). */
    public boolean hasFooter() {
        return (footerText != null && !footerText.isEmpty()) || privacyUrl != null || termsUrl != null
                || supportUrl != null;
    }

    /** The document title for a page called {@code page}: "{brandName} — {page}", or just the page. */
    public String title(final String page) {
        return brandName == null || brandName.isEmpty() ? page : brandName + " — " + page;
    }

    /** A copy for the preview endpoint (see {@link Preview}). */
    public ThemePage withPreview(final Preview value) {
        return new ThemePage(realmId, orgId, orgName, cssVersion, value, layout, branded, brandName, logoUrl,
                logoDarkUrl, faviconUrl, brandImageUrl, themeColorLight, themeColorDark, brandHeadline, brandSubhead,
                brandByline, welcomeText, footerText, badges, privacyUrl, termsUrl, supportUrl, locales);
    }
}
