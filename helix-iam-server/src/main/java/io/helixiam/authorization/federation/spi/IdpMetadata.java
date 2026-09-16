/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.spi;

/**
 * Helix IAM E5.1: descriptor for an {@link IdentityProvider} — its stable alias, protocol, and a
 * display name for the login page / admin console. The registry keys providers by {@link #alias()}.
 *
 * <p>Presentation (E6-login-branding): {@code iconKey} names the built-in brand mark to render on the
 * login button (e.g. {@code digid}, {@code eherkenning}, {@code eidas}, {@code oidc}, {@code saml}) and
 * {@code logoUrl} is an admin-set custom logo that, when present, overrides the built-in mark. Both are
 * nullable — a provider with neither renders as a plain text button.</p>
 */
public record IdpMetadata(String alias, Protocol protocol, String displayName, String iconKey, String logoUrl) {

    public enum Protocol { OIDC, SAML2, LDAP, SOCIAL }

    /** Bare metadata with no presentation hints (icon/logo resolved elsewhere, or a plain text button). */
    public static IdpMetadata of(final String alias, final Protocol protocol, final String displayName) {
        return new IdpMetadata(alias, protocol, displayName, null, null);
    }

    /** Metadata carrying the login-button presentation (built-in {@code iconKey} and/or a custom {@code logoUrl}). */
    public static IdpMetadata of(final String alias, final Protocol protocol, final String displayName,
                                 final String iconKey, final String logoUrl) {
        return new IdpMetadata(alias, protocol, displayName, iconKey, logoUrl);
    }

    /** This metadata with its presentation (icon key + custom logo) replaced — used to enrich a broker's metadata. */
    public IdpMetadata withPresentation(final String iconKey, final String logoUrl) {
        return new IdpMetadata(alias, protocol, displayName, iconKey, logoUrl);
    }
}
