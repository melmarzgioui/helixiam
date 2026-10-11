/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.spi;

import java.util.Map;

/**
 * Helix IAM E5.1: a normalized external identity produced by an {@link IdentityProvider}'s callback,
 * independent of protocol (OIDC/SAML2/LDAP/social). The broker maps this to a local user via
 * account-linking + JIT provisioning + attribute mappers.
 *
 * @param idpAlias        the identity provider this identity came from (stable alias)
 * @param externalSubject the provider's stable subject id for the user (the linking key)
 * @param email           the asserted email (may be null)
 * @param emailVerified   whether the provider asserts the email is verified — required before any
 *                        email-based account linking (an unverified email is an account-takeover vector)
 * @param attributes      remaining normalized attributes (username, given_name, family_name, …) — free-form
 *                        and provider-controlled; NEVER trusted as the source of the level of assurance
 *                        (an upstream OIDC IdP's id_token, or a forged eID assertion attribute, could put
 *                        anything under a key like {@code "loa"} here)
 * @param levelOfAssurance the level of assurance of this login, typed and set ONLY by a connector that
 *                        cryptographically verified it against its own scheme's ladder (today only
 *                        {@code EidSamlIdentityProvider}, from the SAML assertion's
 *                        {@code AuthnContextClassRef}); {@code null} when the provider asserted none, or
 *                        cannot be trusted to assert one. This is the ONLY value the federation broker may
 *                        propagate into the ID token {@code acr} — never {@code attributes.get("loa")}.
 */
public record BrokeredIdentity(String idpAlias, String externalSubject, String email,
                               boolean emailVerified, Map<String, String> attributes, String levelOfAssurance) {

    /** Compatibility constructor for providers that never assert a (trusted) level of assurance. */
    public BrokeredIdentity(final String idpAlias, final String externalSubject, final String email,
                            final boolean emailVerified, final Map<String, String> attributes) {
        this(idpAlias, externalSubject, email, emailVerified, attributes, null);
    }
}
