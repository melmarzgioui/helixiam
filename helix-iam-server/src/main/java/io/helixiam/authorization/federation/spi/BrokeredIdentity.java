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
 * @param attributes      remaining normalized attributes (username, given_name, family_name, …)
 */
public record BrokeredIdentity(String idpAlias, String externalSubject, String email,
                               boolean emailVerified, Map<String, String> attributes) {
}
