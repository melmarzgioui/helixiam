/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.oidc;

import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Discovery metadata for the session features: {@code claims_supported} (including {@code auth_time} and
 * {@code sid}, which every ID token carries) and OIDC Back-Channel Logout 1.0 support with {@code sid}
 * ({@code backchannel_logout_supported}, {@code backchannel_logout_session_supported}). Claims already listed
 * by another customizer are kept. Values are stored as mutable collections (SAS's Jackson allowlist rejects
 * immutable ones).
 */
public final class SessionMetadataCustomizer implements Consumer<OidcProviderConfiguration.Builder> {

    /** Protocol claims in ID tokens, the standard OIDC profile claims, and HelixIAM's role/org claims. */
    static final List<String> CLAIMS = List.of(
            "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid", "azp",
            "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username",
            "email", "email_verified", "profile", "picture", "website", "gender", "birthdate",
            "zoneinfo", "locale", "updated_at", "phone_number", "phone_number_verified",
            "realm_access", "resource_access", "organizations");

    @Override
    public void accept(final OidcProviderConfiguration.Builder builder) {
        builder.claims(claims -> {
            final Set<String> supported = new LinkedHashSet<>();
            if (claims.get("claims_supported") instanceof Collection<?> existing) {
                existing.forEach(c -> supported.add(String.valueOf(c)));
            }
            supported.addAll(CLAIMS);
            claims.put("claims_supported", new ArrayList<>(supported));
            claims.put("backchannel_logout_supported", Boolean.TRUE);
            claims.put("backchannel_logout_session_supported", Boolean.TRUE);
        });
    }
}
