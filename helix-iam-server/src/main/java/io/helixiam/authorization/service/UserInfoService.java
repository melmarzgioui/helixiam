/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.amqp.user.UserPublisher;

import java.io.IOException;
import java.util.HashMap;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class UserInfoService {

    private static final Log LOG = LogFactory.getLog(UserInfoService.class);

    /**
     * Reserved token claims a user profile must NEVER set — they convey identity, audience, expiry or
     * authority. Allowing a user-controlled attribute to land on any of these would let a user forge their
     * subject/roles/audience (claim injection). Standard profile claims (email, name, …) are intentionally
     * NOT reserved. The per-client subject-claim override (admin config) remains the only way to change `sub`.
     */
    private static final Set<String> RESERVED_CLAIMS = Set.of(
            "sub", "iss", "aud", "exp", "iat", "nbf", "jti", "azp", "auth_time", "nonce",
            "at_hash", "c_hash", "s_hash", "sid", "typ", "cnf",
            "scope", "scp", "client_id", "roles", "realm_access", "resource_access",
            "nhi", "act", "may_act", "agent_id", "agent_name", "agent_scope",
            "wif", "workload_iss", "workload_sub", "organizations");

    private final UserPublisher userPublisher;
    private final Map<String, String> claimMapping = new HashMap<>();

    private final ObjectMapper objectMapper = new ObjectMapper();


    @Autowired
    public UserInfoService(final UserPublisher userPublisher, @Value("${mapping.oidc.file}") final String oidcMappingFile) {
        this.userPublisher = userPublisher;
        loadOidcClaimMapping(oidcMappingFile);
    }

    public Map<String, String> getOidcClaimProfile(final String userId) {
        final Map<String, String> claims = userPublisher.getClaimProfile(userId);
        final Map<String, String> oidcClaims = new HashMap<>();

        claims.forEach((key, value) -> {
            // Map the attribute NAME to its configured OIDC claim; with no mapping keep the original KEY.
            // (A prior bug used the attribute VALUE as the fallback, so an unmapped attribute's value became
            //  the claim name — user-controlled claim injection. Never do that.)
            final String oidcClaimKey = claimMapping.getOrDefault(key, key);
            // Security: user profile attributes may never set a reserved identity/authority claim.
            if (RESERVED_CLAIMS.contains(oidcClaimKey)) {
                LOG.warn("Dropping user attribute mapped to reserved claim '" + oidcClaimKey + "' (claim injection guard)");
                return;
            }
            oidcClaims.put(oidcClaimKey, value);
        });

        return oidcClaims;

    }


    private void loadOidcClaimMapping(final String oidcMappingFile) {
        try {
            // Load the JSON file from the classpath (resources directory)
            final ClassPathResource resource = new ClassPathResource(oidcMappingFile);
            // Parse the JSON file into a Map
            final Map<String, String> mapping = objectMapper.readValue(resource.getInputStream(), new TypeReference<>() {});
            claimMapping.putAll(mapping);
        } catch (IOException e) {
            LOG.error("Error loading oidc claim mapping", e);
        }
    }
}
