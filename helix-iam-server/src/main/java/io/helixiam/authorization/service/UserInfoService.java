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
import java.util.HashSet;
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

    private final UserPublisher userPublisher;
    private final Map<String, String> claimMapping = new HashMap<>();

    private final ObjectMapper objectMapper = new ObjectMapper();


    @Autowired
    private io.helixiam.authorization.repository.UserCredentialsRepository users;

    @Autowired(required = false)
    public void setUsers(final io.helixiam.authorization.repository.UserCredentialsRepository users) {
        this.users = users;
    }

    /** Review rc.3 #4: whether the user's current email address is verified. */
    public boolean emailVerified(final String userId) {
        return users != null && userId != null && users.findByUserId(userId).map(
                io.helixiam.authorization.domain.user.UserCredentials::isEmailVerified).orElse(false);
    }

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
            if (io.helixiam.authorization.security.claims.ReservedClaims.isReserved(oidcClaimKey)) {
                LOG.warn("Dropping user attribute mapped to reserved claim '" + oidcClaimKey + "' (claim injection guard)");
                return;
            }
            oidcClaims.put(oidcClaimKey, value);
        });

        return oidcClaims;

    }


    /**
     * The subset of a claim profile that may be copied into a token directly: only the STANDARD OIDC profile
     * claims configured in the claim-mapping file (email, given_name, preferred_username, …), never reserved
     * claims and never arbitrary user attributes. Custom attributes reach a token only through an explicitly
     * configured protocol mapper.
     */
    public Map<String, String> standardClaims(final Map<String, String> profile) {
        final Map<String, String> out = new HashMap<>();
        if (profile == null) {
            return out;
        }
        final Set<String> standard = new HashSet<>(claimMapping.values());
        profile.forEach((k, v) -> {
            if (standard.contains(k) && !io.helixiam.authorization.security.claims.ReservedClaims.isReserved(k)) {
                out.put(k, v);
            }
        });
        return out;
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
