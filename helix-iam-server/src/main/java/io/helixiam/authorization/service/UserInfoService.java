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
    public UserInfoService(final UserPublisher userPublisher, @Value("${mapping.oidc.file}") final String oidcMappingFile) {
        this.userPublisher = userPublisher;
        loadOidcClaimMapping(oidcMappingFile);
    }

    public Map<String, String> getOidcClaimProfile(final String userId) {
        final Map<String, String> claims = userPublisher.getClaimProfile(userId);
        final Map<String, String> oidcClaims = new HashMap<>();

        claims.forEach((key, value) -> {
            final String oidcClaimKey = claimMapping.getOrDefault(key, value); // If no mapping, keep the original key
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
