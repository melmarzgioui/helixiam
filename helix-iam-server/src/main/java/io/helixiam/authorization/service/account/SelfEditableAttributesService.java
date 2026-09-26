/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.account;

import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.repository.realm.RealmConfigRepository;
import io.helixiam.authorization.security.claims.ReservedClaims;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 1.0 security (item 1): the per-realm, admin-managed allowlist of profile attributes a user may edit through
 * the self-service Account API. Empty by default — every other attribute is admin-only. Reserved claim names
 * (sub, iss, aud, roles, …) can never be allowlisted.
 */
@Service
public class SelfEditableAttributesService {

    private final RealmConfigRepository realms;

    public SelfEditableAttributesService(final RealmConfigRepository realms) {
        this.realms = realms;
    }

    /** The realm's allowlist (empty when the realm is unknown or nothing is allowlisted). */
    @Transactional(readOnly = true)
    public Set<String> allowed(final String realmId) {
        return realms.findById(realmId).map(RealmConfig::getSelfEditableAttributes).map(SelfEditableAttributesService::parse)
                .orElseGet(Set::of);
    }

    /** Replaces the allowlist. Empty result when the realm does not exist. Callers reject reserved names first. */
    @Transactional
    public Optional<Set<String>> replace(final String realmId, final Set<String> attributes) {
        return realms.findById(realmId).map(cfg -> {
            final Set<String> clean = attributes == null ? Set.of() : attributes.stream()
                    .filter(a -> a != null && !a.isBlank()).map(String::trim)
                    .collect(Collectors.toCollection(LinkedHashSet::new));
            cfg.setSelfEditableAttributes(clean.isEmpty() ? null : String.join(",", clean));
            realms.save(cfg);
            return clean;
        });
    }

    /** Any reserved claim names among {@code attributes}. */
    public static Set<String> reserved(final Set<String> attributes) {
        return attributes == null ? Set.of() : attributes.stream().filter(ReservedClaims::isReserved)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private static Set<String> parse(final String csv) {
        return csv == null || csv.isBlank() ? Set.of() : Arrays.stream(csv.split(","))
                .map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toCollection(LinkedHashSet::new));
    }
}
