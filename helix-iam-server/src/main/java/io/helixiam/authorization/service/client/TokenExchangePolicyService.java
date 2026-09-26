/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.client;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 1.0 item 5: the RFC 8693 token-exchange target policy. A client can be the {@code audience} of an exchanged
 * token only if it exists in the realm and lists the requesting client among the clients allowed to exchange
 * to it (default: none).
 */
@Service
public class TokenExchangePolicyService {

    private final ServiceProviderRepository repository;

    public TokenExchangePolicyService(final ServiceProviderRepository repository) {
        this.repository = repository;
    }

    /** The clients allowed to exchange to {@code targetClientId}; empty if the target does not exist. */
    public Optional<Set<String>> allowedClients(final String realmId, final String targetClientId) {
        return target(realmId, targetClientId).map(c -> parse(c.getTokenExchangeAllowedClients()));
    }

    @Transactional
    public Optional<Set<String>> replace(final String realmId, final String targetClientId, final Set<String> allowed) {
        return target(realmId, targetClientId).map(c -> {
            final Set<String> clean = allowed == null ? Set.of() : allowed.stream()
                    .filter(s -> s != null && !s.isBlank()).map(String::trim)
                    .collect(Collectors.toCollection(LinkedHashSet::new));
            c.setTokenExchangeAllowedClients(clean.isEmpty() ? null : String.join(",", clean));
            repository.save(c);
            return clean;
        });
    }

    /** The decision for one exchange: the target must exist and allow the requester. */
    public Decision decide(final String realmId, final String requesterClientId, final String targetClientId) {
        final Optional<Set<String>> allowed = allowedClients(realmId, targetClientId);
        if (allowed.isEmpty()) {
            return Decision.UNKNOWN_TARGET;
        }
        return allowed.get().contains(requesterClientId) ? Decision.ALLOWED : Decision.NOT_ALLOWED;
    }

    private Optional<ServiceProviderOAuthClient> target(final String realmId, final String clientId) {
        if (realmId == null || clientId == null || clientId.isBlank()) {
            return Optional.empty();
        }
        return repository.findByClientIdAndRealmIdAndDeleted(clientId, realmId, false);
    }

    private static Set<String> parse(final String joined) {
        if (joined == null || joined.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(joined.split(",")).map(String::trim).filter(s -> !s.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    public enum Decision { ALLOWED, NOT_ALLOWED, UNKNOWN_TARGET }
}
