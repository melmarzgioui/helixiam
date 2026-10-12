/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account.console;

import io.helixiam.authorization.amqp.account.AccountIdentityPublisher;
import io.helixiam.authorization.amqp.account.FederatedLinkDto;
import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Task 21b: the EU Digital Identity Wallet providers of the account console. The provider registry is keyed by alias
 * only (spec conflict 6), so a wallet provider belongs to the request's realm only when it serves it
 * ({@link WalletIdentityProvider#servesRealm}: a YAML provider every realm, a stored one only its own); anything else
 * is "not found" here. Each row says whether the user has linked a wallet through that provider; never the link's
 * subject (a hash).
 */
@Component
public class AccountWallets {

    private final IdentityProviderRegistry registry;
    private final AccountIdentityPublisher identities;

    public AccountWallets(final IdentityProviderRegistry registry, final AccountIdentityPublisher identities) {
        this.registry = registry;
        this.identities = identities;
    }

    /**
     * One wallet provider of the realm, for the console.
     *
     * @param alias       the provider alias (the form value)
     * @param displayName its name, as on the login page
     * @param linked      the user has a wallet linked through it
     */
    public record Row(String alias, String displayName, boolean linked) {
    }

    /** The wallet provider {@code alias} if it is one and serves {@code realm}. */
    public Optional<WalletIdentityProvider> provider(final String realm, final String alias) {
        if (realm == null || alias == null || alias.isBlank()) {
            return Optional.empty();
        }
        try {
            return WalletIdentityProvider.from(registry.get(alias)).filter(p -> p.servesRealm(realm));
        } catch (final IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /** The realm's wallet providers, in login-page order, each with whether {@code userId} linked a wallet. */
    public List<Row> rows(final String realm, final String userId) {
        final List<WalletIdentityProvider> providers = registry.aliases().stream()
                .map(alias -> provider(realm, alias)).flatMap(Optional::stream).toList();
        if (providers.isEmpty()) {
            return List.of();
        }
        final Set<String> linked = linkedAliases(userId);
        return providers.stream().map(p -> new Row(p.config().alias(), p.metadata().displayName(),
                linked.contains(p.config().alias()))).toList();
    }

    /** Whether {@code userId} has a wallet linked through {@code alias}. */
    public boolean isLinked(final String userId, final String alias) {
        return linkedAliases(userId).contains(alias);
    }

    private Set<String> linkedAliases(final String userId) {
        final List<FederatedLinkDto> links = userId == null ? null : identities.list(userId);
        return links == null ? Set.of() : links.stream().map(FederatedLinkDto::idpAlias).filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }
}
