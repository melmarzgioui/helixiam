/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.web;

import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.security.realm.RealmContextHolder;

import java.util.Objects;
import java.util.Optional;

/**
 * Task 18: the realm checks every wallet endpoint makes (spec conflict 6: the provider registry is keyed by alias, not
 * realm). A provider is served under the request's realm ({@link RealmContextHolder}) only when it is a wallet provider
 * and its {@link WalletIdentityProvider#keyRealm()} is {@code null} (YAML, every realm) or that realm; a transaction
 * only when its own realm and provider are the request's. Anything else is "not found".
 */
final class WalletEndpoints {

    private WalletEndpoints() {
    }

    /** The wallet provider {@code alias} if it serves the current realm. */
    static Optional<WalletIdentityProvider> provider(final IdentityProviderRegistry registry, final String alias) {
        final String realm = RealmContextHolder.get();
        if (realm == null || alias == null) {
            return Optional.empty();
        }
        try {
            return WalletIdentityProvider.from(registry.get(realm, alias)).filter(p -> p.servesRealm(realm));
        } catch (final IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /** Whether {@code tx} belongs to the current realm and to {@code provider}. */
    static boolean ownedHere(final WalletTransaction tx, final WalletIdentityProvider provider) {
        return tx != null && Objects.equals(tx.realmId(), RealmContextHolder.get())
                && Objects.equals(tx.providerAlias(), provider.config().alias());
    }
}
