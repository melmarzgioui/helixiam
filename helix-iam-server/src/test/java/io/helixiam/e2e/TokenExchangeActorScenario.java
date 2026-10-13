/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.LongSupplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * RFC 8693 delegation (an {@code actor_token}) is not supported on {@code /oauth2/token}: HelixIAM's delegation is
 * {@code /agent/delegation/token}. Spring Security 7 can store an exchange with an actor (Spring Authorization Server
 * 1.5 could not), and HelixIAM's {@code act} claim would name the requesting client, not the actor. A token exchange
 * carrying {@code actor_token} or {@code actor_token_type} is therefore refused with {@code invalid_request} before
 * anything is issued or stored; an exchange without an actor (impersonation) works as before. Shared by the queue
 * ({@link TokenExchangeActorRefusedE2eTest}) and Redis ({@link TokenExchangeActorRefusedRedisE2eTest}) token stores.
 */
final class TokenExchangeActorScenario {

    static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    private static final String PASSWORD = "Actor-Refused-Passw0rd!";

    private final Function<String, OidcFlow> oidc;
    private final LongSupplier storedAuthorizations;
    private final String realm;
    private final E2eSeed.SeededClient web;
    private final String joeToken;
    private final String ledgerToken;

    TokenExchangeActorScenario(final E2eSeed seed, final Function<String, OidcFlow> oidc,
                               final LongSupplier storedAuthorizations) {
        this.oidc = oidc;
        this.storedAuthorizations = storedAuthorizations;
        realm = E2eSeed.unique("actor");
        seed.realm(realm);
        web = seed.client(realm, "web", List.of("authorization_code", "refresh_token", TOKEN_EXCHANGE),
                List.of(E2eSeed.REDIRECT_URI), List.of("openid", "profile"), false);
        final E2eSeed.SeededClient ledger = seed.serviceAccountClient(realm, "ledger", List.of("openid"));
        final E2eSeed.SeededUser joe = seed.user(realm, E2eSeed.unique("joe"), PASSWORD);
        joeToken = oidc.apply(realm).authorizationCode("web", web.secret(), web.redirectUri(), joe.username(), PASSWORD,
                "openid profile").accessToken();
        ledgerToken = oidc.apply(realm).clientCredentials("ledger", ledger.secret(), "openid").accessToken();
    }

    void anActorToken_isInvalidRequest_andNothingIsStored() {
        final long before = storedAuthorizations.getAsLong();

        final E2eHttp.Response withActor = exchange(Map.of("actor_token", ledgerToken,
                "actor_token_type", ACCESS_TOKEN_TYPE));
        final E2eHttp.Response typeOnly = exchange(Map.of("actor_token_type", ACCESS_TOKEN_TYPE));
        final E2eHttp.Response tokenOnly = exchange(Map.of("actor_token", ledgerToken));

        for (final E2eHttp.Response r : List.of(withActor, typeOnly, tokenOnly)) {
            assertThat(r.status()).as(r.toString()).isEqualTo(400);
            assertThat(r.json().path("error").asText()).isEqualTo("invalid_request");
            assertThat(r.json().has("access_token")).isFalse();
        }
        assertThat(storedAuthorizations.getAsLong()).as("nothing stored").isEqualTo(before);
    }

    void anExchangeWithoutAnActor_stillWorks() {
        final long before = storedAuthorizations.getAsLong();

        final E2eHttp.Response r = exchange(Map.of());

        assertThat(r.status()).as(r.toString()).isEqualTo(200);
        assertThat(OidcFlow.claims(r.json().path("access_token").asText()).get("act")).isEqualTo(Map.of("sub", "web"));
        assertThat(storedAuthorizations.getAsLong()).isEqualTo(before + 1);
    }

    private E2eHttp.Response exchange(final Map<String, String> extra) {
        final Map<String, String> form = new HashMap<>(Map.of("grant_type", TOKEN_EXCHANGE, "subject_token", joeToken,
                "subject_token_type", ACCESS_TOKEN_TYPE));
        form.putAll(extra);
        return oidc.apply(realm).tokenEndpoint("web", web.secret(), form);
    }
}
