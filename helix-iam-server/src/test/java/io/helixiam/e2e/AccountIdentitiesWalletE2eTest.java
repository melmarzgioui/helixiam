/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import io.helixiam.authorization.federation.wallet.WalletLinkService;
import io.helixiam.authorization.federation.wallet.WalletSubject;
import io.helixiam.authorization.service.federation.FederatedLinkService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Task 21b fix round 1 (I1): the JSON account API ({@code /account/identities}, B9) and wallet links. A wallet link is
 * a security setting managed in the account console's wallet section (step-up, audit, unlink-all): the JSON list leaves
 * wallet providers out (their subjects are HMAC hashes), and deleting a wallet alias there is a 409 that changes
 * nothing. Other providers behave as before.
 */
class AccountIdentitiesWalletE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Identities-Passw0rd-2026!";

    private String realm;
    private String walletAlias;
    private String oidcAlias;
    private E2eSeed.SeededUser ada;
    private E2eAdminSession session;
    private WalletSubject.AdminNumber number;
    private WalletSubject.Tuple tuple;

    @BeforeEach
    void setUp() {
        final WalletE2eFixture wallet = new WalletE2eFixture(context);
        realm = E2eSeed.unique("ident");
        seed().realm(realm);
        walletAlias = E2eSeed.unique("eudi-ident");
        wallet.install(realm, wallet.storedProvider(realm, walletAlias, Map.of("subject.acknowledgeWeakSubject", "true")));
        oidcAlias = E2eSeed.unique("oidc-ident");
        ada = seed().user(realm, E2eSeed.unique("ada"), PASSWORD);

        final WalletLinkService links = context.getBean(WalletLinkService.class);
        number = new WalletSubject.AdminNumber(hex(), null);
        tuple = new WalletSubject.Tuple(hex());
        assertThat(links.link(realm, ada.userId(), walletAlias, number)).isEqualTo(WalletLinkService.LinkResult.LINKED);
        assertThat(links.link(realm, ada.userId(), walletAlias, tuple)).isEqualTo(WalletLinkService.LinkResult.LINKED);
        context.getBean(FederatedLinkService.class).link(oidcAlias, "oidc-sub-" + UUID.randomUUID(), ada.userId());
        session = E2eAdminSession.login(newBrowser(), realm, ada.username(), PASSWORD);
    }

    @Test
    void theList_leavesWalletProvidersOut_butStillListsOtherProviders() {
        final E2eHttp.Response list = session.get("/realms/" + realm + "/account/identities");

        assertThat(list.status()).as(list.toString()).isEqualTo(200);
        final List<String> aliases = list.json().findValuesAsText("idpAlias");
        assertThat(aliases).contains(oidcAlias).doesNotContain(walletAlias);
        assertThat(list.body()).doesNotContain(number.value()).doesNotContain(tuple.value());
    }

    @Test
    void deletingAWalletAlias_is409_andBothWalletLinksStay() {
        final E2eHttp.Response delete = session.delete("/realms/" + realm + "/account/identities/" + walletAlias);

        assertThat(delete.status()).as(delete.toString()).isEqualTo(409);
        assertThat(delete.json().path("message").asText()).contains("account console");
        final WalletLinkService links = context.getBean(WalletLinkService.class);
        assertThat(links.find(realm, walletAlias, number)).contains(ada.userId());
        assertThat(links.find(realm, walletAlias, tuple)).contains(ada.userId());
    }

    @Test
    void deletingAnOidcAlias_stillWorks() {
        final E2eHttp.Response delete = session.delete("/realms/" + realm + "/account/identities/" + oidcAlias);

        assertThat(delete.status()).as(delete.toString()).isEqualTo(204);
        assertThat(session.get("/realms/" + realm + "/account/identities").json().findValuesAsText("idpAlias"))
                .doesNotContain(oidcAlias);
    }

    /**
     * Production readiness item 5: the alias is resolved in the user's own realm first. Realm A has an OIDC connection
     * with the alias of the user's OIDC link, and another realm has a WALLET connection of that same alias; the user's
     * OIDC link is still listed and can still be disconnected.
     */
    @Test
    void anotherRealmsWalletWithTheSameAlias_doesNotHideOrLockThisRealmsOidcLink() {
        final Map<String, String> oidc = new java.util.LinkedHashMap<>();
        oidc.put("clientId", "helix");
        oidc.put("clientSecret", "account-identities-" + "secret");
        oidc.put("issuer", "https://upstream.example");
        oidc.put("authorizationEndpoint", "https://upstream.example/authorize");
        oidc.put("tokenEndpoint", "https://upstream.example/token");
        oidc.put("jwksUri", "https://upstream.example/jwks");
        final Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("alias", oidcAlias);
        body.put("protocol", "oidc");
        body.put("displayName", "Corp SSO");
        body.put("enabled", true);
        body.put("config", oidc);
        final E2eHttp.Response created = adminSession().post("/admin/realms/" + realm + "/identity-providers", body);
        assertThat(created.status()).as(created.toString()).isEqualTo(201);
        final String otherRealm = E2eSeed.unique("ident-other");
        seed().realm(otherRealm);
        final WalletE2eFixture wallet = new WalletE2eFixture(context);
        wallet.install(otherRealm, wallet.storedProvider(otherRealm, oidcAlias, Map.of()));

        assertThat(session.get("/realms/" + realm + "/account/identities").json().findValuesAsText("idpAlias"))
                .contains(oidcAlias);
        final E2eHttp.Response delete = session.delete("/realms/" + realm + "/account/identities/" + oidcAlias);
        assertThat(delete.status()).as(delete.toString()).isEqualTo(204);
    }

    private static String hex() {
        final byte[] bytes = new byte[32];
        new java.security.SecureRandom().nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }
}
