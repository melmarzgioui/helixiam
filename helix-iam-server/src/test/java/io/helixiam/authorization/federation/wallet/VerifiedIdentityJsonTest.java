/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The stored shape of a wallet login's mapped identity ({@code WalletTransaction.verifiedIdentityJson}). */
class VerifiedIdentityJsonTest {

    @Test
    void roundTripsEveryMember() {
        final Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("given_name", "Erika");
        attributes.put("family_name", "Mustermann");
        final BrokeredIdentity identity = new BrokeredIdentity("eudi-wallet", "DE/PAN-0001", "erika@example.eu", true,
                attributes, "http://eidas.europa.eu/LoA/high");

        final BrokeredIdentity read = VerifiedIdentityJson.read("eudi-wallet", VerifiedIdentityJson.write(identity));

        assertThat(read).isEqualTo(identity);
    }

    @Test
    void roundTripsAbsentOptionalMembers() {
        final BrokeredIdentity identity = new BrokeredIdentity("eudi-wallet", "sub-1", null, false, Map.of(), null);

        assertThat(VerifiedIdentityJson.read("eudi-wallet", VerifiedIdentityJson.write(identity))).isEqualTo(identity);
    }

    @Test
    void theAliasComesFromTheReadingProviderNotFromTheJson() {
        final String json = VerifiedIdentityJson.write(new BrokeredIdentity("other", "sub-1", null, false, Map.of()));

        assertThat(json).doesNotContain("other");
        assertThat(VerifiedIdentityJson.read("eudi-wallet", json).idpAlias()).isEqualTo("eudi-wallet");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "not json",
        "[]",
        "{\"v\":1}",
        "{\"v\":2,\"externalSubject\":\"s\",\"emailVerified\":false,\"attributes\":{}}",
        "{\"v\":1,\"externalSubject\":\"\",\"emailVerified\":false,\"attributes\":{}}",
        "{\"v\":1,\"externalSubject\":\"s\",\"emailVerified\":false,\"attributes\":{\"a\":1}}",
        "{\"v\":1,\"externalSubject\":\"s\",\"emailVerified\":\"yes\",\"attributes\":{}}",
        "{\"v\":1,\"externalSubject\":\"s\",\"emailVerified\":false,\"attributes\":{},\"extra\":1}",
        "{\"v\":1,\"externalSubject\":\"s\",\"externalSubject\":\"t\",\"emailVerified\":false,\"attributes\":{}}"
    })
    void refusesAnythingButTheExactShape(final String json) {
        assertThatThrownBy(() -> VerifiedIdentityJson.read("eudi-wallet", json))
                .isInstanceOf(WalletVerificationException.class)
                .satisfies(e -> assertThat(((WalletVerificationException) e).code())
                        .isEqualTo(WalletErrorCode.INVALID_RESPONSE));
    }

    @Test
    void refusesNull() {
        assertThatThrownBy(() -> VerifiedIdentityJson.read("eudi-wallet", null))
                .isInstanceOf(WalletVerificationException.class);
    }
    // ------------------------------------------------------------------------------------------- Task 18: decision

    private static BrokeredIdentity walletIdentity() {
        return new BrokeredIdentity("eudi-wallet", "a1b2c3", null, false, Map.of("given_name", "Erika"),
                "http://eidas.europa.eu/LoA/high");
    }

    @Test
    void roundTripsAnExistingDecisionWithItsPendingLink() {
        final WalletLinkService.PendingLink pending = new WalletLinkService.PendingLink("acme", "eudi-wallet",
                "number-hmac", "user-7");
        final WalletLinkService.Decision decision = new WalletLinkService.Decision.Existing("user-7", pending);

        final VerifiedIdentityJson.StoredLogin read = VerifiedIdentityJson.readLogin("eudi-wallet",
                VerifiedIdentityJson.write(walletIdentity(), decision));

        assertThat(read.identity()).isEqualTo(walletIdentity());
        assertThat(read.decision()).isEqualTo(decision);
    }

    @Test
    void roundTripsAnExistingDecisionWithoutPendingLink_andAProvisionDecision() {
        final WalletLinkService.Decision existing = new WalletLinkService.Decision.Existing("user-7");
        final WalletLinkService.Decision provision = new WalletLinkService.Decision.Provision();

        assertThat(VerifiedIdentityJson.readLogin("eudi-wallet",
                VerifiedIdentityJson.write(walletIdentity(), existing)).decision()).isEqualTo(existing);
        assertThat(VerifiedIdentityJson.readLogin("eudi-wallet",
                VerifiedIdentityJson.write(walletIdentity(), provision)).decision()).isEqualTo(provision);
    }

    @Test
    void aRefusedDecisionStoresNoIdentityAtAll() {
        final WalletLinkService.Decision refused =
                new WalletLinkService.Decision.Refused(WalletSubject.Reason.LINK_REQUIRED);

        final String json = VerifiedIdentityJson.write(null, refused);
        final VerifiedIdentityJson.StoredLogin read = VerifiedIdentityJson.readLogin("eudi-wallet", json);

        assertThat(json).doesNotContain("Erika").doesNotContain("externalSubject");
        assertThat(read.identity()).isNull();
        assertThat(read.decision()).isEqualTo(refused);
        // the plain SPI read has no identity to return
        assertThatThrownBy(() -> VerifiedIdentityJson.read("eudi-wallet", json))
                .isInstanceOf(WalletVerificationException.class);
    }

    @Test
    void aDecisionThatNeedsAnIdentityRefusesToBeWrittenWithout() {
        assertThatThrownBy(() -> VerifiedIdentityJson.write(null, new WalletLinkService.Decision.Provision()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void readLogin_withoutADecision_isRefused() {
        final String legacy = VerifiedIdentityJson.write(walletIdentity());

        assertThatThrownBy(() -> VerifiedIdentityJson.readLogin("eudi-wallet", legacy))
                .isInstanceOf(WalletVerificationException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "{\"v\":1,\"externalSubject\":\"s\",\"emailVerified\":false,\"attributes\":{},\"decision\":{}}",
        "{\"v\":1,\"externalSubject\":\"s\",\"emailVerified\":false,\"attributes\":{},\"decision\":{\"kind\":\"other\"}}",
        "{\"v\":1,\"externalSubject\":\"s\",\"emailVerified\":false,\"attributes\":{},\"decision\":{\"kind\":\"existing\"}}",
        "{\"v\":1,\"externalSubject\":\"s\",\"emailVerified\":false,\"attributes\":{},\"decision\":{\"kind\":\"provision\",\"x\":1}}",
        "{\"v\":1,\"emailVerified\":false,\"attributes\":{},\"decision\":{\"kind\":\"provision\"}}",
        "{\"v\":1,\"emailVerified\":false,\"attributes\":{},\"decision\":{\"kind\":\"refused\",\"reason\":\"NOPE\"}}",
        "{\"v\":1,\"externalSubject\":\"s\",\"emailVerified\":false,\"attributes\":{},\"decision\":"
                + "{\"kind\":\"existing\",\"userId\":\"u\",\"pendingLink\":{\"realmId\":\"r\"}}}"
    })
    void readLogin_refusesAnythingButTheExactDecisionShape(final String json) {
        assertThatThrownBy(() -> VerifiedIdentityJson.readLogin("eudi-wallet", json))
                .isInstanceOf(WalletVerificationException.class)
                .satisfies(e -> assertThat(((WalletVerificationException) e).code())
                        .isEqualTo(WalletErrorCode.INVALID_RESPONSE));
    }

    // ------------------------------------------------------------------------------------------- Task 21b: link

    @Test
    void aLinkRecord_roundTripsANumberWithItsTuple_aNumberAlone_aTuple_andUnavailable() {
        for (final WalletSubject subject : java.util.List.<WalletSubject>of(
                new WalletSubject.AdminNumber("aa11", "bb22"), new WalletSubject.AdminNumber("aa11", null),
                new WalletSubject.Tuple("cc33"),
                new WalletSubject.Unavailable(WalletSubject.Reason.WEAK_SUBJECT_NOT_ACKNOWLEDGED))) {
            assertThat(VerifiedIdentityJson.readLink(VerifiedIdentityJson.writeLink(subject))).isEqualTo(subject);
        }
    }

    @Test
    void aLinkRecord_holdsOnlyTheSubjectHashes_noIdentity() {
        final String json = VerifiedIdentityJson.writeLink(new WalletSubject.AdminNumber("aa11", "bb22"));

        assertThat(json).doesNotContain("externalSubject").doesNotContain("decision").contains("\"attributes\":{}");
    }

    @Test
    void aLinkRecord_isNeverALogin_andALoginRecordIsNeverALink() {
        final String link = VerifiedIdentityJson.writeLink(new WalletSubject.Tuple("cc33"));
        final String login = VerifiedIdentityJson.write(new BrokeredIdentity("eudi-wallet", "sub-1", null, false,
                Map.of(), null), new WalletLinkService.Decision.Existing("user-1"));

        assertThatThrownBy(() -> VerifiedIdentityJson.readLogin("eudi-wallet", link))
                .isInstanceOf(WalletVerificationException.class);
        assertThatThrownBy(() -> VerifiedIdentityJson.read("eudi-wallet", link))
                .isInstanceOf(WalletVerificationException.class);
        assertThatThrownBy(() -> VerifiedIdentityJson.readLink(login)).isInstanceOf(WalletVerificationException.class);
        assertThatThrownBy(() -> VerifiedIdentityJson.readLink(null)).isInstanceOf(WalletVerificationException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"v\":1,\"emailVerified\":false,\"attributes\":{},\"link\":{\"kind\":\"number\"}}",
            "{\"v\":1,\"emailVerified\":false,\"attributes\":{},\"link\":{\"kind\":\"number\",\"subject\":\"\"}}",
            "{\"v\":1,\"emailVerified\":false,\"attributes\":{},\"link\":{\"kind\":\"tuple\",\"subject\":\"a\",\"tuple\":\"b\"}}",
            "{\"v\":1,\"emailVerified\":false,\"attributes\":{},\"link\":{\"kind\":\"unavailable\",\"reason\":\"NOPE\"}}",
            "{\"v\":1,\"emailVerified\":false,\"attributes\":{},\"link\":{\"kind\":\"email\",\"subject\":\"a\"}}",
            "{\"v\":1,\"emailVerified\":false,\"attributes\":{\"given_name\":\"Erika\"},\"link\":{\"kind\":\"tuple\",\"subject\":\"a\"}}",
            "{\"v\":1,\"externalSubject\":\"x\",\"emailVerified\":false,\"attributes\":{},\"link\":{\"kind\":\"tuple\",\"subject\":\"a\"}}",
            "{\"v\":1,\"emailVerified\":false,\"attributes\":{},\"link\":{\"kind\":\"tuple\",\"subject\":\"a\"},\"decision\":{\"kind\":\"provision\"}}",
            "{\"v\":1,\"emailVerified\":false,\"attributes\":{},\"link\":\"tuple\"}"
    })
    void readLink_refusesAnythingButTheExactLinkShape(final String json) {
        assertThatThrownBy(() -> VerifiedIdentityJson.readLink(json)).isInstanceOf(WalletVerificationException.class);
    }
}
