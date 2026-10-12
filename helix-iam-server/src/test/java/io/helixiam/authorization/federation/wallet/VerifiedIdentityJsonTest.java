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
}
