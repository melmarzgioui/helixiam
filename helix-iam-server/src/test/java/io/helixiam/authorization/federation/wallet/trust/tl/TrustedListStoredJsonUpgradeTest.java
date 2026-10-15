/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import io.helixiam.testsupport.Jackson2Fixtures;
import org.junit.jupiter.api.Test;

import java.util.List;

import static io.helixiam.testsupport.Jackson2Fixtures.assertWritesSame;
import static io.helixiam.testsupport.Jackson2Fixtures.read;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Jackson 3 upgrade: {@code trusted_list_source.services_json} / {@code trusted_list_member.services_json} and the
 * list settings ({@code service_types}, {@code accepted_statuses}, {@code territories}) were written by the Jackson 2
 * line, and both are covered by a MAC over the stored text. The current code must read them and, for the settings,
 * produce the same bytes (the MAC is recomputed over {@link TrustedListRepository#settingJson}).
 */
class TrustedListStoredJsonUpgradeTest {

    private static final String SERVICES = "trusted-list-services.json";

    @Test
    void storedServices_areReadAndWrittenAsBefore() throws Exception {
        if (Jackson2Fixtures.recording()) {
            final var cert = TrustedListFixtures.signer("PID Provider Zoë / Ünal").certificate();
            assertWritesSame(SERVICES, ServicesCodec.encode(List.of(
                    new ListedService(cert, TrustedListFixtures.PID_TYPE, "PID service \"NL\" <1>",
                            "Rijksdienst & Co", "NL", TrustedListFixtures.GRANTED),
                    new ListedService(cert, TrustedListFixtures.LOTE_PID_TYPE, null, null, null, null))));
        }
        final List<ListedService> services = ServicesCodec.decode(read(SERVICES));

        assertThat(services).hasSize(2);
        assertThat(services.get(0).certificate().getSubjectX500Principal().getName()).contains("PID Provider");
        assertThat(services.get(0).serviceType()).isEqualTo(TrustedListFixtures.PID_TYPE);
        assertThat(services.get(0).serviceName()).isEqualTo("PID service \"NL\" <1>");
        assertThat(services.get(0).provider()).isEqualTo("Rijksdienst & Co");
        assertThat(services.get(0).country()).isEqualTo("NL");
        assertThat(services.get(0).status()).isEqualTo(TrustedListFixtures.GRANTED);
        assertThat(services.get(1).serviceType()).isEqualTo(TrustedListFixtures.LOTE_PID_TYPE);
        assertThat(services.get(1).serviceName()).isNull();
        assertThat(services.get(1).status()).isNull();
        assertWritesSame(SERVICES, ServicesCodec.encode(services));
    }

    @Test
    void theMacedListSettings_areWrittenAsBefore() {
        assertWritesSame("trusted-list-setting.json", TrustedListRepository.settingJson(List.of(
                TrustedListFixtures.PID_TYPE, "http://uri.etsi.org/TrstSvc/Svctype/EAA/Pub-EAA", "NL", "Zoë",
                "a\"b\\c", " ", "😀", "<script>&")));
        assertWritesSame("trusted-list-setting-empty.json", TrustedListRepository.settingJson(List.of()));
    }
}
