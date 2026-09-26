/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.mfa;

import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.repository.realm.RealmConfigRepository;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** 1.0 item 6: requireMfa, the per-realm skip grace (off by default) and the issuer name. */
class MfaPolicyServiceTest {

    private final RealmConfigRepository realms = mock(RealmConfigRepository.class);
    private final RealmConfig cfg = new RealmConfig();

    private MfaPolicyService policy(final boolean global) {
        when(realms.findById("monthfold")).thenReturn(Optional.of(cfg));
        return new MfaPolicyService(realms, global);
    }

    @Test
    void requiredWhenTheRealmSaysSo_orEverywhereByDeploymentSwitch() {
        assertThat(policy(false).required("monthfold")).isFalse();
        cfg.setRequireMfa(true);
        assertThat(policy(false).required("monthfold")).isTrue();
        cfg.setRequireMfa(false);
        assertThat(policy(true).required("monthfold")).isTrue();
    }

    @Test
    void skipIsOffByDefault_andOnlyWithinTheGracePeriod() {
        final Date yesterday = new Date(System.currentTimeMillis() - TimeUnit.DAYS.toMillis(1));
        final Date lastMonth = new Date(System.currentTimeMillis() - TimeUnit.DAYS.toMillis(30));
        final MfaPolicyService p = policy(false);
        assertThat(p.maySkip("monthfold", yesterday)).isFalse();
        cfg.setMfaSkipGraceDays(7);
        assertThat(p.maySkip("monthfold", yesterday)).isTrue();
        assertThat(p.maySkip("monthfold", lastMonth)).isFalse();
        assertThat(p.maySkip("monthfold", null)).isFalse();
    }

    @Test
    void issuerIsTheRealmDisplayName_fallingBackToTheRealmId() {
        final MfaPolicyService p = policy(false);
        assertThat(p.issuer("monthfold")).isEqualTo("monthfold");
        cfg.setDisplayName("Monthfold Books");
        assertThat(p.issuer("monthfold")).isEqualTo("Monthfold Books");
    }
}
