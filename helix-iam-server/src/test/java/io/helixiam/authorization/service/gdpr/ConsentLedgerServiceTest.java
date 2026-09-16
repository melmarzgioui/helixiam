/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.gdpr;

import io.helixiam.authorization.domain.gdpr.ConsentLedgerEntity;
import io.helixiam.authorization.domain.gdpr.GdprConsentRecordDto;
import io.helixiam.authorization.domain.gdpr.GdprConsentWithdrawDto;
import io.helixiam.authorization.domain.gdpr.GdprConsentWriteDto;
import io.helixiam.authorization.repository.gdpr.ConsentLedgerRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Helix IAM GDPR Art. 7: the consent ledger records grants, lists history and withdraws by stamping. */
class ConsentLedgerServiceTest {

    private ConsentLedgerRepository repository;
    private ConsentLedgerService service;

    @BeforeEach
    void setUp() {
        repository = mock(ConsentLedgerRepository.class);
        service = new ConsentLedgerService(repository);
    }

    @Test
    void record_persistsGrant_withScopesAndGrantTimestamp() {
        when(repository.save(any(ConsentLedgerEntity.class))).thenAnswer(i -> i.getArgument(0));

        final GdprConsentRecordDto dto = service.record(
                new GdprConsentWriteDto("gov", "u-1", "portal", List.of("openid", "profile")));

        assertEquals("gov", dto.realmId());
        assertEquals("u-1", dto.userId());
        assertEquals("portal", dto.clientId());
        assertEquals(List.of("openid", "profile"), dto.scopes());
        assertNotNull(dto.grantedAt(), "a grant is timestamped");
        assertNull(dto.withdrawnAt(), "a fresh grant is active");
    }

    @Test
    void withdraw_stampsEveryActiveRow_andReturnsTrue() {
        final ConsentLedgerEntity row = new ConsentLedgerEntity("gov", "u-1", "portal", "openid");
        when(repository.findAllByRealmIdAndUserIdAndClientIdAndWithdrawnAtIsNull("gov", "u-1", "portal"))
                .thenReturn(List.of(row));

        final boolean withdrawn = service.withdraw(new GdprConsentWithdrawDto("gov", "u-1", "portal"));

        assertTrue(withdrawn);
        assertNotNull(row.getWithdrawnAt(), "the active row is stamped withdrawn");
        verify(repository).saveAll(anyList());
    }

    @Test
    void withdraw_returnsFalse_whenNoActiveConsent() {
        when(repository.findAllByRealmIdAndUserIdAndClientIdAndWithdrawnAtIsNull("gov", "u-1", "portal"))
                .thenReturn(List.of());

        assertFalse(service.withdraw(new GdprConsentWithdrawDto("gov", "u-1", "portal")));
    }

    @Test
    void list_mapsScopesFromCsv_newestFirstFromRepo() {
        final ConsentLedgerEntity row = new ConsentLedgerEntity("gov", "u-1", "portal", "openid,email");
        when(repository.findAllByRealmIdAndUserIdOrderByGrantedAtDesc("gov", "u-1")).thenReturn(List.of(row));

        final List<GdprConsentRecordDto> out = service.list("gov", "u-1");

        assertEquals(1, out.size());
        assertEquals(List.of("openid", "email"), out.get(0).scopes());
    }
}
