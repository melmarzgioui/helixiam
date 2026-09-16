/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.authzstore;

import io.helixiam.authorization.domain.authzstore.HelixAuthorization;
import io.helixiam.authorization.domain.authzstore.HelixAuthorizationToken;
import io.helixiam.authorization.domain.authzstore.admin.AuthorizationRecord;
import io.helixiam.authorization.domain.authzstore.admin.AuthorizationRemoveRequest;
import io.helixiam.authorization.repository.authzstore.HelixAuthorizationRepository;
import io.helixiam.authorization.repository.authzstore.HelixAuthorizationTokenRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM (Q1): the subscriber authorization store persists the opaque blob + a SHA-256-hashed token index,
 * and resolves findByToken by hashing the supplied value (so a full-JWT token value never becomes a btree key).
 */
class AuthorizationStoreServiceTest {

    private final HelixAuthorizationRepository authorizations = mock(HelixAuthorizationRepository.class);
    private final HelixAuthorizationTokenRepository tokens = mock(HelixAuthorizationTokenRepository.class);
    private final AuthorizationStoreService service = new AuthorizationStoreService(authorizations, tokens);

    @Test
    void save_persistsBlob_andIndexesTokenKeysByHash() {
        when(authorizations.findById("auth-1")).thenReturn(Optional.empty());

        service.save(new AuthorizationRecord("auth-1", "alice", "authorization_code", "BLOB",
                List.of("tok-abc", "state-xyz"), 123L));

        final ArgumentCaptor<HelixAuthorization> auth = ArgumentCaptor.forClass(HelixAuthorization.class);
        verify(authorizations).save(auth.capture());
        assertThat(auth.getValue().getBlob()).isEqualTo("BLOB");
        assertThat(auth.getValue().getPrincipalName()).isEqualTo("alice");
        verify(tokens).deleteByAuthorizationId("auth-1");
        final ArgumentCaptor<HelixAuthorizationToken> tok = ArgumentCaptor.forClass(HelixAuthorizationToken.class);
        verify(tokens, org.mockito.Mockito.times(2)).save(tok.capture());
        // Index keys are SHA-256 hex (64 chars), not the raw token value.
        assertThat(tok.getAllValues()).allSatisfy(t -> {
            assertThat(t.getTokenHash()).hasSize(64).doesNotContain("tok-abc");
            assertThat(t.getAuthorizationId()).isEqualTo("auth-1");
        });
    }

    @Test
    void findByToken_hashesTheLookupValue_andLoadsTheAuthorization() {
        final String hash = AuthorizationStoreService.sha256("tok-abc");
        final HelixAuthorizationToken idx = new HelixAuthorizationToken();
        idx.setTokenHash(hash);
        idx.setAuthorizationId("auth-1");
        when(tokens.findById(hash)).thenReturn(Optional.of(idx));
        final HelixAuthorization e = new HelixAuthorization();
        e.setId("auth-1");
        e.setBlob("BLOB");
        when(authorizations.findById("auth-1")).thenReturn(Optional.of(e));

        final AuthorizationRecord found = service.findByToken("tok-abc");

        assertThat(found).isNotNull();
        assertThat(found.id()).isEqualTo("auth-1");
        assertThat(found.blob()).isEqualTo("BLOB");
    }

    @Test
    void remove_dropsIndexThenAuthorization() {
        when(authorizations.findById("auth-1")).thenReturn(Optional.of(new HelixAuthorization()));

        service.remove(new AuthorizationRemoveRequest("auth-1", List.of("tok-abc")));

        verify(tokens).deleteByAuthorizationId("auth-1");
        verify(authorizations).delete(any(HelixAuthorization.class));
    }
}
