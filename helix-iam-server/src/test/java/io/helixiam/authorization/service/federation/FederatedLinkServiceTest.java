/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.federation;

import io.helixiam.authorization.domain.federation.FederatedLinkEntity;
import io.helixiam.authorization.repository.federation.FederatedLinkRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E5: the account-linking persistence behind the federation broker — resolve the local
 * user previously linked to an (idp, external subject) pair, and create new links. (JIT user
 * provisioning + email lookup touch the user domain and are wired separately.)
 */
class FederatedLinkServiceTest {

    private FederatedLinkRepository repository;
    private FederatedLinkService service;

    @BeforeEach
    void setUp() {
        repository = mock(FederatedLinkRepository.class);
        service = new FederatedLinkService(repository);
    }

    @Test
    void findLinkedUser_returnsTheLinkedUser() {
        when(repository.findByRealmIdAndIdpAliasAndExternalSubject("acme", "google", "sub-1"))
                .thenReturn(Optional.of(new FederatedLinkEntity("acme", "google", "sub-1", "user-7")));

        assertThat(service.findLinkedUser("acme", "google", "sub-1")).contains("user-7");
    }

    @Test
    void findLinkedUser_isEmptyWhenNoLink() {
        when(repository.findByRealmIdAndIdpAliasAndExternalSubject(any(), any(), any())).thenReturn(Optional.empty());
        assertThat(service.findLinkedUser("acme", "google", "ghost")).isEmpty();
    }

    @Test
    void linksForUser_returnsAllProvidersTheUserHasConnected() {
        when(repository.findAllByRealmIdAndUserId("acme", "user-7")).thenReturn(java.util.List.of(
                new FederatedLinkEntity("acme", "google", "sub-g", "user-7"),
                new FederatedLinkEntity("acme", "digid", "bsn-1", "user-7")));

        final var links = service.linksForUser("acme", "user-7");

        assertThat(links).extracting("idpAlias").containsExactlyInAnyOrder("google", "digid");
        assertThat(links).extracting("externalSubject").contains("sub-g", "bsn-1");
    }

    @Test
    void unlink_removesOnlyTheCallersLinkForThatProvider() {
        when(repository.findAllByRealmIdAndUserId("acme", "user-7")).thenReturn(java.util.List.of(
                new FederatedLinkEntity("acme", "google", "sub-g", "user-7"),
                new FederatedLinkEntity("acme", "digid", "bsn-1", "user-7")));

        final boolean removed = service.unlink("acme", "user-7", "google");

        assertThat(removed).isTrue();
        final ArgumentCaptor<FederatedLinkEntity> deleted = ArgumentCaptor.forClass(FederatedLinkEntity.class);
        verify(repository).delete(deleted.capture());
        assertThat(deleted.getValue().getIdpAlias()).isEqualTo("google");
    }

    @Test
    void unlink_isFalseWhenTheUserHasNoSuchLink() {
        when(repository.findAllByRealmIdAndUserId("acme", "user-7")).thenReturn(java.util.List.of(
                new FederatedLinkEntity("acme", "google", "sub-g", "user-7")));

        assertThat(service.unlink("acme", "user-7", "facebook")).isFalse();
    }

    @Test
    void link_persistsTheMapping() {
        service.link("acme", "google", "sub-9", "user-9", "JIT");

        final ArgumentCaptor<FederatedLinkEntity> saved = ArgumentCaptor.forClass(FederatedLinkEntity.class);
        verify(repository).save(saved.capture());
        assertThat(saved.getValue().getIdpAlias()).isEqualTo("google");
        assertThat(saved.getValue().getExternalSubject()).isEqualTo("sub-9");
        assertThat(saved.getValue().getUserId()).isEqualTo("user-9");
        assertThat(saved.getValue().getId()).isEqualTo("acme|google|sub-9");
        assertThat(saved.getValue().getRealmId()).isEqualTo("acme");
    }

    @Test
    void aLinkOfOneRealmIsNotFoundInAnother() {
        when(repository.findByRealmIdAndIdpAliasAndExternalSubject("acme", "google", "sub-1"))
                .thenReturn(Optional.of(new FederatedLinkEntity("acme", "google", "sub-1", "user-7")));
        when(repository.findByRealmIdAndIdpAliasAndExternalSubject("beta", "google", "sub-1"))
                .thenReturn(Optional.empty());

        assertThat(service.findLinkedUser("beta", "google", "sub-1")).isEmpty();
        assertThat(service.provenance("beta", "google", "sub-1")).isEmpty();
    }

    @Test
    void claimNeverTakesOverALiveOwner() {
        when(repository.insertIfAbsent(any(), any(), any(), any(), any(), any())).thenReturn(0);
        when(repository.findOwner("acme", "google", "sub-1")).thenReturn(Optional.of("owner"));

        final FederatedLinkService.LinkIfAbsent outcome =
                service.claim("acme", "google", "sub-1", "intruder", owner -> true, "SELF");

        assertThat(outcome.ownerUserId()).isEqualTo("owner");
        assertThat(outcome.created()).isFalse();
        verify(repository, org.mockito.Mockito.never()).deleteIfOwnedBy(any(), any(), any(), any());
    }

    @Test
    void aLinkIsMatchedOnItsColumnsNotOnTheCompositeId() {
        // ("corp|x", "attacker2") and ("corp", "x|attacker2") share the composite id; only the columns tell them apart.
        when(repository.findByRealmIdAndIdpAliasAndExternalSubject("acme", "corp|x", "attacker2"))
                .thenReturn(Optional.empty());
        assertThat(service.findLinkedUser("acme", "corp|x", "attacker2")).isEmpty();
        verify(repository, org.mockito.Mockito.never()).findById(any());
    }
}
