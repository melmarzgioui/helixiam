/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.federation;

import io.helixiam.authorization.domain.tenant.TenantUser;
import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Review rc.3 #1: federation in realm X never resolves to a user who belongs only to other realms. */
class FederatedIdentityRealmScopeTest {

    private final UserCredentialsRepository users = mock(UserCredentialsRepository.class);
    private final FederatedLinkService links = mock(FederatedLinkService.class);
    private final TenantUserRepository memberships = mock(TenantUserRepository.class);
    private FederatedIdentityService service;

    @BeforeEach
    void setUp() {
        service = new FederatedIdentityService(users, links);
        service.setMemberships(memberships);
        RealmContextHolder.set("monthfold");
    }

    @AfterEach
    void clear() {
        RealmContextHolder.clear();
    }

    private static TenantUser link(final String realm) {
        final TenantUser t = new TenantUser();
        t.setTenantId(realm);
        return t;
    }

    private void userWithEmail(final String email, final String id) {
        final UserCredentials u = new UserCredentials();
        u.setUserId(id);
        when(users.findByRealmIdAndUsername("monthfold", email)).thenReturn(Optional.of(u));
    }

    @Test
    void emailMatchOnlyWithinTheRealm() {
        userWithEmail("root@example.com", "master-admin");
        when(memberships.findAllByUserId("master-admin")).thenReturn(List.of(link("master")));
        assertThat(service.findUserByEmail("root@example.com")).as("a master-only user").isEmpty();

        userWithEmail("joe@example.com", "joe");
        when(memberships.findAllByUserId("joe")).thenReturn(List.of(link("monthfold")));
        assertThat(service.findUserByEmail("joe@example.com")).contains("joe");

        userWithEmail("legacy@example.com", "legacy");
        when(memberships.findAllByUserId("legacy")).thenReturn(List.of());
        assertThat(service.findUserByEmail("legacy@example.com")).as("pre-1.0 JIT user without a realm link").contains("legacy");
    }

    @Test
    void existingLinksAreRealmScopedToo() {
        when(links.findLinkedUser("corp-ad", "S-1")).thenReturn(Optional.of("master-admin"));
        when(memberships.findAllByUserId("master-admin")).thenReturn(List.of(link("master")));
        assertThat(service.findLinkedUser("corp-ad", "S-1")).isEmpty();
    }

    @Test
    void jitUsersBelongToTheRealmThatCreatedThem() {
        final UserCredentials saved = new UserCredentials();
        saved.setUserId("new-1");
        when(users.save(any())).thenReturn(saved);
        service.provisionUser("ann@example.com", Map.of());
        final ArgumentCaptor<TenantUser> captor = ArgumentCaptor.forClass(TenantUser.class);
        verify(memberships).save(captor.capture());
        assertThat(captor.getValue().getTenantId()).isEqualTo("monthfold");
        assertThat(captor.getValue().getUserId()).isEqualTo("new-1");
    }
}
