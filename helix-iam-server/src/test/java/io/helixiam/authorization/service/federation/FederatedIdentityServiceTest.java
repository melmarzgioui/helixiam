/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.federation;

import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.lang.reflect.Field;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E5: federated user resolution in the identity domain. Email lookup uses the username
 * (which is the email), and JIT provisioning creates a CONSERVATIVE federated user: usable
 * (accountLocked=true means non-locked here), passwordless, with NO roles and NO tenant — access is
 * granted explicitly later. Returning users resolve via the federated_link.
 */
class FederatedIdentityServiceTest {

    private UserCredentialsRepository users;
    private FederatedLinkService links;
    private FederatedIdentityService service;

    @BeforeEach
    void setUp() {
        users = mock(UserCredentialsRepository.class);
        links = mock(FederatedLinkService.class);
        service = new FederatedIdentityService(users, links);
    }

    private static UserCredentials userWithId(final String id) throws Exception {
        final UserCredentials u = new UserCredentials();
        final Field field = UserCredentials.class.getDeclaredField("userId");
        field.setAccessible(true);
        field.set(u, id);
        return u;
    }

    @Test
    void findUserByEmail_resolvesViaUsername() throws Exception {
        when(users.findByUsername("ada@corp")).thenReturn(Optional.of(userWithId("user-7")));
        assertThat(service.findUserByEmail("Ada@Corp")).contains("user-7"); // case-insensitive
    }

    @Test
    void findUserByEmail_isEmptyWhenUnknown() {
        when(users.findByUsername(any())).thenReturn(Optional.empty());
        assertThat(service.findUserByEmail("nobody@corp")).isEmpty();
    }

    @Test
    void provisionUser_createsAConservativeFederatedUser() throws Exception {
        when(users.save(any(UserCredentials.class))).thenAnswer(inv -> {
            final UserCredentials u = inv.getArgument(0);
            final Field field = UserCredentials.class.getDeclaredField("userId");
            field.setAccessible(true);
            field.set(u, "new-user-1"); // simulate the @GeneratedValue id
            return u;
        });

        final String userId = service.provisionUser("grace@corp", Map.of("firstName", "Grace", "email", "grace@corp"));

        assertThat(userId).isEqualTo("new-user-1");
        final ArgumentCaptor<UserCredentials> saved = ArgumentCaptor.forClass(UserCredentials.class);
        verify(users).save(saved.capture());
        final UserCredentials u = saved.getValue();
        assertThat(u.getUsername()).isEqualTo("grace@corp");
        assertThat(u.getPassword()).isNull();                       // passwordless (federated)
        assertThat(u.isAccountNonLocked()).isTrue();                // usable
        assertThat(u.getUserRoles()).isEmpty();                     // NO roles (conservative)
        assertThat(u.getUserAttributes()).containsEntry("firstName", "Grace");
    }

    @Test
    void provisionUser_fallsBackToTheMappedUsernameWhenThereIsNoEmail() throws Exception {
        // eID schemes (DigiD/eHerkenning/eIDAS) assert no email; the subject id is mapped to "username".
        when(users.save(any(UserCredentials.class))).thenAnswer(inv -> inv.getArgument(0));

        service.provisionUser(null, Map.of("username", "123456782", "firstName", "Ada"));

        final ArgumentCaptor<UserCredentials> saved = ArgumentCaptor.forClass(UserCredentials.class);
        verify(users).save(saved.capture());
        assertThat(saved.getValue().getUsername()).isEqualTo("123456782"); // BSN-derived, not null
    }

    @Test
    void findLinkedUser_delegatesToTheLinkService() {
        when(links.findLinkedUser("google", "sub-1")).thenReturn(Optional.of("user-7"));
        assertThat(service.findLinkedUser("google", "sub-1")).contains("user-7");
    }

    @Test
    void link_delegatesToTheLinkService() {
        service.link("google", "sub-9", "user-9");
        verify(links).link("google", "sub-9", "user-9");
    }

    @Test
    void loadUser_returnsTheUserById() throws Exception {
        final UserCredentials user = userWithId("user-9");
        when(users.findByUserId("user-9")).thenReturn(Optional.of(user));
        assertThat(service.loadUser("user-9")).isSameAs(user);
    }

    @Test
    void loadUser_returnsNullWhenUnknown() {
        when(users.findByUserId("ghost")).thenReturn(Optional.empty());
        assertThat(service.loadUser("ghost")).isNull();
    }
}
