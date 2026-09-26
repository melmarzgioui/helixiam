/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.amqp.user.CredentialRevokeRef;
import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.amqp.user.UserAdminRef;
import io.helixiam.authorization.amqp.user.UserChangePasswordDto;
import io.helixiam.authorization.amqp.user.UserWriteDto;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM (6) Self-service Account: the END-USER account API is keyed off the authenticated principal — NOT
 * a path/body userId. These tests prove the security-critical invariant: every operation is scoped to the
 * caller's own userId, so a user can never read or modify another user. They also prove username read-only,
 * change-password delegation, and that an unauthenticated call is 401 (not a thrown exception → 302).
 */
class AccountControllerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private UserAdminPublisher publisher;
    private io.helixiam.authorization.service.account.SelfEditableAttributesService selfEditable;
    private AccountController controller;

    @BeforeEach
    void setUp() {
        publisher = mock(UserAdminPublisher.class);
        selfEditable = mock(io.helixiam.authorization.service.account.SelfEditableAttributesService.class);
        // The realm admin allowlisted `locale` for self-service; everything else is admin-only.
        when(selfEditable.allowed("master")).thenReturn(java.util.Set.of("locale"));
        controller = new AccountController(publisher, selfEditable);
        RealmContextHolder.set("master");
    }

    @AfterEach
    void tearDown() {
        RealmContextHolder.clear();
    }

    private UserCredentials principal(final String userId) {
        return MAPPER.convertValue(Map.of("userId", userId, "username", userId + "@example.com"), UserCredentials.class);
    }

    private UserAdminDto dto(final String userId) {
        return new UserAdminDto("master", userId, "alice", "alice@example.com", true, false, false,
                List.of(), Map.of("locale", "en"), 0L);
    }

    @Test
    void profile_readsOnlyTheAuthenticatedUser() {
        when(publisher.get(any())).thenReturn(dto("alice"));

        final ResponseEntity<UserAdminDto> res = controller.profile(principal("alice"));

        final ArgumentCaptor<UserAdminRef> ref = ArgumentCaptor.forClass(UserAdminRef.class);
        verify(publisher).get(ref.capture());
        assertThat(ref.getValue().userId()).isEqualTo("alice");
        assertThat(ref.getValue().realmId()).isEqualTo("master");
        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void profile_unauthenticated_is401_notException() {
        final ResponseEntity<UserAdminDto> res = controller.profile(null);
        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        verify(publisher, never()).get(any());
    }

    @Test
    void updateProfile_keepsUsernameAndFlags_fromPersistedRecord_scopedToCaller() {
        when(publisher.get(any())).thenReturn(dto("alice"));
        when(publisher.update(any())).thenReturn(dto("alice"));

        // A malicious body cannot change identity: there is no username field, and email/attrs only.
        controller.updateProfile(principal("alice"),
                new AccountProfileRequest("new@example.com", Map.of("locale", "nl")));

        final ArgumentCaptor<UserWriteDto> write = ArgumentCaptor.forClass(UserWriteDto.class);
        verify(publisher).update(write.capture());
        assertThat(write.getValue().userId()).isEqualTo("alice");            // always the caller
        assertThat(write.getValue().username()).isEqualTo("alice");          // read-only, from persisted record
        assertThat(write.getValue().email()).isEqualTo("new@example.com");
        assertThat(write.getValue().enabled()).isTrue();                     // preserved
        assertThat(write.getValue().attributes()).containsEntry("locale", "nl");
        assertThat(write.getValue().password()).isNull();                    // never set here
    }

    @Test
    void changePassword_delegatesWithCallerScope_andReturns204OnSuccess() {
        when(publisher.changePassword(any())).thenReturn(Boolean.TRUE);

        final ResponseEntity<Void> res = controller.changePassword(principal("alice"),
                new AccountPasswordRequest("old", "new"));

        final ArgumentCaptor<UserChangePasswordDto> cap = ArgumentCaptor.forClass(UserChangePasswordDto.class);
        verify(publisher).changePassword(cap.capture());
        assertThat(cap.getValue().userId()).isEqualTo("alice");
        assertThat(cap.getValue().currentPassword()).isEqualTo("old");
        assertThat(cap.getValue().newPassword()).isEqualTo("new");
        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }

    @Test
    void changePassword_wrongCurrent_is400() {
        when(publisher.changePassword(any())).thenReturn(Boolean.FALSE);
        final ResponseEntity<Void> res = controller.changePassword(principal("alice"),
                new AccountPasswordRequest("wrong", "new"));
        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void revokeCredential_isScopedToCaller_soAnotherUsersIdCannotBeTargeted() {
        when(publisher.revokeCredential(any())).thenReturn(Boolean.TRUE);

        controller.revokeCredential(principal("alice"), "passkey", "someoneElsesCredId");

        final ArgumentCaptor<CredentialRevokeRef> ref = ArgumentCaptor.forClass(CredentialRevokeRef.class);
        verify(publisher).revokeCredential(ref.capture());
        // The userId is the caller's — the subscriber's ownership filter then yields 404 for a foreign id.
        assertThat(ref.getValue().userId()).isEqualTo("alice");
        assertThat(ref.getValue().type()).isEqualTo("passkey");
        assertThat(ref.getValue().id()).isEqualTo("someoneElsesCredId");
    }

    @Test
    void credentials_listsOnlyTheCallersFactors() {
        when(publisher.listCredentials(any())).thenReturn(List.of());

        controller.credentials(principal("bob"));

        final ArgumentCaptor<UserAdminRef> ref = ArgumentCaptor.forClass(UserAdminRef.class);
        verify(publisher).listCredentials(ref.capture());
        assertThat(ref.getValue().userId()).isEqualTo("bob");
    }

    // ---- 1.0 security (item 1): self-service attribute edits are restricted -------------------------------

    @Test
    void updateProfile_refusesAReservedAttribute_with400_andNeverWrites() {
        when(publisher.get(any())).thenReturn(dto("alice"));
        final var resp = controller.updateProfile(principal("alice"),
                new AccountProfileRequest("alice@example.com", Map.of("locale", "en", "sub", "joe-id")));
        assertThat(resp.getStatusCode().value()).isEqualTo(400);
        assertThat(resp.getBody().toString()).contains("reserved_attribute").contains("sub");
        org.mockito.Mockito.verify(publisher, org.mockito.Mockito.never()).update(any());
    }

    @Test
    void updateProfile_refusesANonAllowlistedAttribute_with403() {
        when(publisher.get(any())).thenReturn(dto("alice"));
        final var resp = controller.updateProfile(principal("alice"),
                new AccountProfileRequest("alice@example.com", Map.of("locale", "en", "department", "Finance")));
        assertThat(resp.getStatusCode().value()).isEqualTo(403);
        assertThat(resp.getBody().toString()).contains("attribute_not_self_editable").contains("department");
        org.mockito.Mockito.verify(publisher, org.mockito.Mockito.never()).update(any());
    }

    @Test
    void updateProfile_refusesEverythingWhenTheAllowlistIsEmpty_theDefault() {
        when(selfEditable.allowed("master")).thenReturn(java.util.Set.of());
        when(publisher.get(any())).thenReturn(dto("alice"));
        final var resp = controller.updateProfile(principal("alice"),
                new AccountProfileRequest("alice@example.com", Map.of("locale", "nl")));
        assertThat(resp.getStatusCode().value()).isEqualTo(403);
    }

    @Test
    void updateProfile_unchangedAttributesAreNotTreatedAsEdits() {
        when(selfEditable.allowed("master")).thenReturn(java.util.Set.of());
        when(publisher.get(any())).thenReturn(dto("alice"));
        when(publisher.update(any())).thenReturn(dto("alice"));
        // Re-sending the stored attributes unchanged (e.g. only the email changed) is allowed.
        final var resp = controller.updateProfile(principal("alice"),
                new AccountProfileRequest("new@example.com", Map.of("locale", "en")));
        assertThat(resp.getStatusCode().value()).isEqualTo(200);
    }
}
