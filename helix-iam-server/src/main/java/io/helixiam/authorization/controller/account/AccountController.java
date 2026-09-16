/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account;

import io.helixiam.authorization.amqp.user.CredentialRevokeRef;
import io.helixiam.authorization.amqp.user.CredentialSummary;
import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.amqp.user.UserAdminRef;
import io.helixiam.authorization.amqp.user.UserChangePasswordDto;
import io.helixiam.authorization.amqp.user.UserWriteDto;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Helix IAM (6) Self-service Account: the END-USER "my account" API — distinct from the admin console. Every
 * endpoint is keyed off the <em>authenticated principal</em>, never a path/body userId, so a signed-in user
 * can only ever read and modify <em>themselves</em>: there is structurally no way to address another user.
 * Served under {@code /realms/{realm}/account/**} (the realm comes from {@link RealmContextHolder}, the user
 * from the {@link UserCredentials} principal established by the realm's OIDC login).
 *
 * <p>It reuses the existing user-domain AMQP path ({@link UserAdminPublisher}) — the same backend the admin
 * Users screen uses — but always pins {@code realm + userId} to the caller. Password change verifies the
 * current password (self-service, unlike admin reset). Returns {@link ResponseEntity} / relies on Bean
 * Validation everywhere so a bad request is a clean 4xx, never a thrown exception the security chain would
 * turn into a 302 to /login.
 */
@RestController
@RequestMapping("/account")
public class AccountController {

    private final UserAdminPublisher publisher;

    public AccountController(final UserAdminPublisher publisher) {
        this.publisher = publisher;
    }

    /** The signed-in user's own profile (username read-only). 401 when unauthenticated. */
    @GetMapping("/profile")
    public ResponseEntity<UserAdminDto> profile(@AuthenticationPrincipal final UserCredentials principal) {
        final UserCredentials user = require(principal);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        final UserAdminDto me = publisher.get(new UserAdminRef(realm(), user.getUserId()));
        return me == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(me);
    }

    /**
     * Update the signed-in user's own email + attributes. Username is never read from the body — it stays the
     * principal's. Enabled/locked flags are preserved (a user can't unlock/disable themselves), so the current
     * persisted state is carried through.
     */
    @PutMapping("/profile")
    public ResponseEntity<UserAdminDto> updateProfile(@AuthenticationPrincipal final UserCredentials principal,
                                                      @Valid @RequestBody final AccountProfileRequest request) {
        final UserCredentials user = require(principal);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        final UserAdminDto current = publisher.get(new UserAdminRef(realm(), user.getUserId()));
        if (current == null) {
            return ResponseEntity.notFound().build();
        }
        final Map<String, String> attributes = request.attributes() == null ? current.attributes() : request.attributes();
        // Preserve username/enabled/locked from the persisted record; only email + attributes are user-editable.
        final UserAdminDto saved = publisher.update(new UserWriteDto(realm(), user.getUserId(), current.username(),
                request.email(), null, current.enabled(), current.locked(), attributes));
        return saved == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(saved);
    }

    /** Change own password: verify current → set new. 400 on a wrong current password; never reveals which. */
    @PutMapping("/password")
    public ResponseEntity<Void> changePassword(@AuthenticationPrincipal final UserCredentials principal,
                                               @Valid @RequestBody final AccountPasswordRequest request) {
        final UserCredentials user = require(principal);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        final boolean ok = Boolean.TRUE.equals(publisher.changePassword(new UserChangePasswordDto(
                realm(), user.getUserId(), request.currentPassword(), request.newPassword())));
        return ok ? ResponseEntity.noContent().build() : ResponseEntity.badRequest().build();
    }

    /** The signed-in user's own enrolled factors (passkeys, devices, TOTP/HOTP, recovery codes). */
    @GetMapping("/credentials")
    public ResponseEntity<List<CredentialSummary>> credentials(@AuthenticationPrincipal final UserCredentials principal) {
        final UserCredentials user = require(principal);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return ResponseEntity.ok(publisher.listCredentials(new UserAdminRef(realm(), user.getUserId())));
    }

    /** Revoke one of the signed-in user's own factors; 404 when it is absent or not owned by them. */
    @DeleteMapping("/credentials/{type}/{id}")
    public ResponseEntity<Void> revokeCredential(@AuthenticationPrincipal final UserCredentials principal,
                                                 @PathVariable final String type, @PathVariable final String id) {
        final UserCredentials user = require(principal);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        // The revoke is scoped to the caller's userId in the subscriber, so a forged id for another user's
        // factor simply does not match and yields 404 — a user can never revoke someone else's credential.
        final boolean removed = Boolean.TRUE.equals(
                publisher.revokeCredential(new CredentialRevokeRef(realm(), user.getUserId(), type, id)));
        return removed ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    /** Only a real interactive {@link UserCredentials} principal counts; anything else is treated as anonymous. */
    private static UserCredentials require(final UserCredentials principal) {
        return principal;
    }

    private static String realm() {
        return RealmContextHolder.get();
    }
}
