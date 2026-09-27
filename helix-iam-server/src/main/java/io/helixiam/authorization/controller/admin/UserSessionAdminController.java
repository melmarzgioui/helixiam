/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.amqp.user.UserAdminRef;
import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.session.UserSessionRevoker;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Open issue E7: revoke every session of a user in one admin call ({@code manage-users}, as every write under
 * {@code /users}). The user is looked up in the path realm only: an unknown user, or one of another realm, is a 404.
 * Audited as {@code USER_SESSIONS_REVOKE} with the counts.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/users/{userId}/sessions")
@Tag(name = "Users")
public class UserSessionAdminController {

    private final UserAdminPublisher users;
    private final UserSessionRevoker revoker;

    public UserSessionAdminController(final UserAdminPublisher users, final UserSessionRevoker revoker) {
        this.users = users;
        this.revoker = revoker;
    }

    @DeleteMapping
    @Operation(summary = "Revoke every session of a user",
            description = "Ends every SSO session of the user (OIDC back-channel logout to each client of it, "
                    + "sid-based and signed with the realm key), removes every remaining authorization (access and "
                    + "refresh tokens) at the realm's clients, and deletes the user's browser sessions. Answers the "
                    + "counts; 404 when the user is not in this realm.")
    public ResponseEntity<UserSessionRevoker.Result> revokeAll(@PathVariable final String realmId,
                                                               @PathVariable final String userId,
                                                               final HttpServletRequest request) {
        if (users.get(new UserAdminRef(realmId, userId)) == null) {
            return ResponseEntity.notFound().build();
        }
        final UserSessionRevoker.Result result = revoker.revokeAll(realmId, userId);
        AuditContext.attachDetail(request, Map.of(
                "ssoSessions", Integer.toString(result.ssoSessions()),
                "authorizations", Integer.toString(result.authorizations()),
                "browserSessions", Integer.toString(result.browserSessions())));
        return ResponseEntity.ok(result);
    }
}
