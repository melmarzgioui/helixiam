/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import io.helixiam.authorization.amqp.authzstore.AuthorizationStorePublisher;
import io.helixiam.authorization.security.AuthorizationBlobs;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Helix IAM (Q2): the Sessions-admin reader for the queue token store. Lists every stored authorization from
 * the subscriber over AMQP and maps each to a {@link SessionRow} — the same storage-shaped view the JDBC
 * reader produced from {@code oauth2_authorization}. Selected when {@code helix.iam.token-store=queue}.
 */
public class QueueSessionStore implements SessionStore {

    private final AuthorizationStorePublisher store;

    public QueueSessionStore(final AuthorizationStorePublisher store) {
        this.store = store;
    }

    @Override
    public List<SessionRow> findAll() {
        return store.listAll("*").stream()
                .map(r -> AuthorizationBlobs.deserialize(r.blob()))
                .filter(Objects::nonNull)
                .map(QueueSessionStore::toRow)
                .toList();
    }

    private static SessionRow toRow(final OAuth2Authorization a) {
        return new SessionRow(a.getId(), a.getRegisteredClientId(), a.getPrincipalName(),
                a.getAuthorizationGrantType().getValue(), new ArrayList<>(a.getAuthorizedScopes()),
                issuedAt(a), expiresAt(a));
    }

    // issued/expiry collapse the per-token timestamps into one session lifetime (mirrors the JDBC COALESCEs).
    private static Instant issuedAt(final OAuth2Authorization a) {
        if (a.getAccessToken() != null) {
            return a.getAccessToken().getToken().getIssuedAt();
        }
        final OAuth2Authorization.Token<OAuth2AuthorizationCode> code = a.getToken(OAuth2AuthorizationCode.class);
        return code != null ? code.getToken().getIssuedAt() : null;
    }

    private static Instant expiresAt(final OAuth2Authorization a) {
        if (a.getRefreshToken() != null && a.getRefreshToken().getToken().getExpiresAt() != null) {
            return a.getRefreshToken().getToken().getExpiresAt();
        }
        if (a.getAccessToken() != null && a.getAccessToken().getToken().getExpiresAt() != null) {
            return a.getAccessToken().getToken().getExpiresAt();
        }
        final OAuth2Authorization.Token<OAuth2AuthorizationCode> code = a.getToken(OAuth2AuthorizationCode.class);
        return code != null ? code.getToken().getExpiresAt() : null;
    }
}
