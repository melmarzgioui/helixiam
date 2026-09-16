/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import io.helixiam.authorization.amqp.authzstore.AuthorizationStorePublisher;
import io.helixiam.authorization.security.AuthorizationBlobs;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

import java.util.List;
import java.util.Objects;

/**
 * Helix IAM (Q2): the SSO-session reader for the queue token store. Pulls every stored authorization from the
 * subscriber over AMQP, deserializes each blob to an {@link OAuth2Authorization}, and rolls them up by
 * {@code sid} the same way the JDBC/Redis readers do — reusing the shared {@link SsoSessionRollup}. Selected
 * when {@code helix.iam.token-store=queue}.
 */
public class QueueSsoSessionStore implements SsoSessionStore {

    private final AuthorizationStorePublisher store;

    public QueueSsoSessionStore(final AuthorizationStorePublisher store) {
        this.store = store;
    }

    @Override
    public List<SsoSession> findAll() {
        final List<SsoSessionRollup.Entry> entries = store.listAll("*").stream()
                .map(r -> AuthorizationBlobs.deserialize(r.blob()))
                .filter(Objects::nonNull)
                .map(SsoSessionRollup::entryOf)
                .filter(Objects::nonNull)
                .toList();
        return SsoSessionRollup.assemble(entries);
    }

    @Override
    public SsoSession findById(final String ssoSessionId) {
        return findAll().stream().filter(s -> s.ssoSessionId().equals(ssoSessionId)).findFirst().orElse(null);
    }
}
