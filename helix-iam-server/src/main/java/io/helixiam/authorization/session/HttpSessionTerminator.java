/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Component;

import java.util.Collection;

/**
 * Ends specific browser (HTTP) sessions by id through the active Spring Session repository, whichever store
 * backs it (Redis by default, or the queue store). Used by SSO logout to end exactly the browser login of the
 * terminated SSO session, and no other session of the same user. Best-effort: a failure never blocks a logout.
 */
@Component
public class HttpSessionTerminator {

    private static final Logger LOG = LogManager.getLogger(HttpSessionTerminator.class);

    private final ObjectProvider<SessionRepository<?>> sessionRepository;

    public HttpSessionTerminator(final ObjectProvider<SessionRepository<?>> sessionRepository) {
        this.sessionRepository = sessionRepository;
    }

    /** Deletes each HTTP session id; returns how many deletions were issued. */
    public int deleteAll(final Collection<String> sessionIds) {
        final SessionRepository<?> repository = sessionRepository.getIfAvailable();
        if (repository == null || sessionIds == null) {
            return 0;
        }
        int deleted = 0;
        for (final String id : sessionIds) {
            try {
                repository.deleteById(id);
                deleted++;
            } catch (final RuntimeException e) {
                LOG.warn("Could not end HTTP session {}: {}", LogSafe.sanitize(id), LogSafe.sanitize(e.getMessage()));
            }
        }
        return deleted;
    }
}
