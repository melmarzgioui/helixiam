/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import io.helixiam.authorization.amqp.authzstore.AuthorizationStorePublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Helix IAM (Q4): the Sessions-admin {@link SessionStore} reader — queue-backed (reads the realm's
 * authorizations from the subscriber over AMQP). The publisher has no datasource.
 */
@Configuration
public class SessionStoreConfig {

    @Bean
    public SessionStore queueSessionStore(final AuthorizationStorePublisher store) {
        return new QueueSessionStore(store);
    }
}
