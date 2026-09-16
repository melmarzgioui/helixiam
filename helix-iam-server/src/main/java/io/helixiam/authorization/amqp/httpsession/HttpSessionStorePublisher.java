/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.httpsession;


import java.util.List;

/**
 * Helix IAM (Q3): the publisher's seam onto the subscriber-owned HTTP session store, so the publisher's Spring
 * {@code SessionRepository} can persist login sessions without a datasource. Same vhost ({@code authorization})
 * + starter mechanism as the other slices.
 */
public interface HttpSessionStorePublisher {

    String EXCHANGE_AUTHORIZATION_HTTP_SESSION = "exchange-authorization-http-session";
    String SAVE = "authorization.httpsession.save";
    String FIND_BY_ID = "authorization.httpsession.findbyid";
    String DELETE_BY_ID = "authorization.httpsession.deletebyid";
    String FIND_BY_PRINCIPAL = "authorization.httpsession.findbyprincipal";
    String DELETE_BY_PRINCIPAL = "authorization.httpsession.deletebyprincipal";

    Boolean save(HttpSessionRecord record);

    HttpSessionRecord findById(String sessionId);

    Boolean deleteById(String sessionId);

    List<HttpSessionRecord> findByPrincipal(String principalName);

    Integer deleteByPrincipal(String principalName);
}
