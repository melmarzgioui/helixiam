/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.authzstore;


import java.util.List;

/**
 * Helix IAM (Q1): the publisher's seam onto the subscriber-owned OAuth2 authorization (token) store. The
 * subscriber persists an opaque blob + a token-value index; this iface carries the four operations the SAS
 * {@code OAuth2AuthorizationService} needs. Routing keys are single dotted tokens.
 */
public interface AuthorizationStorePublisher {

    String EXCHANGE_AUTHORIZATION_AUTHZ_STORE = "exchange-authorization-authz-store";
    String SAVE = "authorization.authzstore.save";
    String REMOVE = "authorization.authzstore.remove";
    String FIND_BY_ID = "authorization.authzstore.findbyid";
    String FIND_BY_TOKEN = "authorization.authzstore.findbytoken";
    String LIST_ALL = "authorization.authzstore.listall";

    Boolean save(AuthorizationRecord record);

    Boolean remove(RemoveRequest request);

    AuthorizationRecord findById(String id);

    AuthorizationRecord findByToken(String tokenKey);

    /** Every stored authorization (with blobs) — for the Sessions-admin rollup. The arg is an unused marker. */
    List<AuthorizationRecord> listAll(String marker);

    /** Remove an authorization by id, also dropping its token-index entries. */
    record RemoveRequest(String id, List<String> tokenKeys) {
    }
}
