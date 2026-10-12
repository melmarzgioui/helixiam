/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Task 21a: the answer to {@link FederatedIdentityPublisher#claimLink}. JSON-marshalled.
 *
 * @param status      what happened
 * @param ownerUserId the subject's live owner afterwards ({@code null} for {@link Status#USER_NOT_IN_REALM})
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FederatedLinkClaimResult(Status status, String ownerUserId) {

    /** The outcome of a claim. */
    public enum Status {
        /** The link was created for the user (also when it replaced a stale link). */
        CREATED,
        /** The user already owned the link; nothing changed. */
        ALREADY_LINKED,
        /** A different live user of the realm owns the link; nothing changed. */
        LINKED_TO_ANOTHER_USER,
        /** The user does not exist in the realm; nothing changed. */
        USER_NOT_IN_REALM
    }
}