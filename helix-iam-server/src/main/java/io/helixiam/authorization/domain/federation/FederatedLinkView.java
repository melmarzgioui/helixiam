/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Helix IAM B9: a read view of one of a user's federated-identity links, for the end-user account
 * console's "Connected accounts" screen. Two-copy DTO over AMQP (mirrors the publisher's
 * {@code amqp.account.FederatedLinkDto}).
 *
 * @param idpAlias        the identity provider the account is linked through
 * @param externalSubject the provider's subject id for the user (display only)
 * @param linkedAt        epoch millis the link was established (nullable)
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FederatedLinkView(String idpAlias, String externalSubject, Long linkedAt) {

    public static FederatedLinkView from(final FederatedLinkEntity e) {
        return new FederatedLinkView(e.getIdpAlias(), e.getExternalSubject(),
                e.getCreationDate() == null ? null : e.getCreationDate().getTime());
    }
}
