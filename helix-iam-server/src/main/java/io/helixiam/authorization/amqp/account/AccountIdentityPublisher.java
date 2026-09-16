/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.account;


import java.util.List;

/**
 * Helix IAM B9: the account console's seam onto the identity-domain store for the signed-in user's
 * federated-identity links — list their connected accounts and disconnect one. The userId always comes
 * from the authenticated principal in the controller, never from the request body/path.
 */
public interface AccountIdentityPublisher {

    String EXCHANGE_AUTHORIZATION_ACCOUNT_IDENTITIES = "exchange-authorization-account-identities";
    String IDENTITIES_LIST = "authorization.account.identities.list";
    String IDENTITIES_UNLINK = "authorization.account.identities.unlink";

    /** The caller's connected federated identities. */
    List<FederatedLinkDto> list(final String userId);

    /** Disconnect one provider for the caller; {@code false} if they had no such link. */
    Boolean unlink(final AccountUnlinkRef ref);
}
