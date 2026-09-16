/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.federation;

import io.helixiam.authorization.domain.UserCredentials;

/**
 * Helix IAM E5.3: the federation broker's seam onto the identity domain (owned by the subscriber),
 * over AMQP. Backs {@code AmqpFederatedIdentityStore} (link lookup / email lookup / link creation /
 * JIT provisioning) and the passwordless session load that establishes a SecurityContext after a
 * successful external login. JSON-marshalled, two-copy DTOs (like the login + flow exchanges).
 *
 * <p>{@link #loadUser(String)} is deliberately passwordless and is the security-sensitive op: it
 * loads a user purely by id, so it must be reachable ONLY from this server-internal exchange and
 * called ONLY after the external IdP (or a verified link) has authenticated the subject.
 */
public interface FederatedIdentityPublisher {

    String EXCHANGE_AUTHORIZATION_FEDERATION = "exchange-authorization-federation";
    String AUTHORIZATION_FEDERATION_LINK_FIND = "authorization.federation.link.find";
    String AUTHORIZATION_FEDERATION_USER_EMAIL = "authorization.federation.user.email";
    String AUTHORIZATION_FEDERATION_LINK_CREATE = "authorization.federation.link.create";
    String AUTHORIZATION_FEDERATION_USER_PROVISION = "authorization.federation.user.provision";
    String AUTHORIZATION_FEDERATION_USER_LOAD = "authorization.federation.user.load";

    /** The local user id linked to this external identity, or {@code null} if none. */
    String findLinkedUser(final FederatedLinkLookup lookup);

    /** The local user id whose username (email) equals this email, or {@code null} if none. */
    String findUserByEmail(final String email);

    /** Record (or overwrite) the federated link; returns {@code true} on success. */
    Boolean link(final FederatedLink link);

    /** JIT-provision a conservative federated user; returns its generated id. */
    String provisionUser(final FederatedUserProvision provision);

    /** Passwordless load of a user by id, to establish the post-federation session. */
    UserCredentials loadUser(final String userId);
}
