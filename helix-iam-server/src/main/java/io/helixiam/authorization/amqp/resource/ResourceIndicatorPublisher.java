/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.resource;


import java.util.List;

/**
 * Helix IAM (RFC 8707): the publisher seam onto the realm-domain store for a client's configured
 * <b>allowed resources</b> allow-list (owned by the subscriber). Kept on its own exchange so it does
 * not contend with the scope-admin publisher. Routing keys are single dotted tokens (no hyphens) for
 * unambiguous queue binding; the subscriber listener binds the dashed form.
 */
public interface ResourceIndicatorPublisher {

    String EXCHANGE_AUTHORIZATION_RESOURCE = "exchange-authorization-resource";
    String ALLOWED_RESOURCES_FOR_CLIENT = "authorization.resource.allowedforclient";
    // Admin write of a client's allow-list. Single dotted token (no hyphens) so the subscriber's dash→dot
    // binding (authorization-resource-setallowed) resolves unambiguously.
    String SET_ALLOWED_RESOURCES = "authorization.resource.setallowed";

    /**
     * The configured allowed-resource allow-list for an OAuth client (by {@code client_id}). An empty
     * list means the client has no allow-list configured → any requested {@code resource} is accepted
     * (back-compat). Never throws — resolution failures fall back to an empty list (accept any).
     */
    List<String> allowedResourcesForClient(final String clientId);

    /** Set a client's allow-list (admin). {@code true} if the client exists; empty list clears the allow-list. */
    Boolean setAllowedResourcesForClient(final AllowedResourcesWrite write);
}
