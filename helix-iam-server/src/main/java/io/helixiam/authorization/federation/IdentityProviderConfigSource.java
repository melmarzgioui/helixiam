/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;

import java.util.List;

/**
 * Helix IAM E8.3: the seam the federation registry reads stored identity-provider configs from. In
 * production this is backed by the admin/config store over AMQP; in tests it's a simple stub. Keeping
 * it an interface lets the registry refresh from the DB without coupling to the transport.
 */
@FunctionalInterface
public interface IdentityProviderConfigSource {

    /** The persisted identity-provider configs for a realm. */
    List<IdentityProviderConfig> load(String realmId);
}
