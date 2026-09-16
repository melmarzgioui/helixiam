/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.saml;


import java.util.List;

/**
 * Helix IAM: the admin API's + SAML IdP's seam onto the identity-domain store (owned by the subscriber)
 * for managing per-realm SAML2 relying parties (SPs). JSON-marshalled two-copy DTOs, like the federation
 * exchanges. The SAML IdP reads the same store at request time to resolve the calling SP.
 */
public interface SamlRelyingPartyConfigPublisher {

    String EXCHANGE_AUTHORIZATION_SAML_CONFIG = "exchange-authorization-saml-config";
    String SAML_RP_SAVE = "authorization.saml.rp.save";
    String SAML_RP_LIST = "authorization.saml.rp.list";
    String SAML_RP_GET = "authorization.saml.rp.get";
    String SAML_RP_DELETE = "authorization.saml.rp.delete";

    /** Create or update a relying party; returns the persisted state. */
    SamlRelyingPartyConfig save(final SamlRelyingPartyConfig config);

    /** All relying parties for a realm. */
    List<SamlRelyingPartyConfig> list(final String realmId);

    /** A single relying party, or {@code null} if none. */
    SamlRelyingPartyConfig get(final SamlRelyingPartyRef ref);

    /** Remove a relying party; {@code false} if it did not exist. */
    Boolean delete(final SamlRelyingPartyRef ref);
}
