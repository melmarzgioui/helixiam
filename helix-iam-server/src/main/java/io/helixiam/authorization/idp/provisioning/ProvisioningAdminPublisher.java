package io.helixiam.authorization.idp.provisioning;


/**
 * Helix IAM E11: the SCIM/DCR provisioning admin API's seam onto the provisioning-domain store (owned by
 * the subscriber) — SCIM token + DCR policy, initial access tokens (RFC 7591) and registration bindings
 * (RFC 7592). The subscriber derives its binding routing key by replacing EVERY dash in the dashed queue
 * name with a dot, so these publisher routing keys must be fully dot-delimited (no dashes) to match.
 */
public interface ProvisioningAdminPublisher {

    String EXCHANGE_AUTHORIZATION_PROVISIONING_ADMIN = "exchange-authorization-provisioning-admin";
    String PROVISIONING_CONFIG_GET = "authorization.provisioning.config.get";
    String PROVISIONING_CONFIG_SAVE = "authorization.provisioning.config.save";
    String PROVISIONING_SCIM_VERIFY = "authorization.provisioning.scim.verify";
    String PROVISIONING_DCR_OPEN = "authorization.provisioning.dcr.open";
    String PROVISIONING_DCR_ISSUE_IAT = "authorization.provisioning.dcr.issueiat";
    String PROVISIONING_DCR_CONSUME_IAT = "authorization.provisioning.dcr.consumeiat";
    String PROVISIONING_DCR_BIND = "authorization.provisioning.dcr.bind";
    String PROVISIONING_DCR_VERIFY = "authorization.provisioning.dcr.verify";
    String PROVISIONING_DCR_UNBIND = "authorization.provisioning.dcr.unbind";

    /** The realm's provisioning config (defaults when no row exists). */
    ProvisioningConfigDto getConfig(final String realmId);

    /** Upsert the DCR policy and optionally rotate / clear the SCIM token. */
    ProvisioningConfigResult saveConfig(final ProvisioningConfigWriteDto write);

    /** {@code true} when the presented SCIM bearer token matches the realm's stored token. */
    Boolean verifyScimToken(final ScimTokenCheck check);

    /** {@code true} when the realm permits open (un-gated) Dynamic Client Registration. */
    Boolean isDcrOpen(final String realmId);

    /** Mint an initial access token (RFC 7591 §1.2); returned once. */
    String issueInitialAccessToken(final String realmId);

    /** Validate + consume (single-use) an initial access token; {@code true} when it was valid. */
    Boolean consumeInitialAccessToken(final ScimTokenCheck check);

    /** Bind a freshly-created OAuth client to a new registration_access_token (returned once). */
    DcrRegistrationDto bind(final DcrBindRequest request);

    /** {@code true} when the registration_access_token matches the client's binding (RFC 7592 auth). */
    Boolean verifyRegistrationToken(final DcrTokenCheck check);

    /** Forget a client's registration binding (called when the client is deleted via RFC 7592). */
    Boolean unbind(final DcrTokenCheck check);
}
