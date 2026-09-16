/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.saml;

import io.helixiam.authorization.amqp.saml.SamlSpOptions;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Helix IAM E7.1: configuration for Helix's SAML2 Identity Provider role ({@code helix.idp.saml.*}) —
 * the IdP entity id + signing material, and the registered relying parties (SPs) allowed to start SSO.
 * Registering the RP (with its exact ACS URL) is what prevents an attacker pointing the signed
 * assertion at an arbitrary callback.
 */
@ConfigurationProperties(prefix = "helix.idp.saml")
public class SamlIdpProperties {

    private boolean enabled;
    private String entityId;
    private String signingCertificate;
    private String signingPrivateKey;
    private List<RelyingParty> relyingParties = new ArrayList<>();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(final boolean enabled) {
        this.enabled = enabled;
    }

    public String getEntityId() {
        return entityId;
    }

    public void setEntityId(final String entityId) {
        this.entityId = entityId;
    }

    public String getSigningCertificate() {
        return signingCertificate;
    }

    public void setSigningCertificate(final String signingCertificate) {
        this.signingCertificate = signingCertificate;
    }

    public String getSigningPrivateKey() {
        return signingPrivateKey;
    }

    public void setSigningPrivateKey(final String signingPrivateKey) {
        this.signingPrivateKey = signingPrivateKey;
    }

    public List<RelyingParty> getRelyingParties() {
        return relyingParties;
    }

    public void setRelyingParties(final List<RelyingParty> relyingParties) {
        this.relyingParties = relyingParties == null ? new ArrayList<>() : relyingParties;
    }

    public SamlIdpConfig toIdpConfig() {
        return new SamlIdpConfig(entityId, signingCertificate, signingPrivateKey);
    }

    /**
     * A registered SAML relying party (SP).
     *
     * @param entityId            the SP entity id (the AuthnRequest issuer + assertion audience)
     * @param assertionConsumerServiceUrl the SP ACS the signed Response is POSTed to (allow-listed)
     * @param defaultAuthnContextClassRef the AuthnContextClassRef to assert (LoA)
     * @param singleLogoutServiceUrl the SP's SLO endpoint — where Helix sends the signed LogoutResponse and,
     *                               for Single Logout fan-out, a signed LogoutRequest ({@code null} = no SLO)
     * @param signingCertificate  the SP's signing cert (PEM) — Helix validates the SP's signed LogoutRequest
     *                            against it ({@code null} = signature not enforced, parity with SSO)
     */
    public record RelyingParty(String entityId, String assertionConsumerServiceUrl,
                               String defaultAuthnContextClassRef, String singleLogoutServiceUrl,
                               String signingCertificate, SamlSpOptions options) {

        /** Back-compat constructor for the static {@code helix.idp.saml.relyingParties[*]} config (defaults). */
        public RelyingParty(final String entityId, final String assertionConsumerServiceUrl,
                            final String defaultAuthnContextClassRef, final String singleLogoutServiceUrl,
                            final String signingCertificate) {
            this(entityId, assertionConsumerServiceUrl, defaultAuthnContextClassRef, singleLogoutServiceUrl,
                    signingCertificate, SamlSpOptions.defaults());
        }

        /** The advanced options, never null. */
        public SamlSpOptions opts() {
            return options == null ? SamlSpOptions.defaults() : options;
        }
    }
}
