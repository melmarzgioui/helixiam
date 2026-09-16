/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.federation.eid.EidProviderConfig;
import io.helixiam.authorization.federation.oidc.OidcProviderConfig;
import io.helixiam.authorization.federation.saml.SamlProviderConfig;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Helix IAM E5.4: declarative federation configuration ({@code helix.federation.*}). Each entry
 * becomes a runtime {@link io.helixiam.authorization.federation.spi.IdentityProvider} via
 * {@link FederationProviderFactory}, so onboarding an external IdP is configuration, not code.
 *
 * <ul>
 *   <li>{@code helix.federation.oidc[*]} — generic OIDC providers (full {@link OidcProviderConfig}).</li>
 *   <li>{@code helix.federation.social[*]} — social presets (Google/Microsoft): the operator supplies
 *       only a client id + secret (+ tenant for Microsoft); endpoints come from the preset.</li>
 *   <li>{@code helix.federation.saml[*]} — SAML2 IdPs Helix consumes as an SP ({@link SamlProviderConfig}).</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "helix.federation")
public class FederationProviderProperties {

    private List<OidcProviderConfig> oidc = new ArrayList<>();
    private List<SocialEntry> social = new ArrayList<>();
    private List<SamlProviderConfig> saml = new ArrayList<>();
    private List<EidProviderConfig> eid = new ArrayList<>();

    public List<OidcProviderConfig> getOidc() {
        return oidc;
    }

    public void setOidc(final List<OidcProviderConfig> oidc) {
        this.oidc = oidc == null ? new ArrayList<>() : oidc;
    }

    public List<SocialEntry> getSocial() {
        return social;
    }

    public void setSocial(final List<SocialEntry> social) {
        this.social = social == null ? new ArrayList<>() : social;
    }

    public List<SamlProviderConfig> getSaml() {
        return saml;
    }

    public void setSaml(final List<SamlProviderConfig> saml) {
        this.saml = saml == null ? new ArrayList<>() : saml;
    }

    public List<EidProviderConfig> getEid() {
        return eid;
    }

    public void setEid(final List<EidProviderConfig> eid) {
        this.eid = eid == null ? new ArrayList<>() : eid;
    }

    /**
     * A social-login preset entry: the well-known provider name plus Helix's client credentials at it.
     * {@code tenant} is only used by Microsoft Entra ID ("common" for multi-tenant).
     */
    public record SocialEntry(String provider, String clientId, String clientSecret, String tenant) {
    }
}
