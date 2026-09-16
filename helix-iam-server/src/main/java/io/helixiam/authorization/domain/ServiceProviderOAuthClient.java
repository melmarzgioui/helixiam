package io.helixiam.authorization.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.helixiam.persistence.security.AttributeEncryption;
import jakarta.persistence.*;
import org.apache.commons.lang3.StringUtils;
import org.hibernate.annotations.CreationTimestamp;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "service_provider_oauth")
@EntityListeners(AuditingEntityListener.class)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ServiceProviderOAuthClient extends RegisteredClient {

    @Id
    @JsonProperty
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "service_provider_id", updatable = false)
    private String serviceProviderId = null;

    @JsonProperty
    @Column(name = "client_id", updatable = false)
    private String clientId;

    @CreationTimestamp
    @Column(name = "client_id_issued_at", updatable = false)
    private Timestamp clientIdIssuedAt = new Timestamp(System.currentTimeMillis());

    @JsonProperty
    @Convert(converter = AttributeEncryption.class)
    @Column(name = "client_secret")
    private String clientSecret;

    @JsonProperty
    @Column(name = "authorization_grant_types")
    private String authorizationGrantTypes;

    @JsonProperty
    @Column(name = "redirect_uris")
    private String redirectUris;

    @JsonProperty
    @Column(name = "post_logout_redirect_uris")
    private String postLogoutRedirectUris;

    @JsonProperty
    @Column(name = "scopes")
    private String scopes;

    @JsonProperty
    @Column(name = "tenant_id")
    private String tenantId;

    /**
     * Helix IAM multi-tenant (MT-3): the realm (URL path slug, e.g. {@code master}/{@code gov}) this
     * client belongs to. Distinct from {@link #tenantId} (the owning org). Defaults to the admin realm
     * {@code master} so existing/platform-created clients remain reachable under {@code /realms/master}.
     */
    @JsonProperty
    @Column(name = "realm_id")
    private String realmId = "master";

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    @LastModifiedDate
    @Column(name = "modify_date")
    private Date modifyDate;

    @Column(name = "deleted")
    private Boolean deleted = false;

    /** Per-client override of the catalogue claim that populates {@code sub}; {@code null} = inherit the realm default. */
    @JsonProperty
    @Column(name = "subject_claim")
    private String subjectClaim;

    /**
     * Helix IAM (named flows): per-client override of the realm's browser login flow. {@code null} = inherit
     * the realm default ({@code browser}); otherwise the alias of a named flow this client's interactive
     * login runs (per-client flow override).
     */
    @JsonProperty
    @Column(name = "auth_flow_alias")
    private String authFlowAlias;

    /**
     * Helix IAM (Application model): the parent Application ({@code realmId|name}) this OIDC client hangs
     * below. {@code null} = standalone client (legacy). When set, the app's shared subject-claim and
     * login-flow take precedence over this client's own (app ?? client ?? realm).
     */
    @JsonProperty
    @Column(name = "application_id")
    private String applicationId;

    /** display name; {@code null} falls back to {@link #clientId} for {@code client_name}. */
    @JsonProperty
    @Column(name = "name")
    private String name;

    /** Free-text description shown in the console; not used at runtime. */
    @JsonProperty
    @Column(name = "description")
    private String description;

    /** Comma-joined browser origins allowed to call this realm's endpoints cross-origin (CORS allowlist). */
    @JsonProperty
    @Column(name = "web_origins")
    private String webOrigins;

    // --- parity Wave 1: access type + login settings + URLs ---
    /** Public client (SPA/native): authenticates with no secret and is required to use PKCE. */
    @JsonProperty
    @Column(name = "public_client")
    private Boolean publicClient = false;

    /** Show the OAuth consent screen before issuing tokens to this client. */
    @JsonProperty
    @Column(name = "consent_required")
    private Boolean consentRequired = false;

    @JsonProperty
    @Column(name = "display_on_consent_screen")
    private Boolean displayOnConsentScreen = true;

    @JsonProperty
    @Column(name = "login_theme")
    private String loginTheme;

    @JsonProperty
    @Column(name = "root_url")
    private String rootUrl;

    @JsonProperty
    @Column(name = "home_url")
    private String homeUrl;

    @JsonProperty
    @Column(name = "admin_url")
    private String adminUrl;

    @JsonProperty
    @Column(name = "always_display_in_console")
    private Boolean alwaysDisplayInConsole = false;

    // --- parity Wave 2: token tuning / fine-grain OIDC ---
    @JsonProperty
    @Column(name = "access_token_lifespan")
    private Integer accessTokenLifespan;

    @JsonProperty
    @Column(name = "refresh_token_lifespan")
    private Integer refreshTokenLifespan;

    @JsonProperty
    @Column(name = "id_token_signature_alg")
    private String idTokenSignatureAlg;

    @JsonProperty
    @Column(name = "reuse_refresh_tokens")
    private Boolean reuseRefreshTokens = false;

    /** Helix IAM (Wave 5): how the client authenticates at the token endpoint —
     *  {@code CLIENT_SECRET_BASIC} (default) or {@code PRIVATE_KEY_JWT} (signed-JWT, FAPI-grade). */
    @JsonProperty
    @Column(name = "token_endpoint_auth_method")
    private String tokenEndpointAuthMethod;

    /** Helix IAM (Wave 5): the client's JWKS URL — the server fetches it to verify {@code private_key_jwt} assertions. */
    @JsonProperty
    @Column(name = "jwks_url")
    private String jwksUrl;

    /** Helix IAM SSO P6: where to POST the signed {@code logout_token} on OIDC Back-Channel Logout; {@code null} = none. */
    @JsonProperty
    @Column(name = "backchannel_logout_uri")
    private String backchannelLogoutUri;

    /** Helix IAM SSO P6: the client's OIDC Front-Channel Logout URL, loaded in an iframe at logout; {@code null} = none. */
    @JsonProperty
    @Column(name = "frontchannel_logout_uri")
    private String frontchannelLogoutUri;

    /**
     * Helix IAM (RFC 8707 — Resource Indicators): comma/space-joined allow-list of absolute resource URIs
     * this client may request via the {@code resource} parameter. A requested {@code resource} not in this
     * list is rejected with {@code invalid_target}. {@code null}/blank = no allow-list → any (valid) resource
     * is accepted (back-compat). Not consumed by SAS directly; surfaced over AMQP for the token customizer.
     */
    @JsonProperty
    @Column(name = "allowed_resources")
    private String allowedResources;

    /** Helix IAM B11 (FAPI / RFC 8705): bind access tokens to the client's mTLS cert (cnf.x5t#S256). */
    @JsonProperty
    @Column(name = "x509_certificate_bound_access_tokens")
    private Boolean x509CertificateBoundAccessTokens = false;

    /** Helix IAM B11 (FAPI / RFC 9101): require the authorization request to be a signed Request Object. */
    @JsonProperty
    @Column(name = "require_signed_request_object")
    private Boolean requireSignedRequestObject = false;

    /** Helix IAM B11 (FAPI / JARM): JWT-secured authorization response mode; {@code null} = plain OAuth. */
    @JsonProperty
    @Column(name = "jarm_response_mode")
    private String jarmResponseMode;

    @Override
    public String getId() {
        return serviceProviderId;
    }

    @Override
    public String getClientId() {
        return clientId;
    }

    @Override
    public Instant getClientIdIssuedAt() {
        return clientIdIssuedAt.toInstant();
    }

    @Override
    public String getClientSecret() {
        if (clientSecret == null) {
            return null; // public clients have no secret
        }
        if(clientSecret.contains("noop")) {
            return clientSecret;
        }
        return "{noop}" + clientSecret;
    }

    @Override
    public Instant getClientSecretExpiresAt() {
        return null;
    }

    @Override
    public String getClientName() {
        return StringUtils.isNotBlank(name) ? name : getClientId();
    }

    @Override
    public Set<ClientAuthenticationMethod> getClientAuthenticationMethods() {
        // Public clients (SPA/native) authenticate with no credential — PKCE is what protects the flow.
        if (Boolean.TRUE.equals(publicClient)) {
            return Collections.singleton(ClientAuthenticationMethod.NONE);
        }
        // Wave 5: a confidential client may instead authenticate with a signed JWT assertion (private_key_jwt),
        // verified against its registered JWKS — no shared secret on the wire (FAPI-grade).
        if ("PRIVATE_KEY_JWT".equals(tokenEndpointAuthMethod) && StringUtils.isNotBlank(jwksUrl)) {
            return Collections.singleton(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
        }
        return Collections.singleton(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    }

    private boolean usesPrivateKeyJwt() {
        return !Boolean.TRUE.equals(publicClient)
                && "PRIVATE_KEY_JWT".equals(tokenEndpointAuthMethod) && StringUtils.isNotBlank(jwksUrl);
    }

    @Override
    public Set<AuthorizationGrantType> getAuthorizationGrantTypes() {
        final Set<AuthorizationGrantType> grantTypes = new HashSet<>();

        if(StringUtils.isNotEmpty(authorizationGrantTypes)) {
            Set.of(StringUtils.split(authorizationGrantTypes, ",")).forEach(s -> {
                grantTypes.add(new AuthorizationGrantType(s));
            });
        } else {
            grantTypes.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
        }

        return grantTypes;
    }

    @Override
    public Set<String> getRedirectUris() {
        if(StringUtils.isNotEmpty(redirectUris)) {
            return Set.of(StringUtils.split(redirectUris, ","));
        }

        return Collections.emptySet();
    }

    @Override
    public Set<String> getPostLogoutRedirectUris() {
        if(StringUtils.isNotEmpty(postLogoutRedirectUris)) {
            return Set.of(StringUtils.split(postLogoutRedirectUris, ","));
        }
        return Collections.emptySet();
    }

    @Override
    public Set<String> getScopes() {
        if(StringUtils.isNotEmpty(scopes)) {
            return Set.of(StringUtils.split(scopes, ","));
        }

        return Collections.emptySet();
    }

    @Override
    public ClientSettings getClientSettings() {
        // Public clients must use PKCE (no secret to protect the code exchange); consent is per-client.
        final ClientSettings.Builder builder = ClientSettings.builder()
                .requireAuthorizationConsent(Boolean.TRUE.equals(consentRequired))
                .requireProofKey(Boolean.TRUE.equals(publicClient));
        // Wave 5: point SAS at the client's JWKS so it can verify private_key_jwt token-endpoint assertions.
        if (usesPrivateKeyJwt()) {
            builder.jwkSetUrl(jwksUrl);
            builder.tokenEndpointAuthenticationSigningAlgorithm(
                    org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.RS256);
        }
        // B11 (FAPI): ride the resolved RegisteredClient with custom settings the authorize filters read —
        // JARM response mode + whether a signed Request Object (JAR) is mandatory. Absent → default OAuth.
        if (StringUtils.isNotBlank(jarmResponseMode)) {
            builder.setting("helix.jarm.response_mode", jarmResponseMode);
        }
        if (Boolean.TRUE.equals(requireSignedRequestObject)) {
            builder.setting("helix.jar.require_signed_request_object", Boolean.TRUE);
        }
        return builder.build();
    }

    @Override
    public TokenSettings getTokenSettings() {
        final TokenSettings.Builder builder = TokenSettings.builder()
                .accessTokenTimeToLive(accessTokenLifespan != null && accessTokenLifespan > 0
                        ? Duration.ofSeconds(accessTokenLifespan) : Duration.of(1, ChronoUnit.HOURS))
                .reuseRefreshTokens(Boolean.TRUE.equals(reuseRefreshTokens));
        if (refreshTokenLifespan != null && refreshTokenLifespan > 0) {
            builder.refreshTokenTimeToLive(Duration.ofSeconds(refreshTokenLifespan));
        }
        if (StringUtils.isNotBlank(idTokenSignatureAlg)) {
            builder.idTokenSignatureAlgorithm(
                    org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.from(idTokenSignatureAlg));
        }
        // B11 (RFC 8705): advertise mTLS sender-constraining so SAS marks the token cert-bound; the Helix
        // token customizer additionally stamps cnf.x5t#S256 from the forwarded client cert (proxy-terminated TLS).
        if (Boolean.TRUE.equals(x509CertificateBoundAccessTokens)) {
            builder.x509CertificateBoundAccessTokens(true);
        }
        return builder.build();
    }

    public void setTenantId(final String tenantId) {
        this.tenantId = tenantId;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(final String realmId) {
        this.realmId = realmId;
    }

    // --- Admin (E8.5-S3) accessors: write the raw comma-joined columns for the Clients admin API ---

    public String getTenantId() {
        return tenantId;
    }

    public Boolean getDeleted() {
        return deleted;
    }

    public void setClientId(final String clientId) {
        this.clientId = clientId;
    }

    public void setAuthorizationGrantTypes(final String authorizationGrantTypes) {
        this.authorizationGrantTypes = authorizationGrantTypes;
    }

    public void setRedirectUris(final String redirectUris) {
        this.redirectUris = redirectUris;
    }

    public void setPostLogoutRedirectUris(final String postLogoutRedirectUris) {
        this.postLogoutRedirectUris = postLogoutRedirectUris;
    }

    public void setScopes(final String scopes) {
        this.scopes = scopes;
    }


    public static class ClientBuilder extends Builder {
        public ClientBuilder(final RegisteredClient registeredClient) {
            super(registeredClient);
        }
    }

    public static RegisteredClient build(final ServiceProviderOAuthClient serviceProviderOauthClient) {
        return new ClientBuilder(serviceProviderOauthClient).build();
    }

    public void setServiceProviderId(final String serviceProviderId) {
        this.serviceProviderId = serviceProviderId;
    }

    public void setDeleted(final Boolean deleted) {
        this.deleted = deleted;
    }

    public void setClientSecret(final String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getSubjectClaim() {
        return subjectClaim;
    }

    public void setSubjectClaim(final String subjectClaim) {
        this.subjectClaim = subjectClaim;
    }

    public String getAuthFlowAlias() {
        return authFlowAlias;
    }

    public void setAuthFlowAlias(final String authFlowAlias) {
        this.authFlowAlias = authFlowAlias;
    }

    public String getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(final String applicationId) {
        this.applicationId = applicationId;
    }

    public String getName() {
        return name;
    }

    public void setName(final String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(final String description) {
        this.description = description;
    }

    /** The configured CORS origins as a set (empty when none); the comma-joined column split. */
    public Set<String> getWebOriginSet() {
        return StringUtils.isNotEmpty(webOrigins) ? Set.of(StringUtils.split(webOrigins, ",")) : Collections.emptySet();
    }

    public void setWebOrigins(final String webOrigins) {
        this.webOrigins = webOrigins;
    }

    // --- Wave 1 accessors ---
    public Boolean getPublicClient() { return publicClient; }
    public void setPublicClient(final Boolean publicClient) { this.publicClient = publicClient; }
    public Boolean getConsentRequired() { return consentRequired; }
    public void setConsentRequired(final Boolean consentRequired) { this.consentRequired = consentRequired; }
    public Boolean getDisplayOnConsentScreen() { return displayOnConsentScreen; }
    public void setDisplayOnConsentScreen(final Boolean v) { this.displayOnConsentScreen = v; }
    public String getLoginTheme() { return loginTheme; }
    public void setLoginTheme(final String loginTheme) { this.loginTheme = loginTheme; }
    public String getRootUrl() { return rootUrl; }
    public void setRootUrl(final String rootUrl) { this.rootUrl = rootUrl; }
    public String getHomeUrl() { return homeUrl; }
    public void setHomeUrl(final String homeUrl) { this.homeUrl = homeUrl; }
    public String getAdminUrl() { return adminUrl; }
    public void setAdminUrl(final String adminUrl) { this.adminUrl = adminUrl; }
    public Boolean getAlwaysDisplayInConsole() { return alwaysDisplayInConsole; }
    public void setAlwaysDisplayInConsole(final Boolean v) { this.alwaysDisplayInConsole = v; }
    // --- Wave 2 accessors ---
    public Integer getAccessTokenLifespan() { return accessTokenLifespan; }
    public void setAccessTokenLifespan(final Integer v) { this.accessTokenLifespan = v; }
    public Integer getRefreshTokenLifespan() { return refreshTokenLifespan; }
    public void setRefreshTokenLifespan(final Integer v) { this.refreshTokenLifespan = v; }
    public String getIdTokenSignatureAlg() { return idTokenSignatureAlg; }
    public void setIdTokenSignatureAlg(final String v) { this.idTokenSignatureAlg = v; }
    public Boolean getReuseRefreshTokens() { return reuseRefreshTokens; }
    public void setReuseRefreshTokens(final Boolean v) { this.reuseRefreshTokens = v; }
    public String getTokenEndpointAuthMethod() { return tokenEndpointAuthMethod; }
    public void setTokenEndpointAuthMethod(final String v) { this.tokenEndpointAuthMethod = v; }
    public String getJwksUrl() { return jwksUrl; }
    public void setJwksUrl(final String v) { this.jwksUrl = v; }
    // --- SSO P6 accessors ---
    public String getBackchannelLogoutUri() { return backchannelLogoutUri; }
    public void setBackchannelLogoutUri(final String v) { this.backchannelLogoutUri = v; }
    public String getFrontchannelLogoutUri() { return frontchannelLogoutUri; }
    public void setFrontchannelLogoutUri(final String v) { this.frontchannelLogoutUri = v; }
    // --- RFC 8707 Resource Indicators accessors ---
    /** The raw comma/space-joined allowed-resource allow-list column ({@code null}/blank = accept any). */
    public String getAllowedResources() { return allowedResources; }
    public void setAllowedResources(final String allowedResources) { this.allowedResources = allowedResources; }

    // --- B11 FAPI accessors (mTLS cert-bound tokens / signed Request Objects / JARM) ---
    public Boolean getX509CertificateBoundAccessTokens() { return x509CertificateBoundAccessTokens; }
    public void setX509CertificateBoundAccessTokens(final Boolean v) { this.x509CertificateBoundAccessTokens = v; }
    public Boolean getRequireSignedRequestObject() { return requireSignedRequestObject; }
    public void setRequireSignedRequestObject(final Boolean v) { this.requireSignedRequestObject = v; }
    public String getJarmResponseMode() { return jarmResponseMode; }
    public void setJarmResponseMode(final String v) { this.jarmResponseMode = v; }

    /** The decrypted secret without the {@code {noop}} prefix {@link #getClientSecret()} adds (for the admin reveal). */
    public String getRawSecret() {
        return clientSecret == null ? null : clientSecret.replaceFirst("^\\{noop\\}", "");
    }

    @Override
    public String toString() {
        return "ServiceProviderOAuthClient{" +
                "serviceProviderId='" + serviceProviderId + '\'' +
                ", clientId='" + clientId + '\'' +
                ", clientIdIssuedAt=" + clientIdIssuedAt +
                ", clientSecret='" + clientSecret + '\'' +
                ", authorizationGrantTypes='" + authorizationGrantTypes + '\'' +
                ", redirectUris='" + redirectUris + '\'' +
                '}';
    }
}
