package group.mfnr.authorization.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import group.mfnr.authorization.amqp.ServiceProviderPublisher;
import group.mfnr.authorization.amqp.agent.AgentClientQuery;
import group.mfnr.authorization.amqp.agent.AgentIdentityDto;
import group.mfnr.authorization.amqp.agent.AgentIdentityPublisher;
import group.mfnr.authorization.amqp.clientrole.ClientRolePublisher;
import group.mfnr.authorization.amqp.mapper.ClientMapperPublisher;
import group.mfnr.authorization.amqp.mapper.ProtocolMapperDto;
import group.mfnr.authorization.amqp.scope.ClaimScopePublisher;
import group.mfnr.authorization.amqp.user.UserPublisher;
import group.mfnr.authorization.security.mapper.ProtocolMapperResolver;
import group.mfnr.authorization.security.mapper.RoleClaimAssembler;
import group.mfnr.authorization.service.UserInfoService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import group.mfnr.authorization.security.agent.AgentTokenEnricher;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
public class OAuthConfig {

    private static final Logger LOG = LogManager.getLogger(OAuthConfig.class);

    private final ServiceProviderPublisher serviceProviderPublisher;

    @Autowired
    public OAuthConfig(final ServiceProviderPublisher serviceProviderPublisher) {
        this.serviceProviderPublisher = serviceProviderPublisher;
    }

    /** SSO P6: a JwtEncoder over the realm JWKS so we can sign logout_tokens with the realm's active key. */
    @Bean
    public org.springframework.security.oauth2.jwt.JwtEncoder helixJwtEncoder(final JWKSource<SecurityContext> jwkSource) {
        return new org.springframework.security.oauth2.jwt.NimbusJwtEncoder(jwkSource);
    }

    /**
     * Story 1 (CLI browser login): the SAS token generator, but with {@link NativeAppRefreshTokenGenerator}
     * in place of the default refresh-token generator so a native-app public client (the kubedna-cli, RFC 8252)
     * gets a rotating refresh token on the authorization_code grant and stays signed in. The JWT access-token
     * path is unchanged — same realm-aware encoder + the same {@code jwtTokenCustomizer} (roles, claims, etc.).
     */
    @Bean
    public org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator<? extends org.springframework.security.oauth2.core.OAuth2Token> tokenGenerator(
            final org.springframework.security.oauth2.jwt.JwtEncoder helixJwtEncoder,
            final OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer) {
        final org.springframework.security.oauth2.server.authorization.token.JwtGenerator jwtGenerator =
                new org.springframework.security.oauth2.server.authorization.token.JwtGenerator(helixJwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtTokenCustomizer);
        final org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator accessTokenGenerator =
                new org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator();
        final group.mfnr.authorization.security.device.NativeAppRefreshTokenGenerator refreshTokenGenerator =
                new group.mfnr.authorization.security.device.NativeAppRefreshTokenGenerator();
        return new org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator(
                jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    /**
     * B11 (FAPI / RFC 8705): resolves the client certificate that should bind an access token. The header
     * name is where a TLS-terminating proxy (KubeDNA api-gateway) forwards the verified client cert; real
     * JVM-terminated mTLS is read from the servlet X509 attribute regardless of this value.
     */
    @Bean
    public group.mfnr.authorization.security.fapi.ClientCertificateResolver clientCertificateResolver(
            @org.springframework.beans.factory.annotation.Value("${helix.fapi.client-cert-header:X-Client-Cert}") final String header) {
        return new group.mfnr.authorization.security.fapi.ClientCertificateResolver(header);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        // E1.4: keys are served from the realm key store (ACTIVE signs new tokens; ROTATED
        // keys stay published for the verification overlap), refreshed on a short TTL so a
        // rotation propagates without a restart. The kid is still derived from the key
        // modulus, so tokens issued before the cutover keep verifying.
        return new RealmJwkSource(serviceProviderPublisher);
    }


    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer(final UserInfoService userInfoService,
                                                                        final UserPublisher userPublisher,
                                                                        final ClaimScopePublisher claimScopePublisher,
                                                                        final ClientMapperPublisher clientMapperPublisher,
                                                                        final ClientRolePublisher clientRolePublisher,
                                                                        final group.mfnr.authorization.amqp.org.OrganizationAdminPublisher organizationAdminPublisher,
                                                                        final group.mfnr.authorization.amqp.resource.ResourceIndicatorPublisher resourceIndicatorPublisher,
                                                                        final group.mfnr.authorization.observability.HelixMetrics helixMetrics,
                                                                        final group.mfnr.authorization.security.fapi.ClientCertificateResolver clientCertificateResolver,
                                                                        final AgentIdentityPublisher agentIdentityPublisher) {
        return context -> {
            // The principal's effective roles, Keycloak-namespaced: realm roles under `realm_access.roles`
            // and client roles under `resource_access.<clientId>.roles` (never one flat ambiguous list).
            // The flat union is kept only to feed any USER_ROLE protocol mapper.
            final ResolvedRoles resolved = resolveRoles(context, userPublisher, clientRolePublisher);
            context.getClaims().claims(claims -> claims.putAll(resolved.claims()));

            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) || "id_token".equals(context.getTokenType().getValue())) {
                final Map<String, String> profile = userInfoService.getOidcClaimProfile(context.getPrincipal().getName());
                context.getClaims().claims(claims -> claims.putAll(profile));
                applySubjectOverride(context, profile, claimScopePublisher);
                applyProtocolMappers(context, profile, resolved.flat(), clientMapperPublisher);
                // (#9) B2B Organizations: the principal's org memberships as the `organizations` claim.
                applyOrganizations(context, organizationAdminPublisher);
            }

            if (context.getAuthorizationGrantType() == AuthorizationGrantType.CLIENT_CREDENTIALS) {
                // sub/aud = client id, but keep the realm issuer SAS already set so any RFC 9068 / MCP
                // resource server can validate the token (Helix used to wrongly stamp iss = client id).
                MachineTokenCustomizer.applyMachineTokenIdentity(context);
                // Agent (NHI): if this client_credentials client is a registered agent, gate on its lifecycle
                // (a suspended/revoked/expired agent is denied a token) and stamp the `nhi.*` identity claims.
                applyAgentIdentity(context, agentIdentityPublisher);
            }

            // (#18, RFC 8707) Resource Indicators: when a `resource` was requested + allowed, narrow the
            // access-token audience to it. No-op (default audience untouched) when no resource was requested.
            group.mfnr.authorization.security.resource.ResourceIndicatorTokenCustomizer
                    .applyResourceIndicators(context, resourceIndicatorPublisher);

            // B11 (FAPI / RFC 8705): when the client opts into mTLS-bound tokens, stamp cnf.x5t#S256 from the
            // presented/forwarded client certificate so a resource server can verify proof-of-possession.
            applyCertificateBinding(context, clientCertificateResolver);

            // Wave 3 observability: count issued tokens per grant type (bounded vocabulary). Swallows internally.
            helixMetrics.recordTokenIssued(
                    group.mfnr.authorization.security.realm.RealmContextHolder.get(),
                    context.getAuthorizationGrantType() != null ? context.getAuthorizationGrantType().getValue() : null);
        };
    }

    /**
     * Helix IAM Agent (NHI): when a {@code client_credentials} client is a registered agent, enforce its
     * lifecycle at the moment of issuance and stamp the {@code nhi.*} identity. A registry hiccup never
     * breaks token issuance (the lookup is best-effort); a positively-resolved agent that is suspended,
     * revoked or expired is denied with an OAuth2 {@code invalid_client} error so the kill-switch is real.
     */
    private static void applyAgentIdentity(final JwtEncodingContext context,
                                           final AgentIdentityPublisher agentIdentityPublisher) {
        if (context.getRegisteredClient() == null) {
            return;
        }
        final String realm = group.mfnr.authorization.security.realm.RealmContextHolder.get();
        final String clientId = context.getRegisteredClient().getClientId();
        final AgentIdentityDto agent;
        try {
            agent = agentIdentityPublisher.findByClient(new AgentClientQuery(realm, clientId));
        } catch (final RuntimeException e) {
            LOG.debug("Agent enrichment skipped for client {} in realm {}: {}", clientId, realm, e.getMessage());
            return;
        }
        if (agent == null) {
            return; // an ordinary machine client, not an agent
        }
        final String denial = AgentTokenEnricher.denialReason(agent.status(), agent.expiresAt(),
                System.currentTimeMillis());
        if (denial != null) {
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_client",
                    "agent token denied: " + denial, null));
        }
        context.getClaims().claims(claims -> claims.putAll(AgentTokenEnricher.claims(agent)));
        // The agent's OWN least-privilege roles (bound 1), unioned ON TOP of whatever the bound client's
        // service account already granted — never the owner's roles. Plain names → realm_access.roles;
        // {@code clientId/roleName} entries → resource_access.{clientId}.roles.
        final java.util.List<String> realmRoles = AgentTokenEnricher.realmRolesFrom(agent.roles());
        if (!realmRoles.isEmpty()) {
            context.getClaims().claims(claims -> AgentTokenEnricher.mergeRealmRoles(claims, realmRoles));
        }
        final java.util.Map<String, java.util.List<String>> clientRoles = AgentTokenEnricher.clientRolesFrom(agent.roles());
        if (!clientRoles.isEmpty()) {
            context.getClaims().claims(claims -> AgentTokenEnricher.mergeClientRoles(claims, clientRoles));
        }
    }

    /**
     * Helix IAM (#9) B2B Organizations: expose the principal's org memberships as the {@code organizations}
     * claim — an array of {id,name,roles}. Mutable collections only (the SAS Jackson allowlist rejects
     * immutable ones in token claims). Swallows failures so token issuance never breaks on an org lookup.
     */
    private static void applyOrganizations(final JwtEncodingContext context,
                                           final group.mfnr.authorization.amqp.org.OrganizationAdminPublisher organizationAdminPublisher) {
        try {
            final java.util.List<group.mfnr.authorization.amqp.org.OrgMembershipDto> memberships =
                    organizationAdminPublisher.memberships(context.getPrincipal().getName());
            if (memberships == null || memberships.isEmpty()) {
                return;
            }
            final java.util.List<Map<String, Object>> orgs = new java.util.ArrayList<>();
            for (final group.mfnr.authorization.amqp.org.OrgMembershipDto m : memberships) {
                final Map<String, Object> org = new java.util.HashMap<>();
                org.put("id", m.id());
                org.put("name", m.name());
                org.put("roles", new java.util.ArrayList<>(m.roles() == null ? java.util.List.of() : m.roles()));
                orgs.add(org);
            }
            context.getClaims().claims(claims -> claims.put("organizations", orgs));
        } catch (final Exception e) {
            LOG.warn("Organization claim resolution failed for {}, omitting: {}",
                    context.getPrincipal().getName(), e.getMessage());
        }
    }

    /**
     * Helix IAM B11 (FAPI / RFC 8705 — Mutual-TLS sender-constrained tokens): when the client has
     * {@code x509CertificateBoundAccessTokens} enabled and a client certificate is presented (real mTLS or
     * forwarded by a TLS-terminating proxy), stamp the access token's {@code cnf} claim with the cert's
     * {@code x5t#S256} thumbprint — coexisting with any DPoP {@code jkt}. No-op (token unchanged) when the
     * client doesn't opt in or no cert is present. Swallows failures so token issuance never breaks.
     */
    private static void applyCertificateBinding(final JwtEncodingContext context,
                                                final group.mfnr.authorization.security.fapi.ClientCertificateResolver resolver) {
        try {
            if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())
                    || context.getRegisteredClient() == null
                    || !context.getRegisteredClient().getTokenSettings().isX509CertificateBoundAccessTokens()) {
                return;
            }
            final org.springframework.web.context.request.ServletRequestAttributes attrs =
                    (org.springframework.web.context.request.ServletRequestAttributes)
                            org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();
            if (attrs == null) {
                return;
            }
            resolver.resolve(attrs.getRequest()).ifPresent(cert -> {
                final String x5t = group.mfnr.authorization.security.fapi.CertificateThumbprint.x5tS256(cert);
                context.getClaims().claims(claims -> claims.put("cnf",
                        group.mfnr.authorization.security.fapi.MtlsConfirmation.mergeX5t(claims.get("cnf"), x5t)));
            });
        } catch (final Exception e) {
            LOG.warn("mTLS certificate binding failed, issuing an unbound token: {}", e.getMessage());
        }
    }

    /** The Keycloak-namespaced role claims plus the flat union (the latter only feeds the USER_ROLE mapper). */
    private record ResolvedRoles(Map<String, Object> claims, Set<String> flat) {
    }

    /**
     * Helix IAM (Wave 4): the principal's effective roles, split into realm vs client scope. A user's
     * {@code user_in_role} grants are realm roles; for a {@code client_credentials} token the service
     * account's grants are typed (REALM/CLIENT) and routed accordingly. Returns the claim
     * map ({@code realm_access}/{@code resource_access}) and a flat union for the USER_ROLE mapper. Swallows
     * failures so token issuance never breaks on a role lookup.
     */
    private static ResolvedRoles resolveRoles(final JwtEncodingContext context, final UserPublisher userPublisher,
                                              final ClientRolePublisher clientRolePublisher) {
        final Set<String> realmBase = new java.util.HashSet<>();
        try {
            final Set<String> base = userPublisher.getUserInRoles(context.getPrincipal().getName());
            if (base != null) {
                realmBase.addAll(base);
            }
        } catch (final Exception ignored) {
            // base-role lookup failed — fall through with whatever we have
        }

        final List<RoleClaimAssembler.TypedRole> typed = new java.util.ArrayList<>();
        if (context.getAuthorizationGrantType() == AuthorizationGrantType.CLIENT_CREDENTIALS) {
            try {
                final List<group.mfnr.authorization.amqp.clientrole.ServiceAccountRoleDto> saRoles =
                        clientRolePublisher.serviceAccountRoles(group.mfnr.authorization.support.RealmScopedKey.pack(
                                group.mfnr.authorization.security.realm.RealmContextHolder.get(),
                                context.getRegisteredClient().getClientId()));
                if (saRoles != null) {
                    saRoles.forEach(r -> typed.add(new RoleClaimAssembler.TypedRole(r.roleName(), r.roleType(), r.roleClientId())));
                }
            } catch (final Exception e) {
                LOG.warn("Service-account role resolution failed for client {}, keeping base roles: {}",
                        context.getRegisteredClient().getClientId(), e.getMessage());
            }
        }

        final Map<String, Object> claims = RoleClaimAssembler.assemble(realmBase, typed);
        // Flat union (realm + every client's roles) for the USER_ROLE protocol mapper only.
        final Set<String> flat = new java.util.HashSet<>(realmBase);
        typed.forEach(r -> flat.add(r.name()));
        return new ResolvedRoles(claims, Collections.unmodifiableSet(flat));
    }

    /**
     * Helix IAM E8.5: replace the OIDC {@code sub} with the value of the client's effective subject
     * claim (client override, else realm default). When the effective claim is the default {@code sub},
     * the native subject identifier is kept. Any failure leaves {@code sub} untouched so token issuance
     * never breaks on a config lookup.
     */
    private static void applySubjectOverride(final JwtEncodingContext context, final Map<String, String> profile,
                                             final ClaimScopePublisher claimScopePublisher) {
        try {
            final String subjectClaim = claimScopePublisher.subjectForClient(group.mfnr.authorization.support.RealmScopedKey.pack(
                    group.mfnr.authorization.security.realm.RealmContextHolder.get(),
                    context.getRegisteredClient().getClientId()));
            if (subjectClaim == null || subjectClaim.isBlank() || "sub".equals(subjectClaim)) {
                return;
            }
            final String value = profile.get(subjectClaim);
            if (value != null && !value.isBlank()) {
                context.getClaims().subject(value);
            }
        } catch (final Exception e) {
            LOG.warn("Subject-claim override failed for client {}, keeping default sub: {}",
                    context.getRegisteredClient().getClientId(), e.getMessage());
        }
    }

    /**
     * Helix IAM (Wave 3): inject the client's standalone protocol mappers into the token. {@code USER_ATTRIBUTE}
     * mappers copy a profile attribute into the configured claim; {@code HARDCODED} mappers emit a literal value;
     * {@code USER_ROLE} mappers emit the principal's roles as a list claim. The {@code access}/{@code id} token
     * flags decide which token each mapper contributes to. Any failure is swallowed so token issuance never
     * breaks on a mapper lookup.
     */
    private static void applyProtocolMappers(final JwtEncodingContext context, final Map<String, String> profile,
                                             final Set<String> roles, final ClientMapperPublisher clientMapperPublisher) {
        try {
            final List<ProtocolMapperDto> mappers = clientMapperPublisher.forClient(group.mfnr.authorization.support.RealmScopedKey.pack(
                    group.mfnr.authorization.security.realm.RealmContextHolder.get(),
                    context.getRegisteredClient().getClientId()));
            if (mappers == null || mappers.isEmpty()) {
                return;
            }
            final boolean accessToken = OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType());
            final Map<String, Object> claims = ProtocolMapperResolver.claimsForTokenType(mappers, profile, roles, accessToken);
            if (!claims.isEmpty()) {
                context.getClaims().claims(c -> c.putAll(claims));
            }
        } catch (final Exception e) {
            LOG.warn("Protocol-mapper resolution failed for client {}, skipping mapped claims: {}",
                    context.getRegisteredClient().getClientId(), e.getMessage());
        }
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }
}
