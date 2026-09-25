/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.agent;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.helixiam.authorization.amqp.agent.AgentClientQuery;
import io.helixiam.authorization.amqp.agent.AgentIdentityDto;
import io.helixiam.authorization.amqp.agent.AgentIdentityPublisher;
import io.helixiam.authorization.amqp.realm.RealmAdminPublisher;
import io.helixiam.authorization.security.agent.AgentTokenEnricher;
import io.helixiam.authorization.security.agent.DelegationAttenuator;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Helix IAM Agent (NHI) delegation — the on-behalf-of token exchange (Phase B, RFC 8693). An agent acts
 * <em>for</em> a user by presenting the user's Helix token as {@code subject_token} and its own Helix token
 * as {@code actor_token}. Both are verified against the realm signing key; the actor must be an agent
 * ({@code nhi}) that is still ACTIVE. The minted token has {@code sub}=the user, an {@code act} actor claim
 * naming the agent (nested for chains), and roles = the INTERSECTION of the user's roles, the agent's own
 * leash (the roles on its actor token), and the requested scope — never a union, never the owner's roles.
 */
@RestController
public class DelegationTokenController {

    private static final Logger LOG = LogManager.getLogger(DelegationTokenController.class);
    private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String ISSUED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    private static final String JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final RealmAdminPublisher realmAdminPublisher;
    private final AgentIdentityPublisher agentPublisher;
    private final AuthorizationServerSettings settings;
    private final long lifetimeSeconds;
    private final boolean requireSubjectBinding;
    private final int maxChainDepth;

    public DelegationTokenController(final JwtEncoder jwtEncoder, final JWKSource<SecurityContext> jwkSource,
                                     final RealmAdminPublisher realmAdminPublisher,
                                     final AgentIdentityPublisher agentPublisher,
                                     final AuthorizationServerSettings settings,
                                     @Value("${helix.agent.delegation.token-lifetime-seconds:300}") final long lifetimeSeconds,
                                     @Value("${helix.agent.delegation.require-subject-binding:true}") final boolean requireSubjectBinding,
                                     @Value("${helix.agent.delegation.max-chain-depth:3}") final int maxChainDepth) {
        this.jwtEncoder = jwtEncoder;
        // Verify Helix-issued tokens against our own realm JWKS (kid-selected, signature + expiry).
        this.jwtDecoder = OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
        this.realmAdminPublisher = realmAdminPublisher;
        this.agentPublisher = agentPublisher;
        this.settings = settings;
        this.lifetimeSeconds = lifetimeSeconds;
        this.requireSubjectBinding = requireSubjectBinding;
        this.maxChainDepth = maxChainDepth;
    }

    @PostMapping(value = "/agent/delegation/token", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> exchange(
            @RequestParam(value = "grant_type", required = false) final String grantType,
            @RequestParam(value = "subject_token", required = false) final String subjectToken,
            @RequestParam(value = "actor_token", required = false) final String actorToken,
            @RequestParam(value = "scope", required = false) final String requestedScope,
            @RequestParam(value = "resource", required = false) final String resource,
            @RequestParam(value = "subject_token_type", required = false) final String subjectTokenType,
            @RequestParam(value = "actor_token_type", required = false) final String actorTokenType,
            @RequestParam(value = "requested_token_type", required = false) final String requestedTokenType,
            final HttpServletRequest request) {

        final String realm = RealmContextHolder.get();
        if (!TOKEN_EXCHANGE.equals(grantType) || isBlank(subjectToken) || isBlank(actorToken)) {
            return error(HttpStatus.BAD_REQUEST, "invalid_request",
                    "grant_type must be " + TOKEN_EXCHANGE + " with subject_token (the user) and actor_token (the agent)");
        }
        // RFC 8693 token-type parameters. When present the subject/actor tokens must be access tokens (or
        // the generic JWT type) — Helix presents access tokens — and requested_token_type, if given, must be
        // access_token (what this endpoint issues). Reject anything else rather than ignoring it.
        if (!tokenTypeAccepted(subjectTokenType) || !tokenTypeAccepted(actorTokenType)
                || (!isBlank(requestedTokenType) && !ISSUED_TOKEN_TYPE.equals(requestedTokenType))) {
            return error(HttpStatus.BAD_REQUEST, "invalid_request",
                    "unsupported token type parameter; subject/actor must be access_token and requested_token_type must be access_token");
        }
        final String issuer = realmIssuer(realm);

        // (1) Verify BOTH tokens against the realm signing key (signature + expiry). The signature (per-realm
        // kid via RealmJwkSource) is the real trust anchor — only this realm could have minted them.
        final Jwt userJwt;
        final Jwt agentJwt;
        try {
            userJwt = jwtDecoder.decode(subjectToken);
            agentJwt = jwtDecoder.decode(actorToken);
        } catch (final JwtException e) {
            return error(HttpStatus.UNAUTHORIZED, "invalid_grant", "a presented token failed verification");
        }

        // (2) The actor MUST be an agent (nhi) and still ACTIVE now — defends against a token minted before suspension.
        if (!Boolean.TRUE.equals(agentJwt.getClaim("nhi"))) {
            return error(HttpStatus.BAD_REQUEST, "invalid_request", "actor_token is not an agent token");
        }
        // A machine (client_credentials) Helix token identifies its client via azp/client_id; Helix also stamps
        // sub=client_id on those tokens, so sub is a reliable fallback when azp is absent.
        final String agentClientId = firstNonBlank(
                agentJwt.getClaimAsString("azp"), agentJwt.getClaimAsString("client_id"), agentJwt.getSubject());

        // (3) Pin issuers. A user (subject) token always carries the realm issuer URL. A machine agent token
        // carries iss=client_id (Helix stamps client-credentials tokens that way), so accept either for the actor.
        // Read iss as a RAW string, never via getIssuer() — that coerces to java.net.URL and throws on a
        // machine token whose iss is the (non-URL) client id.
        final String agentIss = agentJwt.getClaimAsString("iss");
        if (!issuer.equals(userJwt.getClaimAsString("iss"))) {
            return error(HttpStatus.UNAUTHORIZED, "invalid_grant", "subject_token issuer does not match this realm");
        }
        if (!issuer.equals(agentIss) && !java.util.Objects.equals(agentIss, agentClientId)) {
            return error(HttpStatus.UNAUTHORIZED, "invalid_grant", "actor_token issuer does not match this realm");
        }
        final AgentIdentityDto agent = safeFindAgent(realm, agentClientId);
        if (agent == null) {
            return error(HttpStatus.UNAUTHORIZED, "invalid_grant", "the acting agent is not registered");
        }
        final String denial = AgentTokenEnricher.denialReason(agent.status(), agent.expiresAt(), System.currentTimeMillis());
        if (denial != null) {
            return error(HttpStatus.FORBIDDEN, "invalid_grant", "delegation denied: " + denial);
        }

        // (3c) Bind the subject_token to THIS agent. Without it, any user access token the realm minted
        // (for any client, any audience) could be replayed by any registered agent on that user's behalf.
        // Require the user token to name the agent via aud/azp, or via an RFC 8693 may_act claim. (A stored
        // user->agent consent grant is a future option.) Loosen only via
        // helix.agent.delegation.require-subject-binding=false (documented, opt-in weaker mode).
        if (requireSubjectBinding && !subjectTokenAuthorizesAgent(userJwt, agentClientId)) {
            return error(HttpStatus.FORBIDDEN, "invalid_grant",
                    "subject_token is not authorized for this agent (needs aud/azp or a may_act claim naming it)");
        }

        // (3d) Cap delegation chain depth. Each exchange adds one nested `act` level; refuse to mint beyond
        // the configured maximum (helix.agent.delegation.max-chain-depth) so a delegation chain cannot grow
        // without bound.
        final Map<String, Object> priorAct = agentJwt.getClaim("act") instanceof Map ? asMap(agentJwt.getClaim("act")) : null;
        if (actDepth(priorAct) + 1 > maxChainDepth) {
            return error(HttpStatus.BAD_REQUEST, "invalid_request",
                    "delegation chain too deep (max " + maxChainDepth + ")");
        }

        // (4) Effective authority = user ∩ agent-leash ∩ requested. Only ever shrinks.
        final List<String> requested = isBlank(requestedScope) ? List.of()
                : Arrays.stream(requestedScope.split("[\\s,]+")).filter(s -> !s.isBlank()).toList();
        final List<String> effective = DelegationAttenuator.effectiveRoles(
                realmRoles(userJwt), realmRoles(agentJwt), requested);

        // (5) Mint sub=user, act={agent} (nested when the actor was itself acting), attenuated roles.
        final Instant now = Instant.now();
        final Map<String, Object> realmAccess = new LinkedHashMap<>();
        realmAccess.put("roles", new ArrayList<>(effective));
        final JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(userJwt.getSubject())
                .audience(List.of(!isBlank(resource) ? resource : agentClientId))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(lifetimeSeconds))
                .id(UUID.randomUUID().toString())
                .claim("nhi", Boolean.TRUE)
                .claim("azp", agentClientId)
                .claim("client_id", agentClientId)
                .claim("act", DelegationAttenuator.actClaim(agentClientId, priorAct))
                .claim("agent_id", agent.id())
                .claim("realm_access", realmAccess);
        if (agent.name() != null) {
            claims.claim("agent_name", agent.name());
        }
        if (!effective.isEmpty()) {
            claims.claim("scope", String.join(" ", effective));
        }
        final String accessToken = jwtEncoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(() -> "RS256").build(), claims.build())).getTokenValue();

        final Map<String, Object> body = new LinkedHashMap<>();
        body.put("access_token", accessToken);
        body.put("issued_token_type", ISSUED_TOKEN_TYPE);
        body.put("token_type", "Bearer");
        body.put("expires_in", lifetimeSeconds);
        return ResponseEntity.ok(body);
    }

    private AgentIdentityDto safeFindAgent(final String realm, final String clientId) {
        if (clientId == null) {
            return null;
        }
        try {
            return agentPublisher.findByClient(new AgentClientQuery(realm, clientId));
        } catch (final RuntimeException e) {
            LOG.debug("delegation: agent lookup failed for {}: {}", clientId, e.getMessage());
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private static List<String> realmRoles(final Jwt jwt) {
        final Object ra = jwt.getClaim("realm_access");
        if (ra instanceof Map && ((Map<String, Object>) ra).get("roles") instanceof List) {
            return (List<String>) ((Map<String, Object>) ra).get("roles");
        }
        return List.of();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(final Object o) {
        return (Map<String, Object>) o;
    }

    /**
     * True when the user's {@code subject_token} authorizes THIS agent to act for the user: the agent is in
     * the token's {@code aud}, is its {@code azp}, or is named by an RFC 8693 {@code may_act} claim
     * ({@code {"sub"|"azp"|"client_id": <agentClientId>}}).
     */
    private static boolean subjectTokenAuthorizesAgent(final Jwt userJwt, final String agentClientId) {
        if (agentClientId == null) {
            return false;
        }
        final List<String> aud = userJwt.getAudience();
        if (aud != null && aud.contains(agentClientId)) {
            return true;
        }
        if (agentClientId.equals(userJwt.getClaimAsString("azp"))) {
            return true;
        }
        if (userJwt.getClaim("may_act") instanceof Map<?, ?> mayAct) {
            for (final String key : List.of("sub", "azp", "client_id")) {
                if (agentClientId.equals(str(mayAct.get(key)))) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Depth of a nested {@code act} chain (0 for none): each level is a Map with an optional nested {@code act}. */
    private static int actDepth(final Map<String, Object> act) {
        int depth = 0;
        Object current = act;
        while (current instanceof Map<?, ?> level) {
            depth++;
            current = level.get("act");
        }
        return depth;
    }

    private String realmIssuer(final String realm) {
        String base = null;
        try {
            final var r = realmAdminPublisher.get(realm);
            if (r != null && r.issuer() != null && !r.issuer().isBlank()) {
                base = trimSlash(r.issuer().trim());
            }
        } catch (final Exception e) {
            LOG.debug("delegation issuer lookup failed for {}: {}", realm, e.getMessage());
        }
        if (base == null) {
            base = settings.getIssuer() != null ? trimSlash(settings.getIssuer())
                    : trimSlash(ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString());
        }
        final String suffix = "/realms/" + realm;
        return base.endsWith(suffix) ? base : base + suffix;
    }

    private static boolean isBlank(final String s) {
        return s == null || s.isBlank();
    }

    /** A subject/actor {@code *_token_type} is acceptable when absent, or an access-token / generic JWT type. */
    private static boolean tokenTypeAccepted(final String type) {
        return isBlank(type) || ISSUED_TOKEN_TYPE.equals(type) || JWT_TOKEN_TYPE.equals(type);
    }

    private static String firstNonBlank(final String... candidates) {
        for (final String c : candidates) {
            if (c != null && !c.isBlank()) {
                return c;
            }
        }
        return null;
    }

    private static String str(final Object o) {
        return o == null ? null : o.toString();
    }

    private static String trimSlash(final String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    private static ResponseEntity<Map<String, Object>> error(final HttpStatus status, final String error, final String desc) {
        final Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("error_description", desc);
        return ResponseEntity.status(status).body(body);
    }
}
