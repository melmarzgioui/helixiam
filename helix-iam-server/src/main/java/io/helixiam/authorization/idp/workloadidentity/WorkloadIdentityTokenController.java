package io.helixiam.authorization.idp.workloadidentity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.helixiam.authorization.amqp.clientrole.ClientRolePublisher;
import io.helixiam.authorization.amqp.clientrole.ServiceAccountRoleDto;
import io.helixiam.authorization.amqp.realm.RealmAdminPublisher;
import io.helixiam.authorization.amqp.workloadidentity.WorkloadIdentityConfigPublisher;
import io.helixiam.authorization.amqp.workloadidentity.WorkloadIdentityCredentialDto;
import io.helixiam.authorization.amqp.workloadidentity.WorkloadIdentityResolveQuery;
import io.helixiam.authorization.security.mapper.RoleClaimAssembler;
import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Helix IAM WIF — the keyless token-exchange endpoint. A workload (a Kubernetes pod with a projected
 * ServiceAccount token, a CI job with an OIDC id-token) POSTs its issuer-signed JWT here and receives a
 * realm-signed Helix access token in return — <b>no client secret</b>. Served realm-prefixed at
 * {@code POST /realms/{realm}/workload-identity/token}; the {@link io.helixiam.authorization.security.realm.RealmRoutingFilter}
 * strips the realm into {@link RealmContextHolder} before MVC, so this maps at the bare path.
 *
 * <p>The exchange is RFC 8693-shaped: {@code grant_type=urn:ietf:params:oauth:grant-type:token-exchange},
 * {@code subject_token}=the workload JWT. The endpoint (1) reads the JWT's {@code iss/sub/aud} <i>without
 * trusting them</i> to select a registered credential, (2) cryptographically verifies the JWT against the
 * credential's issuer JWKS with the credential's expected {@code iss/aud/sub} via {@link WorkloadTokenVerifier},
 * and only then (3) mints the Helix token for the credential's mapped client identity. Every failure maps
 * to one generic {@code invalid_grant} 401 (no enumeration of which check failed).
 */
@RestController
public class WorkloadIdentityTokenController {

    private static final Logger LOG = LogManager.getLogger(WorkloadIdentityTokenController.class);
    private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String ISSUED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    private final WorkloadIdentityConfigPublisher credentials;
    private final WorkloadTokenVerifier verifier;
    private final JwtEncoder jwtEncoder;
    private final RealmAdminPublisher realmAdminPublisher;
    private final ClientRolePublisher clientRolePublisher;
    private final AuthorizationServerSettings settings;
    private final AuditLog auditLog;
    private final long lifetimeSeconds;

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final ObjectMapper mapper = new ObjectMapper();
    private final WorkloadExchangeRateLimiter rateLimiter = new WorkloadExchangeRateLimiter();

    public WorkloadIdentityTokenController(final WorkloadIdentityConfigPublisher credentials,
                                           final WorkloadTokenVerifier verifier, final JwtEncoder jwtEncoder,
                                           final RealmAdminPublisher realmAdminPublisher,
                                           final ClientRolePublisher clientRolePublisher,
                                           final AuthorizationServerSettings settings, final AuditLog auditLog,
                                           @Value("${helix.workload-identity.token-lifetime-seconds:900}") final long lifetimeSeconds) {
        this.credentials = credentials;
        this.verifier = verifier;
        this.jwtEncoder = jwtEncoder;
        this.realmAdminPublisher = realmAdminPublisher;
        this.clientRolePublisher = clientRolePublisher;
        this.settings = settings;
        this.auditLog = auditLog;
        this.lifetimeSeconds = lifetimeSeconds;
    }

    @PostMapping(value = "/workload-identity/token", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> exchange(
            @RequestParam(value = "grant_type", required = false) final String grantType,
            @RequestParam(value = "subject_token", required = false) final String subjectToken,
            @RequestParam(value = "scope", required = false) final String requestedScope,
            final HttpServletRequest request) {

        final String realm = RealmContextHolder.get();
        final String sourceIp = AuditContext.clientIp(request);

        if (!TOKEN_EXCHANGE.equals(grantType) || subjectToken == null || subjectToken.isBlank()) {
            return error(HttpStatus.BAD_REQUEST, "invalid_request",
                    "grant_type must be " + TOKEN_EXCHANGE + " and subject_token is required");
        }
        if (!rateLimiter.allow(realm, sourceIp)) {
            return error(HttpStatus.TOO_MANY_REQUESTS, "slow_down", "too many exchange attempts");
        }

        // (1) Read iss/sub/aud WITHOUT trusting them — only to select which credential's trust policy applies.
        final JWTClaimsSet unverified;
        try {
            unverified = SignedJWT.parse(subjectToken).getJWTClaimsSet();
        } catch (final Exception e) {
            return denied(realm, null, sourceIp, "malformed subject_token");
        }
        final String iss = unverified.getIssuer();
        final String sub = unverified.getSubject();
        final List<String> auds = unverified.getAudience() == null ? List.of() : unverified.getAudience();
        if (iss == null || sub == null || auds.isEmpty()) {
            return denied(realm, sub, sourceIp, "subject_token missing iss/sub/aud");
        }

        final WorkloadIdentityCredentialDto credential = resolve(realm, iss, sub, auds);
        if (credential == null) {
            return denied(realm, sub, sourceIp, "no matching workload identity credential");
        }

        // (2) Cryptographic gate — verify against the issuer JWKS using the credential's EXPECTED iss/aud/sub.
        try {
            final String jwksUri = jwksUriFor(credential);
            verifier.verify(verifier.jwkSource(jwksUri), credential.issuer(), credential.audience(),
                    credential.subject(), subjectToken);
        } catch (final Exception e) {
            LOG.debug("WIF verification failed for realm={} sub={}: {}", realm, sub, e.getMessage());
            return denied(realm, sub, sourceIp, "subject_token verification failed");
        }

        // (3) Mint the Helix access token for the mapped client identity.
        final String accessToken = mint(realm, credential, iss, sub);
        auditLog.emit(AuditEvent.authn(AuditContext.nowIso(), "WORKLOAD_TOKEN_ISSUED", realm, credential.clientId(),
                sourceIp, "SUCCESS", Map.of("issuer", iss, "subject", sub)));

        final Map<String, Object> body = new LinkedHashMap<>();
        body.put("access_token", accessToken);
        body.put("issued_token_type", ISSUED_TOKEN_TYPE);
        body.put("token_type", "Bearer");
        body.put("expires_in", lifetimeSeconds);
        final String scope = effectiveScope(credential, requestedScope);
        if (scope != null) {
            body.put("scope", scope);
        }
        return ResponseEntity.ok(body);
    }

    /** Find a credential matching (realm, iss, sub) and any of the token's audiences. */
    private WorkloadIdentityCredentialDto resolve(final String realm, final String iss, final String sub,
                                                  final List<String> auds) {
        for (final String aud : auds) {
            try {
                final WorkloadIdentityCredentialDto c = credentials.resolve(
                        new WorkloadIdentityResolveQuery(realm, iss, sub, aud));
                if (c != null) {
                    return c;
                }
            } catch (final Exception e) {
                LOG.warn("WIF credential resolution failed for realm={}: {}", realm, e.getMessage());
            }
        }
        return null;
    }

    /** The credential's explicit JWKS URI, else the issuer's discovered {@code jwks_uri}. */
    private String jwksUriFor(final WorkloadIdentityCredentialDto credential) throws Exception {
        if (credential.jwksUri() != null && !credential.jwksUri().isBlank()) {
            return credential.jwksUri().trim();
        }
        final String discovery = credential.issuer() + "/.well-known/openid-configuration";
        final HttpResponse<String> resp = http.send(
                HttpRequest.newBuilder(URI.create(discovery)).header("Accept", "application/json")
                        .timeout(Duration.ofSeconds(5)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new IllegalStateException("issuer discovery returned " + resp.statusCode());
        }
        final JsonNode jwks = mapper.readTree(resp.body()).path("jwks_uri");
        if (jwks.isMissingNode() || jwks.asText().isBlank()) {
            throw new IllegalStateException("issuer discovery has no jwks_uri");
        }
        return jwks.asText();
    }

    /** A realm-signed access token whose subject is the credential's mapped client identity. */
    private String mint(final String realm, final WorkloadIdentityCredentialDto credential, final String iss,
                        final String sub) {
        final Instant now = Instant.now();
        final JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .issuer(realmIssuer(realm))
                .subject(credential.clientId())
                .audience(List.of(credential.clientId()))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(lifetimeSeconds))
                .id(UUID.randomUUID().toString())
                .claim("client_id", credential.clientId())
                .claim("azp", credential.clientId())
                .claim("wif", true)
                .claim("workload_iss", iss)
                .claim("workload_sub", sub);
        final String scope = effectiveScope(credential, null);
        if (scope != null) {
            claims.claim("scope", scope);
        }
        // The workload acts as the bound client's service account, so the minted token carries that
        // client's service-account roles (realm_access/resource_access) — the same grants
        // a client_credentials token for that client would carry. Best-effort: a role lookup failure or an
        // unbound/role-less client simply yields a scope-only token.
        try {
            roleClaims(clientRolePublisher.serviceAccountRoles(
                    io.helixiam.authorization.support.RealmScopedKey.pack(realm, credential.clientId()))).forEach(claims::claim);
        } catch (final Exception e) {
            LOG.warn("WIF role resolution failed for client {}, issuing a scope-only token: {}",
                    credential.clientId(), e.getMessage());
        }
        return jwtEncoder.encode(JwtEncoderParameters.from(
                JwsHeader.with(() -> "RS256").build(), claims.build())).getTokenValue();
    }

    /**
     * Maps a client's resolved service-account grants into role claims
     * ({@code realm_access.roles} + {@code resource_access.<clientId>.roles}) via {@link RoleClaimAssembler}.
     * Empty/null in ⇒ empty out (no role claims on the token).
     */
    static Map<String, Object> roleClaims(final List<ServiceAccountRoleDto> saRoles) {
        if (saRoles == null || saRoles.isEmpty()) {
            return Map.of();
        }
        final List<RoleClaimAssembler.TypedRole> typed = new ArrayList<>();
        for (final ServiceAccountRoleDto r : saRoles) {
            typed.add(new RoleClaimAssembler.TypedRole(r.roleName(), r.roleType(), r.roleClientId()));
        }
        return RoleClaimAssembler.assemble(Set.of(), typed);
    }

    /** Scopes granted to the minted token: the requested subset of the credential's scopes, else all of them. */
    private static String effectiveScope(final WorkloadIdentityCredentialDto credential, final String requested) {
        if (credential.scopes() == null || credential.scopes().isBlank()) {
            return null;
        }
        final java.util.Set<String> granted = new java.util.LinkedHashSet<>(
                List.of(credential.scopes().trim().split("\\s+")));
        if (requested == null || requested.isBlank()) {
            return String.join(" ", granted);
        }
        final java.util.List<String> narrowed = new java.util.ArrayList<>();
        for (final String s : requested.trim().split("\\s+")) {
            if (granted.contains(s)) {
                narrowed.add(s);
            }
        }
        return narrowed.isEmpty() ? null : String.join(" ", narrowed);
    }

    /** The realm-prefixed issuer {@code {base}/realms/{realm}} (mirrors the OIDC discovery issuer). */
    private String realmIssuer(final String realm) {
        String base = null;
        try {
            final var r = realmAdminPublisher.get(realm);
            if (r != null && r.issuer() != null && !r.issuer().isBlank()) {
                base = trimSlash(r.issuer().trim());
            }
        } catch (final Exception e) {
            LOG.debug("WIF issuer: realm {} lookup failed, falling back: {}", realm, e.getMessage());
        }
        if (base == null) {
            base = settings.getIssuer() != null ? trimSlash(settings.getIssuer())
                    : trimSlash(ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString());
        }
        final String suffix = "/realms/" + realm;
        return base.endsWith(suffix) ? base : base + suffix;
    }

    private ResponseEntity<Map<String, Object>> denied(final String realm, final String sub, final String sourceIp,
                                                       final String reason) {
        auditLog.emit(AuditEvent.authn(AuditContext.nowIso(), "WORKLOAD_TOKEN_DENIED", realm,
                sub == null ? AuditContext.ANONYMOUS : sub, sourceIp, "DENIED", Map.of("reason", reason)));
        // Generic invalid_grant — never reveal which check failed (no credential enumeration).
        return error(HttpStatus.UNAUTHORIZED, "invalid_grant", "the subject_token could not be exchanged");
    }

    private static ResponseEntity<Map<String, Object>> error(final HttpStatus status, final String code,
                                                             final String description) {
        final Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", code);
        body.put("error_description", description);
        return ResponseEntity.status(status).body(body);
    }

    private static String trimSlash(final String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
