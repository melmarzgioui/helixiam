package io.helixiam.authorization.idp.dcr;

import io.helixiam.authorization.amqp.client.ClientAdminPublisher;
import io.helixiam.authorization.amqp.client.ClientDto;
import io.helixiam.authorization.amqp.client.ClientRef;
import io.helixiam.authorization.amqp.client.ClientWriteDto;
import io.helixiam.authorization.idp.provisioning.DcrBindRequest;
import io.helixiam.authorization.idp.provisioning.DcrRegistrationDto;
import io.helixiam.authorization.idp.provisioning.DcrTokenCheck;
import io.helixiam.authorization.idp.provisioning.ProvisioningAdminPublisher;
import io.helixiam.authorization.idp.provisioning.ScimTokenCheck;
import io.helixiam.authorization.idp.scim.ScimSupport;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * Helix IAM E11: OAuth2/OIDC Dynamic Client Registration — RFC 7591 ({@code POST /connect/register}) and
 * RFC 7592 management ({@code GET/PUT/DELETE /connect/register/{clientInternalId}}). Served per realm
 * (the realm comes from the {@link RealmRoutingFilter} context). Registration creates an OIDC client over
 * the existing {@link ClientAdminPublisher} client-admin path and binds it to a {@code
 * registration_access_token} (RFC 7592). Per-realm policy: open vs initial-access-token-gated (default
 * GATED). Every endpoint returns a {@link ResponseEntity} (never throws — a thrown exception would
 * dispatch to {@code /error}, which Spring Security turns into a 302).
 */
@RestController
public class DynamicClientRegistrationController {

    private static final Logger LOG = LogManager.getLogger(DynamicClientRegistrationController.class);

    private final ClientAdminPublisher clients;
    private final ProvisioningAdminPublisher provisioning;

    public DynamicClientRegistrationController(final ClientAdminPublisher clients,
                                               final ProvisioningAdminPublisher provisioning) {
        this.clients = clients;
        this.provisioning = provisioning;
    }

    @PostMapping(value = "/connect/register", consumes = MediaType.ALL_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> register(@RequestBody final ClientRegistrationRequest body,
                                      final HttpServletRequest request) {
        final String realm = RealmContextHolder.get();
        if (realm == null) {
            return error(HttpStatus.NOT_FOUND, "invalid_request", "Unknown realm.");
        }
        // Per-realm registration policy: GATED (default) requires a valid initial access token, OPEN does not.
        final boolean open = Boolean.TRUE.equals(provisioning.isDcrOpen(realm));
        if (!open) {
            final String iat = ScimSupport.bearerToken(request);
            if (iat == null) {
                return error(HttpStatus.UNAUTHORIZED, "invalid_token",
                        "An initial access token is required (registration is gated for this realm).");
            }
            if (!Boolean.TRUE.equals(provisioning.consumeInitialAccessToken(new ScimTokenCheck(realm, iat)))) {
                return error(HttpStatus.UNAUTHORIZED, "invalid_token", "Invalid or already-used initial access token.");
            }
        }
        if (body == null) {
            return error(HttpStatus.BAD_REQUEST, "invalid_client_metadata", "Missing client metadata.");
        }
        // RFC 7591: authorization_code / implicit clients MUST register at least one redirect_uri.
        final boolean needsRedirect = body.grantTypes() == null
                || body.grantTypes().stream().anyMatch(g -> g.contains("authorization_code") || g.contains("implicit"));
        if (needsRedirect && (body.redirectUris() == null || body.redirectUris().isEmpty())) {
            return error(HttpStatus.BAD_REQUEST, "invalid_redirect_uri",
                    "At least one redirect_uri is required for the requested grant types.");
        }
        final ClientWriteDto write = DcrMapper.toWrite(realm, body);
        final ClientDto created = clients.create(write);
        if (created == null) {
            return error(HttpStatus.BAD_REQUEST, "invalid_client_metadata", "Could not register client.");
        }
        final DcrRegistrationDto binding = provisioning.bind(
                new DcrBindRequest(realm, created.id(), created.clientId()));
        final String registrationClientUri = registrationUri(created.id());
        LOG.debug("Registered DCR client {} ({}) in realm {}", created.clientId(), created.id(), realm);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(DcrMapper.toResponse(created, binding.registrationToken(), registrationClientUri));
    }

    @GetMapping(value = "/connect/register/{clientInternalId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> read(@PathVariable final String clientInternalId, final HttpServletRequest request) {
        final String realm = RealmContextHolder.get();
        final ResponseEntity<?> denied = authorizeManage(realm, clientInternalId, request);
        if (denied != null) {
            return denied;
        }
        final ClientDto client = clients.get(new ClientRef(realm, clientInternalId));
        if (client == null) {
            return error(HttpStatus.NOT_FOUND, "invalid_request", "Registration not found.");
        }
        return ResponseEntity.ok(DcrMapper.toResponse(client, null, registrationUri(clientInternalId)));
    }

    @PutMapping(value = "/connect/register/{clientInternalId}", consumes = MediaType.ALL_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> update(@PathVariable final String clientInternalId,
                                    @RequestBody final ClientRegistrationRequest body,
                                    final HttpServletRequest request) {
        final String realm = RealmContextHolder.get();
        final ResponseEntity<?> denied = authorizeManage(realm, clientInternalId, request);
        if (denied != null) {
            return denied;
        }
        final ClientDto existing = clients.get(new ClientRef(realm, clientInternalId));
        if (existing == null) {
            return error(HttpStatus.NOT_FOUND, "invalid_request", "Registration not found.");
        }
        // Preserve the surrogate id + client_id; apply the updated metadata (RFC 7592 §2.2 full replace).
        final ClientWriteDto base = DcrMapper.toWrite(realm, body);
        final ClientWriteDto write = new ClientWriteDto(realm, clientInternalId, existing.clientId(),
                base.grantTypes(), base.redirectUris(), base.scopes(), base.subjectClaim(), base.authFlowAlias(),
                base.name(), base.description(), base.postLogoutRedirectUris(), base.webOrigins(), base.publicClient(),
                base.consentRequired(), base.displayOnConsentScreen(), base.loginTheme(), base.rootUrl(),
                base.homeUrl(), base.adminUrl(), base.alwaysDisplayInConsole(), base.accessTokenLifespan(),
                base.refreshTokenLifespan(), base.idTokenSignatureAlg(), base.reuseRefreshTokens(),
                base.tokenEndpointAuthMethod(), base.jwksUrl(), base.backchannelLogoutUri(),
                base.frontchannelLogoutUri(), base.applicationId(),
                base.x509CertificateBoundAccessTokens(), base.requireSignedRequestObject(), base.jarmResponseMode());
        final ClientDto saved = clients.update(write);
        if (saved == null) {
            return error(HttpStatus.NOT_FOUND, "invalid_request", "Registration not found.");
        }
        return ResponseEntity.ok(DcrMapper.toResponse(saved, null, registrationUri(clientInternalId)));
    }

    @DeleteMapping("/connect/register/{clientInternalId}")
    public ResponseEntity<?> delete(@PathVariable final String clientInternalId, final HttpServletRequest request) {
        final String realm = RealmContextHolder.get();
        final ResponseEntity<?> denied = authorizeManage(realm, clientInternalId, request);
        if (denied != null) {
            return denied;
        }
        final boolean removed = Boolean.TRUE.equals(clients.delete(new ClientRef(realm, clientInternalId)));
        if (!removed) {
            return error(HttpStatus.NOT_FOUND, "invalid_request", "Registration not found.");
        }
        provisioning.unbind(new DcrTokenCheck(realm, clientInternalId, null));
        return ResponseEntity.noContent().build();
    }

    /** {@code null} when the registration_access_token is valid for the client, else a 401 error. */
    private ResponseEntity<?> authorizeManage(final String realm, final String clientInternalId,
                                              final HttpServletRequest request) {
        if (realm == null) {
            return error(HttpStatus.NOT_FOUND, "invalid_request", "Unknown realm.");
        }
        final String token = ScimSupport.bearerToken(request);
        if (token == null) {
            return error(HttpStatus.UNAUTHORIZED, "invalid_token", "Missing registration access token.");
        }
        if (!Boolean.TRUE.equals(provisioning.verifyRegistrationToken(
                new DcrTokenCheck(realm, clientInternalId, token)))) {
            return error(HttpStatus.UNAUTHORIZED, "invalid_token", "Invalid registration access token.");
        }
        return null;
    }

    private static String registrationUri(final String clientInternalId) {
        return ServletUriComponentsBuilder.fromCurrentContextPath()
                .path("/connect/register/").path(clientInternalId).build().toUriString();
    }

    private static ResponseEntity<DcrError> error(final HttpStatus status, final String error, final String description) {
        return ResponseEntity.status(status).body(DcrError.of(error, description));
    }
}
