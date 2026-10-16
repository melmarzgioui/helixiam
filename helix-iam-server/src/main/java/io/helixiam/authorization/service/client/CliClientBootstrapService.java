/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.client;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Story 4 (CLI auth #148): seeds the built-in {@code helix-cli} public client into a realm so the
 * command-line tool works against any Helix deployment out of the box — no admin has to register it first.
 *
 * <p>It is a native/public app: no client secret, PKCE required ({@link ServiceProviderOAuthClient} maps
 * {@code publicClient=true} to {@code ClientAuthenticationMethod.NONE} + {@code requireProofKey(true)}). It
 * supports three grants: {@code authorization_code} (browser login via a loopback redirect, RFC 8252),
 * {@code refresh_token} (silent refresh), and {@code urn:ietf:params:oauth:grant-type:device_code} (headless
 * login, RFC 8628). Idempotent — a client already present in the realm is left untouched.
 */
@Service
public class CliClientBootstrapService {

    /** The stable client id the CLI authenticates as in every realm. */
    public static final String CLI_CLIENT_ID = "helix-cli";

    private static final Logger LOG = LogManager.getLogger(CliClientBootstrapService.class);

    private static final String GRANT_TYPES =
            "authorization_code,refresh_token,urn:ietf:params:oauth:grant-type:device_code";
    // Loopback redirect URIs for the native-app browser flow (RFC 8252 §7.3). The CLI binds an ephemeral
    // loopback port at login; the authorization server matches loopback redirects ignoring the port, and a
    // couple of fixed fallbacks are registered for environments that require an exact match.
    private static final String REDIRECT_URIS =
            "http://127.0.0.1/callback,http://localhost/callback,http://127.0.0.1:8765/callback";
    private static final String SCOPES = "openid,profile,email,offline_access";
    // 30-day refresh-token lifespan. With rotation (reuseRefreshTokens=false, the default), each silent refresh
    // issues a new 30-day token — a sliding idle window: used within 30 days ⇒ stays signed in; 30 days idle ⇒
    // re-login. The publisher's NativeAppRefreshTokenGenerator lets this public native-app client hold one.
    private static final int REFRESH_TOKEN_LIFESPAN_SECONDS = 30 * 24 * 60 * 60;

    private final ServiceProviderRepository repository;
    private io.helixiam.authorization.security.audit.AuditLog audit;

    public CliClientBootstrapService(final ServiceProviderRepository repository) {
        this.repository = repository;
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setAuditLog(final io.helixiam.authorization.security.audit.AuditLog audit) {
        this.audit = audit;
    }

    /**
     * Ensures the {@code helix-cli} public client exists in {@code realmId} and reconciles its sign-in settings.
     * Idempotent.
     *
     * <p>Round 6: before 1.0 a client manager could create a client named {@code helix-cli} in a realm that did not
     * have one yet, with its own redirect URIs or a secret, and so receive the authorization codes of administrators
     * signing in with the CLI. Creating a client with that id now needs realm-admin, and every start resets what
     * decides where codes and tokens go to the built-in values: public client, no secret, the built-in grant types and
     * the loopback redirect URIs. A client that differed is logged as a warning and audited
     * ({@code SIGN_IN_CLIENT_RECONCILED}); its name, scopes, flow and other settings stay as they are.
     */
    @Transactional
    public void ensureCliClient(final String realmId) {
        final java.util.Optional<ServiceProviderOAuthClient> existing =
                repository.findByClientIdAndRealmIdAndDeleted(CLI_CLIENT_ID, realmId, false);
        if (existing.isPresent()) {
            reconcile(realmId, existing.get());
            return;
        }
        final ServiceProviderOAuthClient client = new ServiceProviderOAuthClient();
        client.setClientId(CLI_CLIENT_ID);
        client.setRealmId(realmId);
        client.setTenantId(realmId);
        client.setDeleted(false);
        client.setPublicClient(true);
        client.setClientSecret(null);
        client.setName("HelixIAM CLI");
        client.setDescription("Built-in public client for command-line tools (PKCE + device code).");
        client.setAuthorizationGrantTypes(GRANT_TYPES);
        client.setRedirectUris(REDIRECT_URIS);
        client.setScopes(SCOPES);
        client.setRefreshTokenLifespan(REFRESH_TOKEN_LIFESPAN_SECONDS);
        client.setReuseRefreshTokens(false); // rotate on every refresh → sliding 30-day idle window
        client.setConsentRequired(false);
        client.setDisplayOnConsentScreen(false);
        repository.save(client);
        LOG.info("Seeded built-in '{}' public CLI client in realm {}", CLI_CLIENT_ID, realmId);
    }

    private void reconcile(final String realmId, final ServiceProviderOAuthClient client) {
        final java.util.List<String> changed = new java.util.ArrayList<>();
        if (!Boolean.TRUE.equals(client.getPublicClient())) {
            changed.add("publicClient");
        }
        if (client.getClientSecret() != null && !client.getClientSecret().isBlank()) {
            changed.add("clientSecret");
        }
        if (!client.getRedirectUris().equals(java.util.Set.of(REDIRECT_URIS.split(",")))) {
            changed.add("redirectUris");
        }
        final java.util.Set<String> grants = new java.util.HashSet<>();
        client.getAuthorizationGrantTypes().forEach(g -> grants.add(g.getValue()));
        if (!grants.equals(java.util.Set.of(GRANT_TYPES.split(",")))) {
            changed.add("grantTypes");
        }
        if (changed.isEmpty()) {
            return;
        }
        client.setPublicClient(true);
        client.setClientSecret(null);
        client.setRedirectUris(REDIRECT_URIS);
        client.setAuthorizationGrantTypes(GRANT_TYPES);
        repository.save(client);
        LOG.warn("The built-in '{}' client of realm {} differed from the built-in sign-in settings ({}); reset them. "
                + "Check who created or changed it.", CLI_CLIENT_ID, realmId, String.join(", ", changed));
        if (audit != null) {
            audit.emit(io.helixiam.authorization.security.audit.AuditEvent.admin(
                    io.helixiam.authorization.security.audit.AuditContext.nowIso(), "SIGN_IN_CLIENT_RECONCILED",
                    realmId, "system", null, "client", CLI_CLIENT_ID, "SUCCESS",
                    java.util.Map.of("fields", String.join(",", changed))));
        }
    }
}
