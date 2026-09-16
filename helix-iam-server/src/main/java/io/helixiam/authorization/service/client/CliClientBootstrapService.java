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
 * Story 4 (CLI auth #148): seeds the built-in {@code kubedna-cli} public client into a realm so the
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
    public static final String CLI_CLIENT_ID = "kubedna-cli";

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

    public CliClientBootstrapService(final ServiceProviderRepository repository) {
        this.repository = repository;
    }

    /** Ensures the {@code kubedna-cli} public client exists in {@code realmId}. Idempotent. */
    @Transactional
    public void ensureCliClient(final String realmId) {
        if (repository.findByClientIdAndRealmIdAndDeleted(CLI_CLIENT_ID, realmId, false).isPresent()) {
            return;
        }
        final ServiceProviderOAuthClient client = new ServiceProviderOAuthClient();
        client.setClientId(CLI_CLIENT_ID);
        client.setRealmId(realmId);
        client.setTenantId(realmId);
        client.setDeleted(false);
        client.setPublicClient(true);
        client.setClientSecret(null);
        client.setName("KubeDNA CLI");
        client.setDescription("Built-in public client for the kubedna command-line tool (PKCE + device code).");
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
}
