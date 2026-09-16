/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.client;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Seeds the standard public {@code helix-console} OIDC client (authorization_code + PKCE, no secret)
 * into a realm so the admin console can log in via SSO — its session then shows on the Sessions
 * screen and is Single-Logout-revocable, like Keycloak's {@code security-admin-console}.
 *
 * <p>Mirrors {@link CliClientBootstrapService}: subscriber-side, direct repository save, idempotent
 * ({@code publicClient=true} maps to {@code ClientAuthenticationMethod.NONE} + {@code
 * requireProofKey(true)} on the entity, so PKCE is required and no secret is stored). Unlike the CLI
 * seeder this is a browser SPA, so it also sets web origins (CORS) + a callback redirect URI.
 *
 * <p>On every run it reconciles the redirect / web-origin / post-logout values from {@code
 * HELIX_CONSOLE_BASE_URL}, so changing the deployment URL and restarting fixes login without a
 * manual client edit. Combined with the wiring into the realm-bootstrap paths, a deleted client is
 * recreated on the next restart (self-heal).
 */
@Service
public class ConsoleClientBootstrapService {

  /** The stable client id the admin console authenticates as in every realm. */
  public static final String CONSOLE_CLIENT_ID = "helix-console";

  private static final Logger LOG = LogManager.getLogger(ConsoleClientBootstrapService.class);
  private static final String GRANT_TYPES = "authorization_code";
  private static final String SCOPES = "openid,profile";

  private final ServiceProviderRepository repository;
  private final String baseUrl;

  public ConsoleClientBootstrapService(
      final ServiceProviderRepository repository,
      @Value("${helix.console.base-url:http://localhost:8180}") final String baseUrl) {
    this.repository = repository;
    this.baseUrl = stripTrailingSlash(baseUrl);
  }

  /** Ensures the {@code helix-console} public client exists in {@code realmId}. Idempotent. */
  @Transactional
  public void ensureConsoleClient(final String realmId) {
    final ServiceProviderOAuthClient existing =
        repository.findByClientIdAndRealmIdAndDeleted(CONSOLE_CLIENT_ID, realmId, false).orElse(null);
    final ServiceProviderOAuthClient client = existing != null ? existing : newClient(realmId);
    // Reconcile deployment-URL-derived config on every run (create AND update paths).
    client.setRedirectUris(baseUrl + "/console/callback");
    client.setPostLogoutRedirectUris(baseUrl + "/");
    client.setWebOrigins(baseUrl);
    repository.save(client);
    if (existing == null) {
      LOG.info("Seeded built-in '{}' console client in realm {}", CONSOLE_CLIENT_ID, realmId);
    }
  }

  private ServiceProviderOAuthClient newClient(final String realmId) {
    final ServiceProviderOAuthClient c = new ServiceProviderOAuthClient();
    c.setClientId(CONSOLE_CLIENT_ID);
    c.setRealmId(realmId);
    c.setTenantId(realmId);
    c.setDeleted(false);
    c.setPublicClient(true); // → ClientAuthenticationMethod.NONE + requireProofKey(true)
    c.setClientSecret(null);
    c.setName("Helix Admin Console");
    c.setDescription("Built-in public client for the Helix admin console (authorization_code + PKCE).");
    c.setAuthorizationGrantTypes(GRANT_TYPES);
    c.setScopes(SCOPES);
    c.setConsentRequired(false);
    c.setDisplayOnConsentScreen(false);
    return c;
  }

  private static String stripTrailingSlash(final String s) {
    return s != null && s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
  }
}
