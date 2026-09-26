/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import io.helixiam.authorization.amqp.client.ClientAdminPublisher;
import io.helixiam.authorization.amqp.client.ClientDto;
import io.helixiam.authorization.amqp.client.ClientWriteDto;
import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.amqp.user.UserWriteDto;
import io.helixiam.authorization.service.RealmService;
import io.helixiam.authorization.service.flow.AuthFlowService;
import io.helixiam.authorization.service.realm.RealmAdminBootstrapService;
import io.helixiam.authorization.service.role.DefaultRolesBootstrapService;
import org.springframework.context.ApplicationContext;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Test-data seeding for the e2e harness. Goes through the SAME Spring beans the admin REST controllers
 * call ({@code ClientAdminController} → {@link ClientAdminPublisher}, {@code UserAdminController} →
 * {@link UserAdminPublisher}), so a seeded client/user is exactly what the console would create — just
 * without the HTTP hop (use {@link E2eAdminSession} when the admin API itself is under test).
 *
 * <p>Realm creation mirrors {@code RealmBootstrap}/{@code TenantService.create}: realm config row +
 * tenant/admin role/admin user + curated default roles + the built-in browser flow. There is no
 * {@code POST /admin/realms} endpoint today; {@code TenantService.create} needs a security context, so the
 * individual idempotent services are called instead.
 *
 * <p>Names shared across the single cached context must be unique: use {@link #unique(String)}.
 */
public final class E2eSeed {

    /** Redirect URI registered on seeded clients; never actually requested — tests read {@code code} off the 302. */
    public static final String REDIRECT_URI = "http://localhost/cb";

    private final ClientAdminPublisher clients;
    private final UserAdminPublisher users;
    private final RealmService realms;
    private final RealmAdminBootstrapService realmAdmins;
    private final DefaultRolesBootstrapService defaultRoles;
    private final AuthFlowService flows;

    public E2eSeed(final ApplicationContext context) {
        this.clients = context.getBean(ClientAdminPublisher.class);
        this.users = context.getBean(UserAdminPublisher.class);
        this.realms = context.getBean(RealmService.class);
        this.realmAdmins = context.getBean(RealmAdminBootstrapService.class);
        this.defaultRoles = context.getBean(DefaultRolesBootstrapService.class);
        this.flows = context.getBean(AuthFlowService.class);
    }

    /** {@code prefix-<8 hex>}: unique across test classes sharing the one database. */
    public static String unique(final String prefix) {
        return prefix + "-" + UUID.randomUUID().toString().substring(0, 8);
    }

    /** Creates (idempotently) a realm with its tenant, admin role + admin user, default roles and browser flow. */
    public void realm(final String realmId) {
        realm(realmId, realmId);
    }

    /** As {@link #realm(String)} with a display name (shown on login/MFA pages and as the TOTP issuer). */
    public void realm(final String realmId, final String displayName) {
        realms.createIfAbsent(realmId, displayName);
        realmAdmins.ensureRealmAdmin(realmId);
        defaultRoles.ensureDefaultRoles(realmId);
        flows.ensureBrowserFlow(realmId);
    }

    /**
     * A confidential ({@code client_secret_basic}) client with {@code authorization_code} + {@code refresh_token},
     * redirect URI {@link #REDIRECT_URI}, no consent. PKCE is not <i>required</i> for confidential clients but
     * SAS enforces the verifier whenever a challenge was sent, which {@link OidcFlow} always does.
     */
    public SeededClient confidentialClient(final String realmId, final String clientId, final List<String> scopes) {
        return client(realmId, clientId, List.of("authorization_code", "refresh_token"),
                List.of(REDIRECT_URI), scopes, false);
    }

    /** Same as {@link #confidentialClient} but with {@code consentRequired=true} (exercises the consent page). */
    public SeededClient consentClient(final String realmId, final String clientId, final List<String> scopes) {
        return client(realmId, clientId, List.of("authorization_code", "refresh_token"),
                List.of(REDIRECT_URI), scopes, true);
    }

    /** A {@code client_credentials} service-account client. */
    public SeededClient serviceAccountClient(final String realmId, final String clientId, final List<String> scopes) {
        return client(realmId, clientId, List.of("client_credentials"), List.of(), scopes, false);
    }

    /** Low-level client creation through {@link ClientAdminPublisher#create}; returns the one-time secret. */
    public SeededClient client(final String realmId, final String clientId, final List<String> grantTypes,
                               final List<String> redirectUris, final List<String> scopes, final boolean consent) {
        final ClientDto saved = clients.create(new ClientWriteDto(realmId, null, clientId, grantTypes, redirectUris,
                scopes, null, null, clientId, "e2e test client", List.of(), List.of(),
                false, consent, true, null, null, null, null, false,
                null, null, null, false, null, null, null, null, null, false, false, null));
        if (saved == null || saved.secret() == null) {
            throw new AssertionError("Client creation returned no secret for " + clientId);
        }
        return new SeededClient(realmId, saved.id(), clientId, saved.secret(),
                redirectUris.isEmpty() ? null : redirectUris.get(0), saved);
    }

    /** An enabled, unlocked realm user with a password (Argon2id-encoded by the service). */
    public SeededUser user(final String realmId, final String username, final String password) {
        return user(realmId, username, password, Map.of());
    }

    /** As {@link #user(String, String, String)} with profile attributes. */
    public SeededUser user(final String realmId, final String username, final String password,
                           final Map<String, String> attributes) {
        final UserAdminDto saved = users.create(new UserWriteDto(realmId, null, username,
                username + "@e2e.helixiam.test", password, true, false, attributes));
        if (saved == null || saved.userId() == null) {
            throw new AssertionError("User creation failed for " + username);
        }
        return new SeededUser(realmId, saved.userId(), username, password, saved);
    }

    /** A seeded OAuth client; {@code secret} is the one-time plaintext secret. */
    public record SeededClient(String realmId, String id, String clientId, String secret, String redirectUri,
                               ClientDto dto) {
    }

    /** A seeded user; {@code userId} is the opaque id the server uses as the principal name / {@code sub}. */
    public record SeededUser(String realmId, String userId, String username, String password, UserAdminDto dto) {
    }
}
