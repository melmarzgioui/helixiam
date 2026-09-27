/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.client;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.domain.client.role.ServiceAccountRoleDto;
import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import io.helixiam.authorization.service.realm.RealmAdminBootstrapService;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * C5: a bootstrap service account for provisioning, so automation never has to sign in as the bootstrap admin user
 * (and operators never have to switch MFA off globally for that).
 *
 * <p>When {@code helix.bootstrap.client-id} ({@code HELIX_BOOTSTRAP_CLIENT_ID}) is set, the first boot creates a
 * confidential {@code client_credentials} client with that id in the {@code master} realm, with the secret from
 * {@code helix.bootstrap.client-secret} ({@code HELIX_BOOTSTRAP_CLIENT_SECRET}) or, preferably, the file named by
 * {@code helix.bootstrap.client-secret-file} ({@code HELIX_BOOTSTRAP_CLIENT_SECRET_FILE}, e.g. a mounted Kubernetes
 * secret; the file wins when both are set). The secret must be 32–120 printable ASCII characters and is stored like
 * any client secret. Its service account gets the master realm's {@code admin} role, which administers every realm
 * through the admin API with a bearer token.
 *
 * <p>Idempotent and create-only: when a client with that id already exists in {@code master}, nothing is changed
 * (an operator may have rotated its secret or narrowed its roles since); rotate with
 * {@code POST /admin/realms/master/clients/{id}/secret}. A missing or unacceptable secret is logged as an error and
 * no client is created — the value itself is never logged.
 */
@Service
public class BootstrapServiceAccountService {

    private static final Logger LOG = LogManager.getLogger(BootstrapServiceAccountService.class);

    private final ServiceProviderRepository clients;
    private final ClientRoleAdminService roles;
    private final String clientId;
    private final String secret;
    private final String secretFile;

    public BootstrapServiceAccountService(final ServiceProviderRepository clients, final ClientRoleAdminService roles,
                                          @Value("${helix.bootstrap.client-id:}") final String clientId,
                                          @Value("${helix.bootstrap.client-secret:}") final String secret,
                                          @Value("${helix.bootstrap.client-secret-file:}") final String secretFile) {
        this.clients = clients;
        this.roles = roles;
        this.clientId = clientId == null ? "" : clientId.trim();
        this.secret = secret;
        this.secretFile = secretFile == null ? "" : secretFile.trim();
    }

    /** Outcome of {@link #ensureBootstrapServiceAccount()}. */
    public enum Result { NOT_CONFIGURED, CREATED, EXISTS, INVALID_SECRET }

    /** Creates the bootstrap service account on first boot (see class doc). */
    @Transactional
    public Result ensureBootstrapServiceAccount() {
        if (clientId.isEmpty()) {
            return Result.NOT_CONFIGURED;
        }
        final String realm = RealmConfig.ADMIN_REALM_ID;
        if (clients.findByClientIdAndRealmIdAndDeleted(clientId, realm, false).isPresent()) {
            LOG.debug("Bootstrap service account {} already exists in realm {}; left unchanged",
                    LogSafe.sanitize(clientId), realm);
            return Result.EXISTS;
        }
        final String resolved = resolveSecret();
        if (!ClientAdminService.isValidSecret(resolved)) {
            LOG.error("Bootstrap service account {} NOT created: set HELIX_BOOTSTRAP_CLIENT_SECRET_FILE (or "
                    + "HELIX_BOOTSTRAP_CLIENT_SECRET) to a secret of 32 to 120 printable ASCII characters without spaces",
                    LogSafe.sanitize(clientId));
            return Result.INVALID_SECRET;
        }
        final ServiceProviderOAuthClient client = new ServiceProviderOAuthClient();
        client.setClientId(clientId);
        client.setRealmId(realm);
        client.setTenantId(realm);
        client.setDeleted(false);
        client.setPublicClient(false);
        client.setClientSecret(resolved); // stored exactly like every client secret (encrypted at rest)
        client.setName("Bootstrap service account");
        client.setDescription("Created from HELIX_BOOTSTRAP_CLIENT_ID for provisioning through the admin API.");
        client.setAuthorizationGrantTypes("client_credentials");
        client.setRedirectUris("");
        client.setScopes("openid");
        client.setConsentRequired(false);
        client.setDisplayOnConsentScreen(false);
        clients.save(client);
        roles.assignServiceAccountRole(new ServiceAccountRoleDto(null, realm, clientId,
                RealmAdminBootstrapService.ADMIN_ROLE, "REALM", null));
        LOG.info("Created bootstrap service account {} in realm {} with the '{}' role",
                LogSafe.sanitize(clientId), realm, RealmAdminBootstrapService.ADMIN_ROLE);
        return Result.CREATED;
    }

    /** The secret from the file (trailing newline trimmed) when one is configured, else the plain setting. */
    String resolveSecret() {
        if (!secretFile.isEmpty()) {
            try {
                return Files.readString(Path.of(secretFile), StandardCharsets.UTF_8).strip();
            } catch (final IOException e) {
                // Nothing from the secret setting is logged, not even the file's path (CodeQL #260).
                LOG.error("Could not read the file named by HELIX_BOOTSTRAP_CLIENT_SECRET_FILE: {}",
                        LogSafe.sanitize(e.getClass().getSimpleName()));
                return null;
            }
        }
        return secret == null ? null : secret.strip();
    }
}
