/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.client;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.domain.client.admin.ClientDto;
import io.helixiam.authorization.domain.client.admin.ClientWriteDto;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Helix IAM E8.5-S3: OAuth client administration — register/update/delete the confidential clients
 * (relying parties) that trust a realm, over the existing {@code service_provider_oauth} store.
 * Secrets are generated server-side and returned exactly once (on create / regenerate).
 */
@Service
public class ClientAdminService {

    private static final Logger LOG = LogManager.getLogger(ClientAdminService.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final ServiceProviderRepository repository;

    @Autowired
    public ClientAdminService(final ServiceProviderRepository repository) {
        this.repository = repository;
    }

    /** All active clients registered in the realm (never exposes secrets). */
    public List<ClientDto> list(final String realmId) {
        return repository.findAllByTenantIdAndDeleted(realmId, false).stream().map(c -> toDto(c, null)).toList();
    }

    /** A single client by surrogate id. */
    public Optional<ClientDto> get(final String realmId, final String id) {
        return inRealm(realmId, id).map(c -> toDto(c, null));
    }

    /** Registers a new confidential client; returns it with the one-time generated secret. */
    @Transactional
    public ClientDto create(final ClientWriteDto write) {
        // Invariant guard: a client must have a clientId.
        if (write.clientId() == null || write.clientId().isBlank()) {
            throw new IllegalArgumentException("Client ID is required.");
        }
        final boolean publicClient = Boolean.TRUE.equals(write.publicClient());
        final String supplied = write.clientSecret();
        if (supplied != null) {
            requireSettableSecret(supplied, publicClient);
        }
        // Public clients (SPA/native) authenticate with no secret — PKCE protects the code exchange.
        // C2: a caller-supplied secret is stored exactly like a generated one, but never returned.
        final String secret = publicClient ? null : supplied != null ? supplied : generateSecret();
        final ServiceProviderOAuthClient client = new ServiceProviderOAuthClient();
        client.setClientId(write.clientId());
        client.setTenantId(write.realmId());
        // The realm the client is reachable under (/realms/{realm}/oauth2/…). Left unset it defaulted to master,
        // so every client created in another realm was unreachable there and collided on client_id (1.0 item 2).
        client.setRealmId(write.realmId());
        client.setDeleted(false);
        client.setClientSecret(secret);
        applyWrite(client, write);
        final ServiceProviderOAuthClient saved = repository.save(client);
        LOG.debug("Registered client {} in realm {}", LogSafe.sanitize(write.clientId()), LogSafe.sanitize(write.realmId()));
        return toDto(saved, supplied != null ? null : secret);
    }

    /**
     * Updates a client's grant types / redirect URIs / scopes. The secret is unchanged unless the write carries a
     * caller-supplied {@code clientSecret} (C2), which replaces it (never returned).
     */
    @Transactional
    public Optional<ClientDto> update(final ClientWriteDto write) {
        if (write.clientSecret() != null) {
            requireSettableSecret(write.clientSecret(), Boolean.TRUE.equals(write.publicClient()));
        }
        return inRealm(write.realmId(), write.id()).map(client -> {
            applyWrite(client, write);
            if (write.clientSecret() != null) {
                client.setClientSecret(write.clientSecret());
            }
            return toDto(repository.save(client), null);
        });
    }

    /** Outcome of {@link #setSecret}. */
    public enum SetSecretResult { SET, NOT_FOUND, PUBLIC_CLIENT }

    /**
     * C2: sets a caller-chosen secret (from a secrets manager) on a confidential client of {@code realmId}. Stored
     * exactly like a generated secret; the value is never returned or logged.
     */
    @Transactional
    public SetSecretResult setSecret(final String realmId, final String id, final String secret) {
        requireSettableSecret(secret, false);
        return inRealm(realmId, id).map(client -> {
            if (Boolean.TRUE.equals(client.getPublicClient())) {
                return SetSecretResult.PUBLIC_CLIENT;
            }
            client.setClientSecret(secret);
            repository.save(client);
            LOG.debug("Set a caller-supplied secret on client {} in realm {}", LogSafe.sanitize(client.getClientId()),
                    LogSafe.sanitize(realmId));
            return SetSecretResult.SET;
        }).orElse(SetSecretResult.NOT_FOUND);
    }

    /** Minimum length of a caller-supplied secret (C2). */
    public static final int MIN_SECRET_LENGTH = 32;
    /** Maximum length: the AES-GCM-encrypted, Base64-encoded value must fit {@code client_secret varchar(200)}. */
    public static final int MAX_SECRET_LENGTH = 120;

    /**
     * The service-side guard behind the admin API's Bean Validation (the realm import writes through here without
     * it): 32–120 printable ASCII characters, and only on a confidential client. The message never carries the value.
     */
    public static void requireSettableSecret(final String secret, final boolean publicClient) {
        if (publicClient) {
            throw new IllegalArgumentException("A public client has no secret.");
        }
        if (!isValidSecret(secret)) {
            throw new IllegalArgumentException(
                    "The client secret must be 32 to 120 printable ASCII characters without spaces.");
        }
    }

    /** Whether {@code secret} is an acceptable caller-supplied client secret. */
    public static boolean isValidSecret(final String secret) {
        if (secret == null || secret.length() < MIN_SECRET_LENGTH || secret.length() > MAX_SECRET_LENGTH) {
            return false;
        }
        return secret.chars().allMatch(ch -> ch >= 0x21 && ch <= 0x7E);
    }

    /** Reveals a client's current secret (Credentials tab); the rest of the DTO is the client as-is. */
    public Optional<ClientDto> reveal(final String realmId, final String id) {
        return inRealm(realmId, id).map(c -> toDto(c, c.getRawSecret()));
    }

    /** Issues a fresh secret for a client; returns it once. */
    @Transactional
    public Optional<ClientDto> regenerateSecret(final String realmId, final String id) {
        return inRealm(realmId, id).map(client -> {
            final String secret = generateSecret();
            client.setClientSecret(secret);
            return toDto(repository.save(client), secret);
        });
    }

    /** Soft-deletes a client (the OAuth server stops resolving it); {@code false} if absent. */
    @Transactional
    public boolean delete(final String realmId, final String id) {
        return inRealm(realmId, id).map(client -> {
            // Protect the built-in console/CLI clients: deleting them would lock admins out of the console /
            // break the CLI. They self-heal on restart anyway, but refuse the delete so the UI can't remove them.
            if (ConsoleClientBootstrapService.CONSOLE_CLIENT_ID.equals(client.getClientId())
                    || CliClientBootstrapService.CLI_CLIENT_ID.equals(client.getClientId())) {
                LOG.warn("Refused deletion of protected built-in client {} in realm {}",
                        LogSafe.sanitize(client.getClientId()), LogSafe.sanitize(realmId));
                return false;
            }
            client.setDeleted(true);
            repository.save(client);
            LOG.debug("Deleted client {} from realm {}", LogSafe.sanitize(id), LogSafe.sanitize(realmId));
            return true;
        }).orElse(false);
    }

    /** A client by surrogate id, only if it belongs to {@code realmId} — never another realm's client. */
    private Optional<ServiceProviderOAuthClient> inRealm(final String realmId, final String id) {
        return repository.findByIdAndDeleted(id, false).filter(c -> realmId != null && realmId.equals(c.getRealmId()));
    }

    private void applyWrite(final ServiceProviderOAuthClient client, final ClientWriteDto write) {
        client.setAuthorizationGrantTypes(join(write.grantTypes()));
        client.setRedirectUris(join(write.redirectUris()));
        client.setPostLogoutRedirectUris(join(write.postLogoutRedirectUris()));
        client.setScopes(join(write.scopes()));
        client.setSubjectClaim(blankToNull(write.subjectClaim()));
        client.setAuthFlowAlias(blankToNull(write.authFlowAlias()));
        client.setApplicationId(sameRealmApplication(write.realmId(), blankToNull(write.applicationId())));
        client.setName(blankToNull(write.name()));
        client.setDescription(blankToNull(write.description()));
        client.setWebOrigins(join(write.webOrigins()));
        client.setPublicClient(Boolean.TRUE.equals(write.publicClient()));
        client.setConsentRequired(Boolean.TRUE.equals(write.consentRequired()));
        client.setDisplayOnConsentScreen(write.displayOnConsentScreen() == null || write.displayOnConsentScreen());
        client.setLoginTheme(blankToNull(write.loginTheme()));
        client.setRootUrl(blankToNull(write.rootUrl()));
        client.setHomeUrl(blankToNull(write.homeUrl()));
        client.setAdminUrl(blankToNull(write.adminUrl()));
        client.setAlwaysDisplayInConsole(Boolean.TRUE.equals(write.alwaysDisplayInConsole()));
        client.setAccessTokenLifespan(write.accessTokenLifespan());
        client.setRefreshTokenLifespan(write.refreshTokenLifespan());
        client.setIdTokenSignatureAlg(blankToNull(write.idTokenSignatureAlg()));
        client.setReuseRefreshTokens(Boolean.TRUE.equals(write.reuseRefreshTokens()));
        client.setTokenEndpointAuthMethod(blankToNull(write.tokenEndpointAuthMethod()));
        client.setJwksUrl(blankToNull(write.jwksUrl()));
        client.setBackchannelLogoutUri(blankToNull(write.backchannelLogoutUri()));
        client.setFrontchannelLogoutUri(blankToNull(write.frontchannelLogoutUri()));
        // B11 FAPI: mTLS cert-bound tokens / signed Request Object / JARM response mode (all back-compat off).
        client.setX509CertificateBoundAccessTokens(Boolean.TRUE.equals(write.x509CertificateBoundAccessTokens()));
        client.setRequireSignedRequestObject(Boolean.TRUE.equals(write.requireSignedRequestObject()));
        client.setJarmResponseMode(blankToNull(write.jarmResponseMode()));
    }

    private static String blankToNull(final String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String join(final List<String> values) {
        return values == null ? "" : String.join(",", values.stream().map(String::trim).filter(s -> !s.isEmpty()).toList());
    }

    private static String generateSecret() {
        final byte[] bytes = new byte[24];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private ClientDto toDto(final ServiceProviderOAuthClient client, final String secret) {
        final List<String> grants = client.getAuthorizationGrantTypes().stream()
                .map(AuthorizationGrantType::getValue).sorted().toList();
        return new ClientDto(client.getTenantId(), client.getId(), client.getClientId(),
                grants, new ArrayList<>(client.getRedirectUris()), new ArrayList<>(client.getScopes()), secret,
                client.getSubjectClaim(), client.getAuthFlowAlias(), client.getName(), client.getDescription(),
                new ArrayList<>(client.getPostLogoutRedirectUris()), new ArrayList<>(client.getWebOriginSet()),
                client.getPublicClient(), client.getConsentRequired(), client.getDisplayOnConsentScreen(),
                client.getLoginTheme(), client.getRootUrl(), client.getHomeUrl(), client.getAdminUrl(),
                client.getAlwaysDisplayInConsole(), client.getAccessTokenLifespan(), client.getRefreshTokenLifespan(),
                client.getIdTokenSignatureAlg(), client.getReuseRefreshTokens(),
                client.getTokenEndpointAuthMethod(), client.getJwksUrl(),
                client.getBackchannelLogoutUri(), client.getFrontchannelLogoutUri(), client.getApplicationId(),
                client.getX509CertificateBoundAccessTokens(), client.getRequireSignedRequestObject(),
                client.getJarmResponseMode());
    }

    /**
     * Review rc.3 #1: an application reference must be an application of the client's realm (application ids are
     * {@code realm|name}); another realm's application is ignored.
     */
    public static String sameRealmApplication(final String realmId, final String applicationId) {
        if (applicationId == null || realmId == null) {
            return applicationId;
        }
        if (!applicationId.startsWith(realmId + "|")) {
            LOG.warn("Ignored application reference {} from another realm on a client of realm {}", applicationId, realmId);
            return null;
        }
        return applicationId;
    }
}
