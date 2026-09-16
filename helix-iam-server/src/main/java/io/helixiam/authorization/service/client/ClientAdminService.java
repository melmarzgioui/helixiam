package io.helixiam.authorization.service.client;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.domain.client.admin.ClientDto;
import io.helixiam.authorization.domain.client.admin.ClientWriteDto;
import io.helixiam.authorization.repository.ServiceProviderRepository;
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
        return repository.findByIdAndDeleted(id, false).map(c -> toDto(c, null));
    }

    /** Registers a new confidential client; returns it with the one-time generated secret. */
    @Transactional
    public ClientDto create(final ClientWriteDto write) {
        // Invariant guard: a client must have a clientId.
        if (write.clientId() == null || write.clientId().isBlank()) {
            throw new IllegalArgumentException("Client ID is required.");
        }
        // Public clients (SPA/native) authenticate with no secret — PKCE protects the code exchange.
        final String secret = Boolean.TRUE.equals(write.publicClient()) ? null : generateSecret();
        final ServiceProviderOAuthClient client = new ServiceProviderOAuthClient();
        client.setClientId(write.clientId());
        client.setTenantId(write.realmId());
        client.setDeleted(false);
        client.setClientSecret(secret);
        applyWrite(client, write);
        final ServiceProviderOAuthClient saved = repository.save(client);
        LOG.debug("Registered client {} in realm {}", write.clientId(), write.realmId());
        return toDto(saved, secret);
    }

    /** Updates a client's grant types / redirect URIs / scopes; secret unchanged. */
    @Transactional
    public Optional<ClientDto> update(final ClientWriteDto write) {
        return repository.findByIdAndDeleted(write.id(), false).map(client -> {
            applyWrite(client, write);
            return toDto(repository.save(client), null);
        });
    }

    /** Reveals a client's current secret (Credentials tab); the rest of the DTO is the client as-is. */
    public Optional<ClientDto> reveal(final String realmId, final String id) {
        return repository.findByIdAndDeleted(id, false).map(c -> toDto(c, c.getRawSecret()));
    }

    /** Issues a fresh secret for a client; returns it once. */
    @Transactional
    public Optional<ClientDto> regenerateSecret(final String realmId, final String id) {
        return repository.findByIdAndDeleted(id, false).map(client -> {
            final String secret = generateSecret();
            client.setClientSecret(secret);
            return toDto(repository.save(client), secret);
        });
    }

    /** Soft-deletes a client (the OAuth server stops resolving it); {@code false} if absent. */
    @Transactional
    public boolean delete(final String realmId, final String id) {
        return repository.findByIdAndDeleted(id, false).map(client -> {
            // Protect the built-in console/CLI clients: deleting them would lock admins out of the console /
            // break the CLI. They self-heal on restart anyway, but refuse the delete so the UI can't remove them.
            if (ConsoleClientBootstrapService.CONSOLE_CLIENT_ID.equals(client.getClientId())
                    || CliClientBootstrapService.CLI_CLIENT_ID.equals(client.getClientId())) {
                LOG.warn("Refused deletion of protected built-in client {} in realm {}", client.getClientId(), realmId);
                return false;
            }
            client.setDeleted(true);
            repository.save(client);
            LOG.debug("Deleted client {} from realm {}", id, realmId);
            return true;
        }).orElse(false);
    }

    private void applyWrite(final ServiceProviderOAuthClient client, final ClientWriteDto write) {
        client.setAuthorizationGrantTypes(join(write.grantTypes()));
        client.setRedirectUris(join(write.redirectUris()));
        client.setPostLogoutRedirectUris(join(write.postLogoutRedirectUris()));
        client.setScopes(join(write.scopes()));
        client.setSubjectClaim(blankToNull(write.subjectClaim()));
        client.setAuthFlowAlias(blankToNull(write.authFlowAlias()));
        client.setApplicationId(blankToNull(write.applicationId()));
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
}
