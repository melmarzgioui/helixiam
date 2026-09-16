package group.mfnr.authorization.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import group.mfnr.authorization.domain.ServiceProviderOAuthClient;
import group.mfnr.authorization.repository.ServiceProviderRepository;
import io.helixiam.common.exception.ValidationException;
import jakarta.annotation.PostConstruct;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;

/**
 * Service responsible for managing Service Provider OAuth client configurations.
 * Handles initialization, persistence, and retrieval of registered clients.
 */
@Service
public class ServiceProviderService {

    private final ServiceProviderRepository registeredClientRepository;
    private final group.mfnr.authorization.repository.application.ApplicationRepository applications;
    private final String fileLocation;

    private static final Logger LOG = LogManager.getLogger(ServiceProviderService.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /**
     * Constructs the service with repository and file location for initial config.
     *
     * `@param registeredClientRepository` Repository to persist service provider configs
     * `@param fileLocation` Path to config file containing initial service provider data
     */
    @Autowired
    public ServiceProviderService(
            final ServiceProviderRepository registeredClientRepository,
            final group.mfnr.authorization.repository.application.ApplicationRepository applications,
            @Value("${sp.config.location}") final String fileLocation
    ) {
        this.registeredClientRepository = registeredClientRepository;
        this.applications = applications;
        this.fileLocation = fileLocation;
    }

    /**
     * Loads the service provider config on startup from the configured file or a dummy fallback.
     */
    @PostConstruct
    private void initializeServiceProvider() throws IOException {
        final ServiceProviderOAuthClient initialServiceProvider = getServiceProviderOAuthClient();

        if (initialServiceProvider != null) {
            initialServiceProvider.setTenantId("-1234");
            final RegisteredClient registeredClient = getRegisteredClientByClientId(initialServiceProvider.getClientId());
            if (registeredClient != null) {
                initialServiceProvider.setServiceProviderId(registeredClient.getId());
            }

            registeredClientRepository.save(initialServiceProvider);
        }
    }

    /**
     * Loads a service provider config from file or dummy resource if not found.
     */
    private ServiceProviderOAuthClient getServiceProviderOAuthClient() {
        try {
            final File configFile = new File(fileLocation);
            if (configFile.exists()) {
                return OBJECT_MAPPER.readValue(configFile, ServiceProviderOAuthClient.class);
            } else {
                LOG.warn("Using test service provider configuration");
                return OBJECT_MAPPER.readValue(
                        ServiceProviderService.class.getResourceAsStream("/dummy/dummy.json"),
                        ServiceProviderOAuthClient.class
                );
            }
        } catch (final Exception e) {
            LOG.warn("Failed to parse service provider configuration", e);
            return null;
        }
    }

    /**
     * Fetch a registered client by its ID if not marked as deleted.
     */
    public RegisteredClient getRegisteredClientId(final String id) {
        return registeredClientRepository
                .findByIdAndDeleted(id, false)
                .map(ServiceProviderOAuthClient::build)
                .orElse(null);
    }

    /**
     * Fetch a registered client by client ID if not marked as deleted.
     */
    public RegisteredClient getRegisteredClientByClientId(final String clientId) {
        return registeredClientRepository
                .findByClientIdAndDeleted(clientId, false)
                .map(ServiceProviderOAuthClient::build)
                .orElse(null);
    }

    /**
     * Helix IAM multi-tenant (MT-3): fetch a registered client by client ID <b>within {@code realm}</b>.
     * Returns {@code null} when no such client belongs to that realm — so a client registered under one
     * realm cannot be used under another realm's {@code /realms/{realm}/oauth2/*} endpoints.
     */
    public RegisteredClient getRegisteredClientByClientId(final String clientId, final String realm) {
        return registeredClientRepository
                .findByClientIdAndRealmIdAndDeleted(clientId, realm, false)
                .map(ServiceProviderOAuthClient::build)
                .orElse(null);
    }

    /**
     * Helix IAM (named flows): the per-client login-flow override for {@code clientId} within {@code realm},
     * or {@code null} when the client has none (so the realm's default {@code browser} flow applies). Read
     * from the client's own {@code auth_flow_alias}; realm-scoped so a client only binds a flow in its realm.
     */
    public String getFlowAlias(final String clientId, final String realm) {
        return registeredClientRepository
                .findByClientIdAndRealmIdAndDeleted(clientId, realm, false)
                // Application model: the parent app's shared login flow takes precedence over the client's own.
                .map(client -> {
                    if (client.getApplicationId() != null) {
                        final String appAlias = applications.findById(client.getApplicationId())
                                .map(group.mfnr.authorization.domain.application.ApplicationEntity::getAuthFlowAlias)
                                .filter(a -> a != null && !a.isBlank())
                                .orElse(null);
                        if (appAlias != null) {
                            return appAlias;
                        }
                    }
                    return client.getAuthFlowAlias();
                })
                .orElse(null);
    }

    /**
     * Helix IAM (CORS): the union of all web origins configured across {@code realm}'s live clients — the
     * browser origins allowed to call that realm's OAuth/OIDC endpoints cross-origin.
     */
    public java.util.List<String> webOriginsForRealm(final String realm) {
        return registeredClientRepository.findAllByRealmIdAndDeleted(realm, false).stream()
                .flatMap(c -> c.getWebOriginSet().stream())
                .distinct()
                .toList();
    }

    /** Realm-scoped fetch by internal id (MT-3) — returns {@code null} if it is not in {@code realm}. */
    public RegisteredClient getRegisteredClientId(final String id, final String realm) {
        return registeredClientRepository
                .findByIdAndRealmIdAndDeleted(id, realm, false)
                .map(ServiceProviderOAuthClient::build)
                .orElse(null);
    }

    /**
     * Saves a new service provider record.
     */
    public ServiceProviderOAuthClient save(final ServiceProviderOAuthClient serviceProviderOauthClient) {
        try {
            return registeredClientRepository.save(serviceProviderOauthClient);
        } catch (final Exception error) {
            // Was ResponseException(error, false) over AMQP (group.mfnr.subscriber.starter.amqp.exception);
            // no broker/serialized-reply channel remains (Task 2, strip-RabbitMQ), so this now throws the
            // vendored in-process ValidationException — same shape (message + errorCode + authorization
            // flag), unchecked so the signature drops `throws`.
            final ValidationException validationException = new ValidationException(error.getMessage());
            validationException.setAuthorization(false);
            throw validationException;
        }
    }

    /**
     * Updates the client secret of an existing service provider.
     */
    public ServiceProviderOAuthClient update(final ServiceProviderOAuthClient serviceProviderOauthClient) {
        registeredClientRepository
                .findByClientIdAndRealmIdAndDeleted(
                        serviceProviderOauthClient.getClientId(), serviceProviderOauthClient.getRealmId(), false)
                .ifPresent(registeredClient -> {
                    registeredClient.setClientSecret(serviceProviderOauthClient.getClientSecret());
                    registeredClientRepository.save(registeredClient);
                });

        return serviceProviderOauthClient;
    }

    /**
     * Retrieves a service provider object by its client ID.
     */
    public ServiceProviderOAuthClient get(final String clientId) {
        return registeredClientRepository
                .findByClientIdAndDeleted(clientId, false)
                .orElse(null);
    }

    /**
     * Marks a service provider as deleted.
     */
    public void disable(final String serviceProviderId) {
        registeredClientRepository
                .findByIdAndDeleted(serviceProviderId, false)
                .ifPresent(serviceProviderOAuthClient -> {
                    serviceProviderOAuthClient.setDeleted(true);
                    registeredClientRepository.save(serviceProviderOAuthClient);
                });
    }

    /**
     * Deletes a service provider record from the repository.
     */
    public void delete(final String serviceProviderId) {
        registeredClientRepository
                .findByIdAndDeleted(serviceProviderId, false)
                .ifPresent(registeredClientRepository::delete);
    }
}
