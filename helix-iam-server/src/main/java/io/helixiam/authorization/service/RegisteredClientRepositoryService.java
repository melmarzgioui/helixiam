package io.helixiam.authorization.service;

import io.helixiam.authorization.support.RealmScopedKey;
import io.helixiam.authorization.amqp.ServiceProviderPublisher;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

@Service
public class RegisteredClientRepositoryService implements RegisteredClientRepository {

    private final ServiceProviderPublisher serviceProviderPublisher;

    public RegisteredClientRepositoryService(final ServiceProviderPublisher serviceProviderPublisher) {
        this.serviceProviderPublisher = serviceProviderPublisher;
    }

    @Override
    public void save(final RegisteredClient registeredClient) {
        // We like to swallow
    }

    @Override
    public RegisteredClient findById(final String id) {
        // MT-3: scope to the realm of the in-flight /realms/{realm}/… request (null → master).
        return unwrap(serviceProviderPublisher.findById(RealmScopedKey.pack(RealmContextHolder.get(), id)));
    }

    @Override
    public RegisteredClient findByClientId(final String clientId) {
        return unwrap(serviceProviderPublisher.findByClientId(RealmScopedKey.pack(RealmContextHolder.get(), clientId)));
    }

    /**
     * MT-3: the subscriber returns a sentinel (not {@code null}) for a not-found / cross-realm lookup, so the
     * serialized AMQP reply is never empty — an empty reply would block the caller for the full reply timeout.
     * Map the sentinel back to {@code null} so the Spring Authorization Server resolves it as {@code invalid_client}.
     */
    private static RegisteredClient unwrap(final RegisteredClient client) {
        return (client != null && RealmScopedKey.NOT_FOUND_CLIENT_ID.equals(client.getClientId())) ? null : client;
    }
}
