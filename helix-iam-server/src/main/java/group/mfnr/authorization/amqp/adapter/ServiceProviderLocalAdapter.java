package group.mfnr.authorization.amqp.adapter;

import group.mfnr.authorization.amqp.ServiceProviderPublisher;
import group.mfnr.authorization.service.ServiceProviderService;
import group.mfnr.authorization.service.key.KeyMaterialService;
import group.mfnr.authorization.support.RealmScopedKey;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link ServiceProviderPublisher}.
 *
 * <p>The former AMQP not-found sentinel ({@code RealmScopedKey.NOT_FOUND_CLIENT_ID}) is dropped: it only
 * existed because a {@code null} reply on a serialized request/reply queue would block the caller for the
 * full timeout. In-process a {@code null} return is returned directly, and the caller
 * ({@code RegisteredClientRepositoryService.unwrap}) already tolerates both {@code null} and the sentinel.
 *
 * <p>DEVIATION: {@link #save(OAuth2Authorization)} is a no-op. It has no caller in the folded web front
 * (SAS token/authorization persistence goes through {@code AuthorizationStorePublisher}; registered-client
 * persistence is a swallow in {@code RegisteredClientRepositoryService.save}), and its former AMQP listener
 * bound an incompatible payload type ({@code ServiceProviderOAuthClient}), so there is no type-safe
 * in-process delegation. See ADAPTERS.md "deviations".
 */
@Component
public class ServiceProviderLocalAdapter implements ServiceProviderPublisher {

    private final ServiceProviderService serviceProviderService;
    private final KeyMaterialService keyMaterialService;

    public ServiceProviderLocalAdapter(final ServiceProviderService serviceProviderService,
                                       final KeyMaterialService keyMaterialService) {
        this.serviceProviderService = serviceProviderService;
        this.keyMaterialService = keyMaterialService;
    }

    @Override
    public void save(final OAuth2Authorization authorization) {
        // No-op: vestigial, uncalled sender whose former AMQP listener took an incompatible type. See class Javadoc.
    }

    @Override
    public KeyPair retrieveKeyPair(final String realm) {
        return keyMaterialService.activeKeyPair(realm);
    }

    @Override
    public ArrayList<RSAPublicKey> retrieveVerificationKeys(final String realm) {
        return new ArrayList<>(keyMaterialService.rotatedPublicKeys(realm));
    }

    @Override
    public ArrayList<String> retrieveWebOrigins(final String realm) {
        return new ArrayList<>(serviceProviderService.webOriginsForRealm(realm));
    }

    @Override
    public RegisteredClient findById(final String realmScopedId) {
        final String[] parts = RealmScopedKey.split(realmScopedId);
        return serviceProviderService.getRegisteredClientId(parts[1], parts[0]);
    }

    @Override
    public RegisteredClient findByClientId(final String realmScopedClientId) {
        final String[] parts = RealmScopedKey.split(realmScopedClientId);
        return serviceProviderService.getRegisteredClientByClientId(parts[1], parts[0]);
    }
}
