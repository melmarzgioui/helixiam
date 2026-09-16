package group.mfnr.authorization.service.credential;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Helix IAM: auto-discovered catalogue of {@link CredentialProvider}s, keyed by type. Spring
 * injects every provider bean, so a new credential type is added by dropping a {@code @Component}
 * — no change here or at the generic AMQP endpoint. The publisher routes a login verification to
 * the right provider by type.
 */
@Component
public class CredentialProviderRegistry {

    private static final Logger LOG = LogManager.getLogger(CredentialProviderRegistry.class);

    private final Map<String, CredentialProvider> byType = new LinkedHashMap<>();

    public CredentialProviderRegistry(final Collection<CredentialProvider> providers) {
        for (final CredentialProvider provider : providers) {
            if (byType.containsKey(provider.type())) {
                throw new IllegalArgumentException("Duplicate credential provider type: " + provider.type());
            }
            byType.put(provider.type(), provider);
        }
        LOG.info("Helix credential SPI: discovered {} provider(s): {}", byType.size(), byType.keySet());
    }

    /** Routes a login verification to the provider for the given credential type. */
    public boolean verify(final String type, final String userId, final String input) {
        final CredentialProvider provider = byType.get(type);
        if (provider == null) {
            throw new IllegalArgumentException("No credential provider for type: " + type);
        }
        return provider.verify(userId, input);
    }
}
