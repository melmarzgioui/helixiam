package group.mfnr.authorization.federation;

import group.mfnr.authorization.federation.spi.IdentityProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Helix IAM E5.1: catalogue of {@link IdentityProvider}s, keyed by alias. Assembled in
 * {@link FederationConfig} from auto-discovered {@code @Component} providers plus the ones
 * {@link FederationProviderFactory} builds from {@code helix.federation.*} config (E5.4), so a new
 * connector is either a bean or a config entry. The login page lists the aliases; the broker callback
 * routes by alias. Duplicate aliases are rejected at startup.
 */
public class IdentityProviderRegistry {

    private static final Logger LOG = LogManager.getLogger(IdentityProviderRegistry.class);

    /** Startup providers — bean-discovered + built from {@code helix.federation.*} props (E5.4). */
    private final Map<String, IdentityProvider> staticByAlias = new LinkedHashMap<>();
    /** Providers loaded from the persisted store at runtime (E8.3); replaced wholesale on each reload. */
    private volatile Map<String, IdentityProvider> dynamicByAlias = new LinkedHashMap<>();

    public IdentityProviderRegistry(final Collection<IdentityProvider> providers) {
        for (final IdentityProvider provider : providers) {
            final String alias = provider.metadata().alias();
            if (staticByAlias.containsKey(alias)) {
                throw new IllegalArgumentException("Duplicate identity provider alias: " + alias);
            }
            staticByAlias.put(alias, provider);
        }
        LOG.info("Helix federation SPI: discovered {} identity provider(s): {}", staticByAlias.size(), staticByAlias.keySet());
    }

    /**
     * Replaces the dynamic (store-backed) providers with {@code providers} (E8.3). Static providers are
     * untouched; a dynamic provider takes precedence over a static one on the same alias, so an
     * admin-managed connection overrides a config/bean default. Within the set the last wins on a
     * duplicate alias. Atomic swap — readers see either the old or the new set, never a partial one.
     */
    public void reload(final Collection<IdentityProvider> providers) {
        final Map<String, IdentityProvider> next = new LinkedHashMap<>();
        for (final IdentityProvider provider : providers) {
            next.put(provider.metadata().alias(), provider);
        }
        this.dynamicByAlias = next;
        LOG.info("Helix federation: reloaded {} store-backed identity provider(s): {}", next.size(), next.keySet());
    }

    /** The provider registered under {@code alias} (store-backed providers take precedence). */
    public IdentityProvider get(final String alias) {
        final IdentityProvider provider = dynamicByAlias.getOrDefault(alias, staticByAlias.get(alias));
        if (provider == null) {
            throw new IllegalArgumentException("No identity provider for alias: " + alias);
        }
        return provider;
    }

    /** The configured provider aliases (for the login page / admin console). */
    public Set<String> aliases() {
        return merged().keySet();
    }

    /** Provider metadata (alias + display name + protocol) in registration order, for the login page. */
    public java.util.List<group.mfnr.authorization.federation.spi.IdpMetadata> metadatas() {
        return merged().values().stream().map(IdentityProvider::metadata).toList();
    }

    /** Static providers overlaid with the store-backed set (dynamic wins on alias). */
    private Map<String, IdentityProvider> merged() {
        final Map<String, IdentityProvider> merged = new LinkedHashMap<>(staticByAlias);
        merged.putAll(dynamicByAlias);
        return merged;
    }
}
