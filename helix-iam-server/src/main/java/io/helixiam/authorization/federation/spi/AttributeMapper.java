package io.helixiam.authorization.federation.spi;

import java.util.Map;

/**
 * Helix IAM E5.1 (Mapper SPI, §5.5): maps a {@link BrokeredIdentity}'s external attributes to the
 * local user attributes used for JIT provisioning (username, email, firstName, lastName, …).
 * Pluggable: drop a {@code @Component} to add or override mapping for a realm/provider.
 */
@FunctionalInterface
public interface AttributeMapper {

    Map<String, String> map(BrokeredIdentity identity);
}
