package group.mfnr.authorization.federation;

import group.mfnr.authorization.federation.spi.AttributeMapper;
import group.mfnr.authorization.federation.spi.BrokeredIdentity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Helix IAM E5.1: maps a normalized {@link BrokeredIdentity} (from any {@code IdentityProvider}) to a
 * local user, applying account linking + just-in-time provisioning + attribute mapping per the
 * realm's {@link AccountLinkingPolicy}. Pure orchestration over a {@link FederatedIdentityStore} seam
 * so it is fully unit-testable; the live store talks to the subscriber over AMQP.
 *
 * Resolution order:
 * <ol>
 *   <li>existing federated link → that user (returning login);</li>
 *   <li>verified-email match to an existing local user → link + that user;</li>
 *   <li>JIT-provision a new local user (if enabled) → link + the new user;</li>
 *   <li>otherwise rejected.</li>
 * </ol>
 * An <b>unverified</b> email is never used to link to an existing account (account-takeover guard).
 */
public class IdentityBroker {

    private static final Logger LOG = LogManager.getLogger(IdentityBroker.class);

    private final FederatedIdentityStore store;
    private final AttributeMapper attributeMapper;

    public IdentityBroker(final FederatedIdentityStore store, final AttributeMapper attributeMapper) {
        this.store = store;
        this.attributeMapper = attributeMapper;
    }

    public BrokerResult broker(final BrokeredIdentity identity, final AccountLinkingPolicy policy) {
        return broker(identity, policy, null);
    }

    /**
     * Broker an identity, additionally applying the provider's configured attribute/claim mappers (B5).
     *
     * @param mapperConfig the per-IdP {@code "source=target,…"} mapper CSV (may be null/blank); applied on
     *                     top of the default normalization at JIT provisioning, overriding on conflict.
     */
    public BrokerResult broker(final BrokeredIdentity identity, final AccountLinkingPolicy policy,
                               final String mapperConfig) {
        final String alias = identity.idpAlias();
        final String subject = identity.externalSubject();

        // 1. Returning identity: an existing link wins outright.
        final var linked = store.findLinkedUser(alias, subject);
        if (linked.isPresent()) {
            return BrokerResult.existingLink(linked.get());
        }

        // 2. Link to an existing local user — ONLY on a verified email (never unverified: takeover).
        if (policy.linkByVerifiedEmail() && identity.emailVerified()
                && identity.email() != null && !identity.email().isBlank()) {
            final var existing = store.findUserByEmail(identity.email());
            if (existing.isPresent()) {
                store.link(alias, subject, existing.get());
                LOG.info("Linked federated identity {}:{} to existing user {} by verified email",
                        alias, subject, existing.get());
                return BrokerResult.linkedExisting(existing.get());
            }
        }

        // 3. Just-in-time provision a new local user.
        if (policy.jitProvision()) {
            // Default normalization first, then the admin-configured per-IdP mappers (B5) override on conflict.
            final java.util.Map<String, String> attributes = new java.util.HashMap<>(attributeMapper.map(identity));
            attributes.putAll(AttributeMapperRules.apply(identity, mapperConfig));
            final String userId = store.provisionUser(identity, attributes);
            store.link(alias, subject, userId);
            LOG.info("JIT-provisioned user {} for federated identity {}:{}", userId, alias, subject);
            return BrokerResult.provisioned(userId);
        }

        // 4. No match and JIT disabled → rejected.
        LOG.warn("Rejected federated identity {}:{} — no link/match and JIT provisioning disabled", alias, subject);
        return BrokerResult.unresolved();
    }
}
