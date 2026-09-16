/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.federation.spi.AttributeMapper;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E5.1: the broker maps a normalized external identity to a local user. The security-
 * critical rules: a returning identity resolves via its stored link; a new one links to an existing
 * account ONLY on a verified email (never unverified — account takeover); otherwise it is JIT-
 * provisioned (if enabled) or rejected.
 */
class IdentityBrokerTest {

    private final AttributeMapper mapper = new DefaultAttributeMapper();

    /** A configurable in-memory store standing in for the subscriber. */
    private static final class FakeStore implements FederatedIdentityStore {
        final Map<String, String> links = new HashMap<>();         // "alias|subject" -> userId
        final Map<String, String> usersByEmail = new HashMap<>();  // email -> userId
        final AtomicReference<Map<String, String>> lastProvisionAttrs = new AtomicReference<>();
        int provisionSeq = 0;

        @Override public Optional<String> findLinkedUser(final String a, final String s) {
            return Optional.ofNullable(links.get(a + "|" + s));
        }
        @Override public Optional<String> findUserByEmail(final String email) {
            return Optional.ofNullable(usersByEmail.get(email));
        }
        @Override public void link(final String a, final String s, final String userId) {
            links.put(a + "|" + s, userId);
        }
        @Override public String provisionUser(final BrokeredIdentity id, final Map<String, String> attrs) {
            lastProvisionAttrs.set(attrs);
            final String userId = "new-user-" + (++provisionSeq);
            if (id.email() != null) {
                usersByEmail.put(id.email(), userId);
            }
            return userId;
        }
    }

    private BrokeredIdentity identity(final String subject, final String email, final boolean verified) {
        final Map<String, String> attrs = new HashMap<>();
        attrs.put("given_name", "Ada");
        attrs.put("family_name", "Lovelace");
        return new BrokeredIdentity("google", subject, email, verified, attrs);
    }

    @Test
    void resolvesAReturningIdentityViaItsStoredLink() {
        final FakeStore store = new FakeStore();
        store.link("google", "sub-1", "user-7");
        final IdentityBroker broker = new IdentityBroker(store, mapper);

        final BrokerResult result = broker.broker(identity("sub-1", "ada@x.io", true), AccountLinkingPolicy.defaults());

        assertThat(result.resolved()).isTrue();
        assertThat(result.userId()).isEqualTo("user-7");
        assertThat(result.provisioned()).isFalse();
        assertThat(result.linked()).isFalse();
    }

    @Test
    void linksToAnExistingUserOnAVerifiedEmail() {
        final FakeStore store = new FakeStore();
        store.usersByEmail.put("ada@x.io", "user-7");
        final IdentityBroker broker = new IdentityBroker(store, mapper);

        final BrokerResult result = broker.broker(identity("sub-1", "ada@x.io", true), AccountLinkingPolicy.defaults());

        assertThat(result.userId()).isEqualTo("user-7");
        assertThat(result.provisioned()).isFalse();
        assertThat(result.linked()).isTrue();
        assertThat(store.findLinkedUser("google", "sub-1")).contains("user-7"); // link recorded
    }

    @Test
    void doesNotLinkToAnExistingUserWhenTheEmailIsUnverified_accountTakeoverGuard() {
        final FakeStore store = new FakeStore();
        store.usersByEmail.put("ada@x.io", "victim-7");
        final IdentityBroker broker = new IdentityBroker(store, mapper);

        // Unverified email matching a local account must NOT link to it — it JIT-provisions a fresh user.
        final BrokerResult result = broker.broker(identity("sub-1", "ada@x.io", false), AccountLinkingPolicy.defaults());

        assertThat(result.provisioned()).isTrue();
        assertThat(result.userId()).isNotEqualTo("victim-7");
    }

    @Test
    void jitProvisionsAndLinksANewIdentity_applyingTheMapper() {
        final FakeStore store = new FakeStore();
        final IdentityBroker broker = new IdentityBroker(store, mapper);

        final BrokerResult result = broker.broker(identity("sub-9", "grace@x.io", true), AccountLinkingPolicy.defaults());

        assertThat(result.provisioned()).isTrue();
        assertThat(result.userId()).isEqualTo("new-user-1");
        assertThat(store.findLinkedUser("google", "sub-9")).contains("new-user-1");
        assertThat(store.lastProvisionAttrs.get()).containsEntry("firstName", "Ada").containsEntry("email", "grace@x.io");
    }

    @Test
    void jitProvisionAppliesConfiguredMappersOnTopOfTheDefaults() {
        final FakeStore store = new FakeStore();
        final IdentityBroker broker = new IdentityBroker(store, mapper);
        final Map<String, String> attrs = new HashMap<>();
        attrs.put("given_name", "Ada");
        attrs.put("department", "R&D");
        final BrokeredIdentity identity = new BrokeredIdentity("acme", "sub-9", "ada@x.io", true, attrs);

        // Per-IdP mapper config: project the upstream 'department' claim onto a local 'dept' attribute.
        final BrokerResult result = broker.broker(identity, AccountLinkingPolicy.defaults(), "department=dept");

        assertThat(result.provisioned()).isTrue();
        // Default normalization still applies…
        assertThat(store.lastProvisionAttrs.get()).containsEntry("firstName", "Ada").containsEntry("email", "ada@x.io");
        // …and the configured mapper added the extra attribute.
        assertThat(store.lastProvisionAttrs.get()).containsEntry("dept", "R&D");
    }

    @Test
    void configuredMapperOverridesADefaultAttributeOnConflict() {
        final FakeStore store = new FakeStore();
        final IdentityBroker broker = new IdentityBroker(store, mapper);
        final Map<String, String> attrs = new HashMap<>();
        attrs.put("given_name", "Ada");
        attrs.put("displayName", "Ada L.");
        final BrokeredIdentity identity = new BrokeredIdentity("acme", "sub-9", "ada@x.io", true, attrs);

        // Admin explicitly maps displayName→firstName, which must win over the default given_name→firstName.
        final BrokerResult result = broker.broker(identity, AccountLinkingPolicy.defaults(), "displayName=firstName");

        assertThat(result.provisioned()).isTrue();
        assertThat(store.lastProvisionAttrs.get()).containsEntry("firstName", "Ada L.");
    }

    @Test
    void rejectsAnUnmatchedIdentityWhenJitDisabled() {
        final FakeStore store = new FakeStore();
        final IdentityBroker broker = new IdentityBroker(store, mapper);

        final BrokerResult result = broker.broker(
                identity("sub-1", "ada@x.io", true), new AccountLinkingPolicy(true, false));

        assertThat(result.resolved()).isFalse();
        assertThat(result.userId()).isNull();
    }
}
