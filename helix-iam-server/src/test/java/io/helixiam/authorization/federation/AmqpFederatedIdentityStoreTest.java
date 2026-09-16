/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.amqp.federation.FederatedIdentityPublisher;
import io.helixiam.authorization.amqp.federation.FederatedLink;
import io.helixiam.authorization.amqp.federation.FederatedLinkLookup;
import io.helixiam.authorization.amqp.federation.FederatedUserProvision;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E5.3: the AMQP-backed {@link FederatedIdentityStore} adapts the broker's store seam onto
 * the federation exchange. Proves it delegates each op to the publisher and maps a {@code null}
 * answer to an empty {@link Optional} (no link / no user).
 */
class AmqpFederatedIdentityStoreTest {

    private final FederatedIdentityPublisher publisher = mock(FederatedIdentityPublisher.class);
    private final AmqpFederatedIdentityStore store = new AmqpFederatedIdentityStore(publisher);

    @Test
    void findLinkedUserReturnsThePublishersAnswer() {
        when(publisher.findLinkedUser(new FederatedLinkLookup("corp", "ext-1"))).thenReturn("user-9");

        assertThat(store.findLinkedUser("corp", "ext-1")).contains("user-9");
    }

    @Test
    void findLinkedUserMapsNullToEmpty() {
        when(publisher.findLinkedUser(new FederatedLinkLookup("corp", "ext-1"))).thenReturn(null);

        assertThat(store.findLinkedUser("corp", "ext-1")).isEmpty();
    }

    @Test
    void findUserByEmailMapsNullToEmpty() {
        when(publisher.findUserByEmail("ada@corp")).thenReturn(null);

        assertThat(store.findUserByEmail("ada@corp")).isEmpty();
    }

    @Test
    void findUserByEmailReturnsThePublishersAnswer() {
        when(publisher.findUserByEmail("ada@corp")).thenReturn("user-3");

        assertThat(store.findUserByEmail("ada@corp")).contains("user-3");
    }

    @Test
    void linkForwardsTheTriple() {
        store.link("corp", "ext-1", "user-9");

        verify(publisher).link(new FederatedLink("corp", "ext-1", "user-9"));
    }

    @Test
    void provisionUserSendsEmailAndMappedAttributes() {
        final BrokeredIdentity identity =
                new BrokeredIdentity("corp", "ext-1", "ada@corp", true, Map.of("username", "ada"));
        final Map<String, String> mapped = Map.of("email", "ada@corp", "username", "ada");
        when(publisher.provisionUser(new FederatedUserProvision("ada@corp", mapped))).thenReturn("user-new");

        final String userId = store.provisionUser(identity, mapped);

        assertThat(userId).isEqualTo("user-new");
        final ArgumentCaptor<FederatedUserProvision> captor = ArgumentCaptor.forClass(FederatedUserProvision.class);
        verify(publisher).provisionUser(captor.capture());
        assertThat(captor.getValue().email()).isEqualTo("ada@corp");
        assertThat(captor.getValue().attributes()).isEqualTo(mapped);
    }
}
