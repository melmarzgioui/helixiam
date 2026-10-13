/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.federation.adapter;

import io.helixiam.authorization.amqp.federation.FederatedIdentityPublisher;
import io.helixiam.authorization.amqp.federation.FederatedLinkClaimResult;
import io.helixiam.authorization.amqp.federation.RealmFederatedLink;
import io.helixiam.authorization.amqp.federation.RealmFederatedLinkLookup;
import io.helixiam.authorization.amqp.federation.RealmFederatedUnlink;
import io.helixiam.authorization.amqp.support.DtoBridge;
import io.helixiam.authorization.service.federation.FederatedIdentityService;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Task 21a fix round 1 (ruling 6): the realm-scoped link operations the wallet uses go through the
 * {@link FederatedIdentityPublisher} seam; the local adapter delegates them to {@link FederatedIdentityService}.
 */
class FederatedIdentityLocalAdapterTest {

    private final FederatedIdentityService service = mock(FederatedIdentityService.class);
    private final FederatedIdentityPublisher adapter =
            new FederatedIdentityLocalAdapter(service, mock(DtoBridge.class));

    @Test
    void findRealmLinkedUser_delegates_andAnEmptyAnswerIsNull() {
        when(service.findLinkedUserInRealm("r", "wallet", "s1")).thenReturn(Optional.of("u1"));
        when(service.findLinkedUserInRealm("r", "wallet", "s2")).thenReturn(Optional.empty());

        assertThat(adapter.findRealmLinkedUser(new RealmFederatedLinkLookup("r", "wallet", "s1"))).isEqualTo("u1");
        assertThat(adapter.findRealmLinkedUser(new RealmFederatedLinkLookup("r", "wallet", "s2"))).isNull();
    }

    @Test
    void claimLink_delegates() {
        final FederatedLinkClaimResult created =
                new FederatedLinkClaimResult(FederatedLinkClaimResult.Status.CREATED, "u1");
        when(service.claimLink("r", "wallet", "s1", "u1")).thenReturn(created);

        assertThat(adapter.claimLink(new RealmFederatedLink("r", "wallet", "s1", "u1"))).isEqualTo(created);
    }

    @Test
    void unlinkAll_delegates() {
        when(service.unlinkAll("r", "u1", "wallet")).thenReturn(2);

        assertThat(adapter.unlinkAll(new RealmFederatedUnlink("r", "u1", "wallet"))).isEqualTo(2);
    }

    @Test
    void newRoutingKeysAreAllDots_neverDashes() {
        for (final String key : List.of(FederatedIdentityPublisher.AUTHORIZATION_FEDERATION_LINK_FIND_IN_REALM,
                FederatedIdentityPublisher.AUTHORIZATION_FEDERATION_LINK_CLAIM,
                FederatedIdentityPublisher.AUTHORIZATION_FEDERATION_LINK_REMOVE_ALL)) {
            assertThat(key).matches("[a-z]+(\\.[a-z]+)+");
        }
    }
}
