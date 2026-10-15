/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.scim;

import tools.jackson.databind.ObjectMapper;
import io.helixiam.authorization.amqp.scim.ScimTargetConfigPublisher;
import io.helixiam.authorization.amqp.scim.ScimTargetDto;
import io.helixiam.testsupport.RebindingTarget;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.mockito.Mockito;
import org.springframework.beans.factory.ObjectProvider;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/** M6: SCIM provisioning requests go to the address the guard validated, never to a second DNS answer. */
class ScimProvisioningRebindingTest {

    @SuppressWarnings("unchecked")
    private static ScimProvisioningDispatcher dispatcher(final RebindingTarget target) {
        final ScimTargetConfigPublisher publisher = Mockito.mock(ScimTargetConfigPublisher.class);
        Mockito.when(publisher.active("acme")).thenReturn(List.of(new ScimTargetDto("t1", "acme", "downstream",
                target.url("http", "/scim/v2"), "tok-123", true, "", true, 0L)));
        final ObjectProvider<ScimTargetConfigPublisher> provider = Mockito.mock(ObjectProvider.class);
        Mockito.when(provider.getIfAvailable()).thenReturn(publisher);
        return new ScimProvisioningDispatcher(provider, new ObjectMapper(), target.guard());
    }

    private static void awaitRequests(final RebindingTarget target, final int n) throws InterruptedException {
        final long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (target.requests().size() < n && System.nanoTime() < until) {
            Thread.sleep(20);
        }
        Thread.sleep(200); // nothing more arrives
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    void aCreateIsPostedToTheValidatedAddressOnly() throws Exception {
        try (RebindingTarget target = RebindingTarget.http("scim.rebind.test")) {
            dispatcher(target).provision("acme", ScimProvisioningDispatcher.Operation.CREATE,
                    new ScimUserView("u-1", "alice", "alice@example.org", true, "Alice", "A"));
            awaitRequests(target, 1);

            assertThat(target.requests()).hasSize(1);
            final RebindingTarget.Seen seen = target.requests().get(0);
            assertThat(seen.method()).isEqualTo("POST");
            assertThat(seen.path()).isEqualTo("/scim/v2/Users");
            assertThat(seen.header("Authorization")).isEqualTo("Bearer tok-123");
            assertThat(seen.header("Content-Type")).isEqualTo("application/scim+json");
            assertThat(seen.body()).contains("\"userName\":\"alice\"");
            assertThat(target.lookups()).isEqualTo(1);
        }
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    void anUpdateRebindingBetweenItsTwoRequestsNeverReachesTheSecondAnswer() throws Exception {
        try (RebindingTarget target = RebindingTarget.http("scim.rebind.test")) {
            target.respond(s -> new RebindingTarget.Answer(200, "application/scim+json",
                    "{\"Resources\":[{\"id\":\"remote-9\"}]}"));
            dispatcher(target).provision("acme", ScimProvisioningDispatcher.Operation.UPDATE,
                    new ScimUserView("u-1", "alice", "alice@example.org", true, "Alice", "A"));
            awaitRequests(target, 1);

            // the lookup went to the validated address; the PUT resolved again, got the metadata address and was
            // refused by the guard before any connection
            assertThat(target.requests()).extracting(RebindingTarget.Seen::method).containsExactly("GET");
            assertThat(target.lookups()).isEqualTo(2);
        }
    }
}
