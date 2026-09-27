/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.scim;

import io.helixiam.authorization.amqp.group.GroupAdminPublisher;
import io.helixiam.authorization.amqp.group.GroupDto;
import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.idp.provisioning.ProvisioningAdminPublisher;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * SCIM list paging (RFC 7644 §3.4.2.4): {@code startIndex}/{@code count} are client-supplied, so the page
 * bounds must never overflow — {@code count=Integer.MAX_VALUE} past the first item used to wrap
 * {@code from + count} negative and blow up {@code subList} (a 500 instead of the rest of the list).
 */
class ScimListPagingTest {

    private static final String REALM = "scim-paging";

    private final ProvisioningAdminPublisher provisioning = mock(ProvisioningAdminPublisher.class);
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        RealmContextHolder.set(REALM);
        request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer scim-token");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        when(provisioning.verifyScimToken(any())).thenReturn(Boolean.TRUE);
    }

    @AfterEach
    void tearDown() {
        RealmContextHolder.clear();
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void users_hugeCountPastTheFirstItem_returnsTheRemainder() {
        final UserAdminPublisher users = mock(UserAdminPublisher.class);
        when(users.list(anyString())).thenReturn(List.of(user("u1"), user("u2"), user("u3")));
        final ScimUserController controller = new ScimUserController(users, provisioning);

        final ResponseEntity<?> res = controller.list(null, 2, Integer.MAX_VALUE, request);

        assertThat(res.getStatusCode().value()).isEqualTo(200);
        final ScimListResponse<?> body = (ScimListResponse<?>) res.getBody();
        assertThat(body.Resources()).hasSize(2);
        assertThat(body.totalResults()).isEqualTo(3);
    }

    @Test
    void groups_hugeCountPastTheFirstItem_returnsTheRemainder() {
        final GroupAdminPublisher groups = mock(GroupAdminPublisher.class);
        when(groups.list(anyString())).thenReturn(List.of(group("g1"), group("g2"), group("g3")));
        when(groups.members(any())).thenReturn(List.of());
        final ScimGroupController controller = new ScimGroupController(groups, provisioning);

        final ResponseEntity<?> res = controller.list(null, 3, Integer.MAX_VALUE, request);

        assertThat(res.getStatusCode().value()).isEqualTo(200);
        final ScimListResponse<?> body = (ScimListResponse<?>) res.getBody();
        assertThat(body.Resources()).hasSize(1);
    }

    private static UserAdminDto user(final String id) {
        return new UserAdminDto(REALM, id, id, id + "@x.test", true, false, false, List.of(), Map.of(), 0L);
    }

    private static GroupDto group(final String id) {
        return new GroupDto(REALM, id, id, null, 0, List.of());
    }
}
