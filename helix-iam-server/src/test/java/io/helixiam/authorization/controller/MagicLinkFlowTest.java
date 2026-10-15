/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller;

import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.federation.FederatedLoginCompleter;
import io.helixiam.authorization.federation.FederatedSessionEstablisher;
import io.helixiam.authorization.security.SignInAuthorities;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.service.magiclink.MagicLinkService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.ui.ExtendedModelMap;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Security review: with the flow engine on, a magic link runs the login's flow like a federated first factor. */
class MagicLinkFlowTest {

    @AfterEach
    void clear() {
        RealmContextHolder.clear();
    }

    @Test
    void withTheEngineOn_theMagicLinkCompletesThroughTheFlow() {
        RealmContextHolder.set("acme");
        final MagicLinkService links = mock(MagicLinkService.class);
        when(links.enabled("acme")).thenReturn(true);
        when(links.consume("acme", "t")).thenReturn(Optional.of("user-1"));
        final FederatedSessionEstablisher sessions = mock(FederatedSessionEstablisher.class);
        when(sessions.loadUser("user-1")).thenReturn(mock(UserCredentials.class));
        final FederatedLoginCompleter completer = mock(FederatedLoginCompleter.class);
        when(completer.completeLogin(eq("user-1"), isNull(), any(), any(), isNull(), isNull(),
                eq(SignInAuthorities.MAGIC_LINK))).thenReturn(new FederatedLoginCompleter.Completion("redirect:/flow",
                FederatedLoginCompleter.Outcome.PENDING));
        final MagicLinkController controller = new MagicLinkController(links, sessions, null, null, null,
                mock(AuditLog.class), null, "https://sp", "https://idp");
        controller.setFlowEngineEnabled(true);
        controller.setFlowSupport(completer, null);

        final String view = controller.verify("t", new MockHttpServletRequest(), new MockHttpServletResponse(),
                new ExtendedModelMap());

        assertThat(view).isEqualTo("redirect:/flow");
        verify(completer).completeLogin(eq("user-1"), isNull(), any(), any(), isNull(), isNull(),
                eq(SignInAuthorities.MAGIC_LINK));
    }
}
