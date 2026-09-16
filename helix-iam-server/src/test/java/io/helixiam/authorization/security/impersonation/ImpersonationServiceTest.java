package io.helixiam.authorization.security.impersonation;

import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.federation.FederatedSessionEstablisher;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Helix IAM B4: admin impersonation — establish a session AS a target user, passwordlessly. */
class ImpersonationServiceTest {

    private final FederatedSessionEstablisher establisher = mock(FederatedSessionEstablisher.class);
    private final ImpersonationService service = new ImpersonationService(establisher, "https://app.example", null);

    private static UserCredentials user(final String id) {
        try {
            // UserCredentials is JSON-populated (no setters); getUsername() returns the userId.
            return new com.fasterxml.jackson.databind.ObjectMapper()
                    .readValue("{\"userId\":\"" + id + "\"}", UserCredentials.class);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void impersonate_establishesSessionAsTarget_andMarksTheImpersonator() {
        when(establisher.loadUser("u-1")).thenReturn(user("u-1"));
        final MockHttpServletRequest req = new MockHttpServletRequest();
        final MockHttpServletResponse res = new MockHttpServletResponse();

        final ImpersonationService.Result result = service.impersonate("master", "u-1", "admin", req, res);

        // The session was established AS the target user (persist called with an authenticated token for alice).
        final var captor = org.mockito.ArgumentCaptor.forClass(Authentication.class);
        verify(establisher).persist(captor.capture(), any(), any());
        assertThat(captor.getValue().isAuthenticated()).isTrue();
        assertThat(((UserCredentials) captor.getValue().getPrincipal()).getUserId()).isEqualTo("u-1");
        // The original admin is recorded on the session so a banner + "stop" path can find it.
        assertThat(req.getSession().getAttribute(ImpersonationService.IMPERSONATOR_ATTR)).isEqualTo("admin");
        assertThat(result.username()).isEqualTo("u-1");
        assertThat(result.redirectUrl()).isEqualTo("https://app.example");
    }

    @Test
    void stop_endsImpersonation_whenMarked_andReportsTheImpersonator() {
        final MockHttpServletRequest req = new MockHttpServletRequest();
        req.getSession().setAttribute(ImpersonationService.IMPERSONATOR_ATTR, "admin");
        final MockHttpServletResponse res = new MockHttpServletResponse();

        final String impersonator = service.stop(req, res);

        assertThat(impersonator).isEqualTo("admin");
    }

    @Test
    void stop_returnsNull_whenNotImpersonating() {
        final MockHttpServletRequest req = new MockHttpServletRequest();
        assertThat(service.stop(req, new MockHttpServletResponse())).isNull();
        verify(establisher, never()).loadUser(any());
    }
}
