package io.helixiam.authorization.federation;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.amqp.federation.FederatedIdentityPublisher;
import io.helixiam.authorization.domain.UserCredentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E5.3/E5.4: the session-establishment primitives. {@code loadUser} fetches the resolved
 * user passwordlessly (hard failure when missing); {@code persist} installs a given Authentication
 * into a fresh SecurityContext saved to the HTTP session.
 */
class FederatedSessionEstablisherTest {

    private final FederatedIdentityPublisher publisher = mock(FederatedIdentityPublisher.class);
    private final FederatedSessionEstablisher establisher = new FederatedSessionEstablisher(publisher);

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private static UserCredentials user(final String userId, final String email) throws Exception {
        final String json = "{\"userId\":\"" + userId + "\",\"username\":\"" + email + "\","
                + "\"authorities\":[{\"role\":\"ROLE_USER\"}]}";
        return new ObjectMapper().readValue(json, UserCredentials.class);
    }

    @Test
    void loadUserReturnsTheResolvedUser() throws Exception {
        when(publisher.loadUser("user-9")).thenReturn(user("user-9", "ada@corp"));

        assertThat(establisher.loadUser("user-9").getUserId()).isEqualTo("user-9");
    }

    @Test
    void loadUserFailsWhenTheUserCannotBeLoaded() {
        when(publisher.loadUser("ghost")).thenReturn(null);

        assertThatThrownBy(() -> establisher.loadUser("ghost")).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void persistInstallsAndSavesAnAuthenticatedSession() throws Exception {
        final UserCredentials user = user("user-9", "ada@corp");
        final Authentication auth =
                UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities());
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();

        establisher.persist(auth, request, response);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(auth);
        assertThat(request.getSession(false)).isNotNull();
        assertThat(request.getSession(false)
                .getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).isNotNull();
    }
}
