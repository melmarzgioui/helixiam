package io.helixiam.authorization.security.flow;

import org.junit.jupiter.api.Test;
import org.springframework.security.web.savedrequest.SavedRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Helix IAM (named flows): resolving the in-flight relying party's {@code client_id} from the OAuth
 * authorize request Spring Security cached before bouncing the user to login — so the login flow can be
 * chosen per client.
 */
class InFlightClientResolverTest {

    @Test
    void clientIdOf_returnsNull_whenThereIsNoSavedRequest() {
        assertNull(InFlightClientResolver.clientIdOf(null));
    }

    @Test
    void clientIdOf_returnsNull_whenTheSavedRequestCarriesNoClientId() {
        final SavedRequest saved = mock(SavedRequest.class);
        when(saved.getParameterValues("client_id")).thenReturn(null);
        assertNull(InFlightClientResolver.clientIdOf(saved));
    }

    @Test
    void clientIdOf_extractsTheClientId_fromTheCachedAuthorizeRequest() {
        final SavedRequest saved = mock(SavedRequest.class);
        when(saved.getParameterValues("client_id")).thenReturn(new String[]{"gov-portal"});
        assertEquals("gov-portal", InFlightClientResolver.clientIdOf(saved));
    }
}
