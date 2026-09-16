package group.mfnr.authorization.federation;

import group.mfnr.authorization.federation.spi.IdentityProvider;
import group.mfnr.authorization.federation.spi.IdentityProvider.LogoutContext;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM SSO P9: the coordinator routes a brokered-session logout to the originating IdP by alias, and is
 * strictly best-effort — an unknown alias, a non-brokered session, or a failing provider never propagates an
 * error to the local logout.
 */
class FederatedLogoutCoordinatorTest {

    private final IdentityProviderRegistry registry = mock(IdentityProviderRegistry.class);
    private final FederatedLogoutCoordinator coordinator = new FederatedLogoutCoordinator(registry);

    @Test
    void propagate_routesToTheProviderNamedByAlias() {
        final IdentityProvider provider = mock(IdentityProvider.class);
        when(registry.get("upstream")).thenReturn(provider);
        final LogoutContext ctx = new LogoutContext("master", "u", "upstream", "idtok", null, null);

        coordinator.propagate(ctx);

        verify(provider).logout(ctx);
    }

    @Test
    void propagate_isANoOp_forANonBrokeredSession() {
        coordinator.propagate(new LogoutContext("master", "u")); // idpAlias == null
        verify(registry, never()).get(any());
    }

    @Test
    void propagate_swallowsAnUnknownAlias() {
        when(registry.get("ghost")).thenThrow(new IllegalArgumentException("No identity provider for alias: ghost"));
        assertThatCode(() -> coordinator.propagate(new LogoutContext("master", "u", "ghost", null, null, null)))
                .doesNotThrowAnyException();
    }

    @Test
    void propagate_swallowsAFailingProvider() {
        final IdentityProvider provider = mock(IdentityProvider.class);
        when(registry.get("upstream")).thenReturn(provider);
        doThrow(new RuntimeException("upstream down")).when(provider).logout(any());

        assertThatCode(() -> coordinator.propagate(new LogoutContext("master", "u", "upstream", "t", null, null)))
                .doesNotThrowAnyException();
    }
}
