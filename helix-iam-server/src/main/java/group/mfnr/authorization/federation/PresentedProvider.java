package group.mfnr.authorization.federation;

import group.mfnr.authorization.federation.spi.BrokeredIdentity;
import group.mfnr.authorization.federation.spi.IdentityProvider;
import group.mfnr.authorization.federation.spi.IdpMetadata;

/**
 * Helix IAM (login branding): wraps a broker so its {@link #metadata()} carries login-button presentation
 * (a built-in {@code iconKey} and/or an admin-set {@code logoUrl}) without every concrete provider having to
 * thread those through its own config. All behaviour ({@code start}/{@code callback}/{@code logout}) delegates
 * unchanged; only the metadata is enriched.
 */
public final class PresentedProvider implements IdentityProvider {

    private final IdentityProvider delegate;
    private final String iconKey;
    private final String logoUrl;

    public PresentedProvider(final IdentityProvider delegate, final String iconKey, final String logoUrl) {
        this.delegate = delegate;
        this.iconKey = iconKey;
        this.logoUrl = logoUrl;
    }

    @Override
    public IdpMetadata metadata() {
        return delegate.metadata().withPresentation(iconKey, logoUrl);
    }

    @Override
    public RedirectResponse start(final AuthnRequestContext context) {
        return delegate.start(context);
    }

    @Override
    public BrokeredIdentity callback(final CallbackContext context) {
        return delegate.callback(context);
    }

    @Override
    public void logout(final LogoutContext context) {
        delegate.logout(context);
    }
}
