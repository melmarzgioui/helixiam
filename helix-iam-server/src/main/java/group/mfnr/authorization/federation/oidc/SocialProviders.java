package group.mfnr.authorization.federation.oidc;

import java.util.List;

/**
 * Helix IAM E5.2: presets that turn the generic {@link OidcIdentityProvider} into the common social
 * logins by supplying each provider's well-known OIDC endpoints — the admin only enters a client id
 * + secret. Google and Microsoft are full OIDC providers (issue an ID token). (GitHub/Apple variants
 * follow the same shape; GitHub needs an OAuth2+userinfo path since it has no standard ID token.)
 */
public final class SocialProviders {

    private SocialProviders() {
    }

    /** Google ("Sign in with Google"). */
    public static OidcProviderConfig google(final String clientId, final String clientSecret) {
        return new OidcProviderConfig("google", "Google", clientId, clientSecret,
                "https://accounts.google.com/o/oauth2/v2/auth",
                "https://oauth2.googleapis.com/token",
                "https://www.googleapis.com/oauth2/v3/certs",
                "https://accounts.google.com",
                List.of("openid", "email", "profile"));
    }

    /** Microsoft Entra ID ("Sign in with Microsoft") for a given tenant ("common" for multi-tenant). */
    public static OidcProviderConfig microsoft(final String clientId, final String clientSecret, final String tenant) {
        final String base = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0";
        return new OidcProviderConfig("microsoft", "Microsoft", clientId, clientSecret,
                base + "/authorize",
                base + "/token",
                "https://login.microsoftonline.com/" + tenant + "/discovery/v2.0/keys",
                "https://login.microsoftonline.com/" + tenant + "/v2.0",
                List.of("openid", "email", "profile"));
    }
}
