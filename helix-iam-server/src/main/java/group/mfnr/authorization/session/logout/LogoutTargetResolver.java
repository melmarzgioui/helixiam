package group.mfnr.authorization.session.logout;

import java.util.List;

/**
 * Helix IAM SSO P6: resolves, for the clients spanned by a terminating SSO session, where to deliver the
 * logout notification — the registered OIDC back-channel ({@code logout_token} POST) and front-channel
 * (iframe) endpoints. Backed by the realm's client store.
 */
public interface LogoutTargetResolver {

    /** A client's registered front-channel logout URL (loaded in an iframe at logout). */
    record FrontchannelTarget(String clientId, String frontchannelLogoutUri) {
    }

    /** Back-channel targets ({@code backchannel_logout_uri} present) for the given clients in a realm. */
    List<BackchannelLogoutNotifier.Target> backchannelTargets(String realm, List<String> clientIds);

    /** Front-channel targets ({@code frontchannel_logout_uri} present) for the given clients in a realm. */
    List<FrontchannelTarget> frontchannelTargets(String realm, List<String> clientIds);
}
