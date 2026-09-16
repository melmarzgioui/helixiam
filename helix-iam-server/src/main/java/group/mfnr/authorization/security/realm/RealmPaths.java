package group.mfnr.authorization.security.realm;

/**
 * Helix IAM: builds realm-prefixed application paths ({@code /realms/{realm}/...}).
 *
 * <p>The {@link RealmRoutingFilter} strips {@code /realms/{realm}} into a {@link RealmContextHolder}
 * before routing, so controllers map at the bare path ({@code /flow}, {@code /login}). But any URL the
 * server hands back to the browser — a {@code redirect:} or a rendered {@code <form action>} — must
 * carry the realm prefix again, otherwise the browser posts to the flat path and the realm-routing
 * guard rejects it with a 404. This centralises that prefixing (mirrors the inline
 * {@code "/realms/" + realm} used by the SAML/OIDC endpoints).
 */
public final class RealmPaths {

    private RealmPaths() {
    }

    /**
     * @param realm the active realm (typically {@link RealmContextHolder#get()}); null/blank ⇒ flat access
     * @param path  an application path, with or without a leading slash
     * @return {@code /realms/{realm}{path}}, or just {@code path} when no realm is in context
     */
    public static String prefixed(final String realm, final String path) {
        final String normalised = path.startsWith("/") ? path : "/" + path;
        if (realm == null || realm.isBlank()) {
            return normalised;
        }
        return "/realms/" + realm + normalised;
    }
}
