package io.helixiam.authorization.security.resource;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Helix IAM (RFC 8707 — Resource Indicators for OAuth 2.0). Pure, side-effect-free logic for the
 * {@code resource} parameter on {@code /oauth2/authorize} and {@code /oauth2/token}:
 *
 * <ul>
 *   <li>{@link #isValidResource(String)} — a resource is an <b>absolute URI without a fragment</b>
 *       (RFC 8707 §2). Anything else is {@code invalid_target}.</li>
 *   <li>{@link #isAllowed(String, java.util.Collection)} — when a client has an allow-list, a
 *       requested resource must be a member; an <b>empty/blank allow-list means "accept any"</b>
 *       (back-compat — pre-RFC-8707 clients are untouched).</li>
 *   <li>{@link #resolveAudience(List, java.util.Collection)} — compute the {@code aud} claim value
 *       for a set of requested resources, validating + allow-list-checking each. Returns a
 *       <b>mutable</b> {@link ArrayList} so the SAS Jackson allowlist accepts it as a token claim
 *       (CRITICAL: never {@code List.of}/{@code .toList()} here).</li>
 * </ul>
 *
 * This class is deliberately decoupled from Spring/SAS so it can be unit-tested in isolation and
 * reused from both the authorize-request validator and the JWT token customizer.
 */
public final class ResourceIndicators {

    private ResourceIndicators() {
    }

    /** RFC 8707 §2: a {@code resource} value MUST be an absolute URI and MUST NOT contain a fragment. */
    public static boolean isValidResource(final String resource) {
        if (resource == null || resource.isBlank()) {
            return false;
        }
        try {
            final URI uri = new URI(resource);
            return uri.isAbsolute() && uri.getRawFragment() == null;
        } catch (final URISyntaxException e) {
            return false;
        }
    }

    /**
     * Whether {@code resource} is permitted for a client given its allow-list. A {@code null} or empty
     * allow-list means the client has none configured → accept any (back-compat). Otherwise the
     * resource must be an exact member.
     */
    public static boolean isAllowed(final String resource, final java.util.Collection<String> allowList) {
        if (allowList == null || allowList.isEmpty()) {
            return true;
        }
        return allowList.contains(resource);
    }

    /**
     * The result of resolving a token's audience from the requested resources: either a mutable list of
     * granted audience values, or an {@code invalid_target} rejection carrying the offending resource.
     */
    public record AudienceResult(boolean rejected, String invalidResource, List<String> audience) {

        static AudienceResult granted(final List<String> audience) {
            return new AudienceResult(false, null, audience);
        }

        static AudienceResult reject(final String resource) {
            return new AudienceResult(true, resource, Collections.emptyList());
        }
    }

    /**
     * Compute the access-token {@code aud} from the requested {@code resource} values:
     * <ul>
     *   <li>no resources requested → {@link AudienceResult#audience()} is empty and not rejected; the
     *       caller MUST leave the default audience untouched (the OAuth hot path is unchanged).</li>
     *   <li>any requested resource that is not a valid absolute-URI-without-fragment, or not in the
     *       client allow-list, → {@code rejected} with that resource as {@code invalidResource}.</li>
     *   <li>otherwise → a <b>mutable</b> de-duplicated audience list (insertion order preserved).</li>
     * </ul>
     */
    public static AudienceResult resolveAudience(final List<String> requestedResources,
                                                 final java.util.Collection<String> allowList) {
        if (requestedResources == null || requestedResources.isEmpty()) {
            return AudienceResult.granted(new ArrayList<>());
        }
        final Set<String> ordered = new LinkedHashSet<>();
        for (final String resource : requestedResources) {
            if (!isValidResource(resource) || !isAllowed(resource, allowList)) {
                return AudienceResult.reject(resource);
            }
            ordered.add(resource);
        }
        // MUTABLE collection — SAS Jackson token-claim allowlist rejects immutable List.of/.toList().
        return AudienceResult.granted(new ArrayList<>(ordered));
    }

    /** Split a comma/space-joined allow-list column (DB storage) into a set; blank → empty (accept any). */
    public static Set<String> parseAllowList(final String joined) {
        if (joined == null || joined.isBlank()) {
            return Collections.emptySet();
        }
        final Set<String> out = new LinkedHashSet<>();
        for (final String part : joined.split("[,\\s]+")) {
            if (!part.isBlank()) {
                out.add(part.trim());
            }
        }
        return out;
    }
}
