package group.mfnr.authorization.security;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.util.Assert;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

/**
 * Helix IAM E1.2 (scenario C): Redis-backed {@link OAuth2AuthorizationService} for the
 * high-throughput tier (HELIX_TOKEN_STORE=redis).
 *
 * <p>Each {@link OAuth2Authorization} (which is {@link java.io.Serializable}) is stored
 * whole under {@code helix:authz:id:{id}} via the template's value serializer, with one
 * value-indexed lookup key per contained token/code/state pointing back to the id. Every
 * key carries a TTL equal to the longest-lived contained token, so Redis auto-expires
 * spent authorizations (no cleanup job).
 *
 * <p>Consistency note: Redis (even with AOF) can lose the last fraction of a second of
 * writes on a crash or async-replica failover. That is acceptable here precisely because
 * the data is disposable — a lost authorization just forces a re-login, never corruption
 * or a security hole (live API calls validate JWTs by signature, not via this store).
 * Durable identity data and client secrets are never stored here — they stay in Postgres.
 */
public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private static final String ID_PREFIX = "helix:authz:id:";
    private static final String TOKEN_PREFIX = "helix:authz:tok:";
    /** Fallback TTL when an authorization has no expiring token yet (e.g. just-issued code). */
    private static final Duration DEFAULT_TTL = Duration.ofHours(1);
    /** Buffer so lookup keys outlive the token they point at, avoiding lookup races. */
    private static final Duration TTL_BUFFER = Duration.ofMinutes(5);

    private final RedisTemplate<String, Object> redisTemplate;

    public RedisOAuth2AuthorizationService(final RedisTemplate<String, Object> redisTemplate) {
        Assert.notNull(redisTemplate, "redisTemplate cannot be null");
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void save(final OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        final Duration ttl = computeTtl(authorization);
        redisTemplate.opsForValue().set(ID_PREFIX + authorization.getId(), authorization, ttl);
        for (final String value : lookupValues(authorization)) {
            redisTemplate.opsForValue().set(TOKEN_PREFIX + value, authorization.getId(), ttl);
        }
    }

    @Override
    public void remove(final OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        redisTemplate.delete(ID_PREFIX + authorization.getId());
        for (final String value : lookupValues(authorization)) {
            redisTemplate.delete(TOKEN_PREFIX + value);
        }
    }

    @Override
    public OAuth2Authorization findById(final String id) {
        Assert.hasText(id, "id cannot be empty");
        final Object value = redisTemplate.opsForValue().get(ID_PREFIX + id);
        return (value instanceof OAuth2Authorization authorization) ? authorization : null;
    }

    @Override
    public OAuth2Authorization findByToken(final String token, final OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        // All token/code/state values are indexed in one namespace; resolving by value and
        // loading the authoritative record by id lets Spring's own token-type/invalidation
        // checks decide validity, so the (ignored) tokenType need not be matched here.
        final Object id = redisTemplate.opsForValue().get(TOKEN_PREFIX + token);
        return (id != null) ? findById(id.toString()) : null;
    }

    /** All values that {@link #findByToken} may be called with for this authorization. */
    private Set<String> lookupValues(final OAuth2Authorization authorization) {
        final Set<String> values = new HashSet<>();
        addToken(values, authorization.getToken(OAuth2AuthorizationCode.class));
        addToken(values, authorization.getAccessToken());
        addToken(values, authorization.getToken(OAuth2RefreshToken.class));
        addToken(values, authorization.getToken(OidcIdToken.class));
        final String state = authorization.getAttribute(OAuth2ParameterNames.STATE);
        if (state != null) {
            values.add(state);
        }
        return values;
    }

    private void addToken(final Set<String> values, final OAuth2Authorization.Token<?> token) {
        if (token != null && token.getToken().getTokenValue() != null) {
            values.add(token.getToken().getTokenValue());
        }
    }

    /** TTL = time until the longest-lived contained token expires (plus a small buffer). */
    private Duration computeTtl(final OAuth2Authorization authorization) {
        Instant max = null;
        for (final Class<?> type : new Class<?>[]{
                OAuth2AuthorizationCode.class, OAuth2AccessToken.class, OAuth2RefreshToken.class,
                OidcIdToken.class}) {
            @SuppressWarnings("unchecked")
            final OAuth2Authorization.Token<?> token =
                    authorization.getToken((Class) type);
            if (token != null && token.getToken().getExpiresAt() != null) {
                final Instant expiresAt = token.getToken().getExpiresAt();
                if (max == null || expiresAt.isAfter(max)) {
                    max = expiresAt;
                }
            }
        }
        if (max == null) {
            return DEFAULT_TTL;
        }
        final Duration remaining = Duration.between(Instant.now(), max).plus(TTL_BUFFER);
        return remaining.isNegative() ? DEFAULT_TTL : remaining;
    }
}
