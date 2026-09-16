package io.helixiam.authorization.session;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Helix IAM SSO P4: the high-throughput SSO-session reader — rolls up the OAuth2 authorizations stored in
 * Redis ({@code helix:authz:id:*}, written by {@code RedisOAuth2AuthorizationService}) the same way the
 * {@link JdbcSsoSessionStore} does for Postgres. Selected when {@code helix.iam.token-store=redis}. The
 * grouping itself is the shared, store-agnostic {@link SsoSessionRollup}.
 */
public class RedisSsoSessionStore implements SsoSessionStore {

    private static final Logger LOG = LogManager.getLogger(RedisSsoSessionStore.class);
    private static final String ID_PREFIX = "helix:authz:id:";

    private final RedisTemplate<String, Object> redisTemplate;

    public RedisSsoSessionStore(final RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public List<SsoSession> findAll() {
        final Set<String> keys = redisTemplate.keys(ID_PREFIX + "*"); // admin-list read; infrequent
        if (keys == null || keys.isEmpty()) {
            return List.of();
        }
        final List<SsoSessionRollup.Entry> entries = new ArrayList<>();
        for (final String key : keys) {
            try {
                if (redisTemplate.opsForValue().get(key) instanceof OAuth2Authorization authorization) {
                    final SsoSessionRollup.Entry entry = SsoSessionRollup.entryOf(authorization);
                    if (entry != null) {
                        entries.add(entry);
                    }
                }
            } catch (final RuntimeException e) {
                LOG.debug("Could not read SSO entry from {}: {}", key, e.getMessage());
            }
        }
        return SsoSessionRollup.assemble(entries);
    }

    @Override
    public SsoSession findById(final String ssoSessionId) {
        return findAll().stream().filter(s -> s.ssoSessionId().equals(ssoSessionId)).findFirst().orElse(null);
    }

}
