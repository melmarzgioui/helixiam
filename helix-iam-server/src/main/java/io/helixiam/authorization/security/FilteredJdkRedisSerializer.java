/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;

import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;

/**
 * Java serialization for HelixIAM's Redis stores, read through the same JEP-290 allowlists as the queue (PostgreSQL)
 * stores: {@link AuthorizationBlobs#filter()} for the token store and the SSO-session reader,
 * {@link SessionBlobs#filter()} for Spring Session's HTTP sessions. Writes exactly what
 * {@link JdkSerializationRedisSerializer} writes, and reads Spring Authorization Server 1.x data
 * ({@link LegacyAuthorizationServerSerialization}).
 *
 * <p>A value the allowlist refuses (a deserialization gadget planted in Redis: the class is never constructed) or that
 * cannot be read (a class this version does not have) is not an error: the token store and the SSO reader see it as
 * absent ({@code null}), the session store as {@link #UNREADABLE}, which drops the whole session
 * ({@code RedisSessionSerializationConfig}), as the queue stores do. Each is logged (WARN) by the refused class name or
 * the failure's type only, never the content.
 */
public final class FilteredJdkRedisSerializer implements RedisSerializer<Object> {

    /** What the session store's serializer answers for an attribute it cannot or may not read. */
    public static final Object UNREADABLE = Unreadable.VALUE;

    private static final Logger LOG = LogManager.getLogger(FilteredJdkRedisSerializer.class);

    private final String store;
    private final ObjectInputFilter filter;
    private final Object onFailure;
    private final JdkSerializationRedisSerializer writer = new JdkSerializationRedisSerializer();

    private FilteredJdkRedisSerializer(final String store, final ObjectInputFilter filter, final Object onFailure) {
        this.store = store;
        this.filter = filter;
        this.onFailure = onFailure;
    }

    /** For OAuth2 authorizations (the Redis token store and the SSO-session reader): a refused entry is absent. */
    public static FilteredJdkRedisSerializer forAuthorizations() {
        return new FilteredJdkRedisSerializer("token store", AuthorizationBlobs.filter(), null);
    }

    /** For Spring Session's HTTP-session attributes: a refused attribute reads as {@link #UNREADABLE}. */
    public static FilteredJdkRedisSerializer forSessions() {
        return new FilteredJdkRedisSerializer("session store", SessionBlobs.filter(), UNREADABLE);
    }

    @Override
    public byte[] serialize(final Object value) {
        return writer.serialize(value);
    }

    @Override
    public Object deserialize(final byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return null;
        }
        final RecordingFilter recording = new RecordingFilter(filter);
        try (ObjectInputStream in = LegacyAuthorizationServerSerialization.objectInputStream(bytes)) {
            in.setObjectInputFilter(recording);
            return in.readObject();
        } catch (final Exception e) {
            if (recording.rejectedClass != null) {
                LOG.warn("Redis {}: entry dropped: it holds {}, which the store's allowlist rejects", store,
                        LogSafe.sanitize(recording.rejectedClass));
            } else if (recording.rejectedLimit) {
                LOG.warn("Redis {}: entry dropped: it exceeds the store's size or depth limits", store);
            } else {
                LOG.warn("Redis {}: entry dropped: it could not be read ({})", store, LogSafe.sanitize(e.getClass().getName()));
            }
            return onFailure;
        }
    }

    /** The marker for an unreadable session attribute; never stored (the session holding it is dropped). */
    private enum Unreadable {
        VALUE
    }

    /** The store's filter, remembering what it rejected (a class name, or a size/depth limit) for the log line. */
    private static final class RecordingFilter implements ObjectInputFilter {

        private final ObjectInputFilter delegate;
        private String rejectedClass;
        private boolean rejectedLimit;

        RecordingFilter(final ObjectInputFilter delegate) {
            this.delegate = delegate;
        }

        @Override
        public Status checkInput(final FilterInfo info) {
            final Status status = delegate.checkInput(info);
            if (status == Status.REJECTED && rejectedClass == null && !rejectedLimit) {
                final Class<?> type = info.serialClass();
                if (type != null) {
                    rejectedClass = type.isArray() ? type.getComponentType().getName() + "[]" : type.getName();
                } else {
                    rejectedLimit = true;
                }
            }
            return status;
        }
    }
}
