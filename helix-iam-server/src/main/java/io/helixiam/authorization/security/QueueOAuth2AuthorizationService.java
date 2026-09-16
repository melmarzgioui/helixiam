/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import io.helixiam.authorization.amqp.authzstore.AuthorizationRecord;
import io.helixiam.authorization.amqp.authzstore.AuthorizationStorePublisher;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Helix IAM (Q1): a queue-backed {@link OAuth2AuthorizationService} so the publisher needs no database — all
 * persistence is delegated to the subscriber (the {@code kubeiam} owner) over AMQP via
 * {@link AuthorizationStorePublisher}. Structurally mirrors {@link RedisOAuth2AuthorizationService}: the whole
 * (serializable) {@link OAuth2Authorization} is stored as an opaque base64 blob under its id, with one index
 * entry per contained token/code/state value pointing back to the id, so {@code findByToken} resolves by value
 * then loads the authoritative record. Selected by {@code helix.iam.token-store=queue}.
 *
 * <p>Like the Redis tier, the blob is treated as disposable (a lost authorization just forces a re-login,
 * never corruption — live API calls validate JWTs by signature, not via this store).
 */
public class QueueOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final AuthorizationStorePublisher store;

    public QueueOAuth2AuthorizationService(final AuthorizationStorePublisher store) {
        Assert.notNull(store, "store cannot be null");
        this.store = store;
    }

    @Override
    public void save(final OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        final List<String> tokenKeys = lookupValues(authorization);
        store.save(new AuthorizationRecord(authorization.getId(), authorization.getPrincipalName(),
                authorization.getAuthorizationGrantType().getValue(), AuthorizationBlobs.serialize(authorization),
                tokenKeys, latestExpiry(authorization)));
    }

    @Override
    public void remove(final OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        store.remove(new AuthorizationStorePublisher.RemoveRequest(authorization.getId(), lookupValues(authorization)));
    }

    @Override
    public OAuth2Authorization findById(final String id) {
        Assert.hasText(id, "id cannot be empty");
        return deserialize(store.findById(id));
    }

    @Override
    public OAuth2Authorization findByToken(final String token, final OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        // Every token/code/state value is indexed in one namespace; resolving by value and loading the
        // authoritative record lets SAS's own token-type/invalidation checks decide validity.
        return deserialize(store.findByToken(token));
    }

    /** All values {@link #findByToken} may be called with for this authorization. */
    private static List<String> lookupValues(final OAuth2Authorization authorization) {
        final List<String> values = new ArrayList<>();
        addToken(values, authorization.getToken(OAuth2AuthorizationCode.class));
        addToken(values, authorization.getAccessToken());
        addToken(values, authorization.getToken(OAuth2RefreshToken.class));
        addToken(values, authorization.getToken(OidcIdToken.class));
        // RFC 8628 device grant: at the device_authorization step these are the only tokens present, and the
        // token poll (device_code) + /activate page (user_code) resolve by them.
        addToken(values, authorization.getToken(OAuth2DeviceCode.class));
        addToken(values, authorization.getToken(OAuth2UserCode.class));
        final String state = authorization.getAttribute(OAuth2ParameterNames.STATE);
        if (state != null && !values.contains(state)) {
            values.add(state);
        }
        return values;
    }

    private static void addToken(final List<String> values, final OAuth2Authorization.Token<?> token) {
        if (token != null && token.getToken().getTokenValue() != null
                && !values.contains(token.getToken().getTokenValue())) {
            values.add(token.getToken().getTokenValue());
        }
    }

    /** Epoch-milli of the latest-expiring contained token, or null. */
    private static Long latestExpiry(final OAuth2Authorization authorization) {
        Instant max = null;
        for (final OAuth2Authorization.Token<?> token : new OAuth2Authorization.Token<?>[]{
                authorization.getToken(OAuth2AuthorizationCode.class), authorization.getAccessToken(),
                authorization.getToken(OAuth2RefreshToken.class), authorization.getToken(OidcIdToken.class),
                authorization.getToken(OAuth2DeviceCode.class), authorization.getToken(OAuth2UserCode.class)}) {
            if (token != null && token.getToken().getExpiresAt() != null
                    && (max == null || token.getToken().getExpiresAt().isAfter(max))) {
                max = token.getToken().getExpiresAt();
            }
        }
        return max == null ? null : max.toEpochMilli();
    }

    private static OAuth2Authorization deserialize(final AuthorizationRecord record) {
        return record == null ? null : AuthorizationBlobs.deserialize(record.blob());
    }
}
