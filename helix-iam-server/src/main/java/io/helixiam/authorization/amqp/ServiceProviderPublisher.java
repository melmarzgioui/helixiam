/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;

public interface ServiceProviderPublisher {

    String EXCHANGE_AUTHORIZATION_SERVICE_PROVIDER = "exchange-authorization-service-provider";
    String AUTHORIZATION_SERVICE_PROVIDER_CREATE = "authorization.service.provider.create";
    String AUTHORIZATION_SERVICE_PROVIDER_CLIENT_ID_GET = "authorization.service.provider.client.id.get";
    String AUTHORIZATION_SERVICE_PROVIDER_ID_GET = "authorization.service.provider.id.get";
    String AUTHORIZATION_SERVICE_PROVIDER_KEY_PAIR = "authorization.service.provider.key.pair";
    String AUTHORIZATION_SERVICE_PROVIDER_VERIFICATION_KEYS = "authorization.service.provider.verification.keys";
    String AUTHORIZATION_SERVICE_PROVIDER_WEB_ORIGINS = "authorization.service.provider.web.origins";


    void save(final OAuth2Authorization authorization);


    /** MT-3: the ACTIVE signing keypair for {@code realm} (admin realm seeds from {@code /jks}; others are own). */
    KeyPair retrieveKeyPair(final String realm);

    /** E1.4/MT-3: {@code realm}'s ROTATED public keys to add to its JWKS for the rotation overlap window. */
    ArrayList<RSAPublicKey> retrieveVerificationKeys(final String realm);

    /** Helix IAM (CORS): {@code realm}'s allowed browser origins (union over its clients' web origins). */
    ArrayList<String> retrieveWebOrigins(final String realm);

    /** MT-3: {@code realmScopedId} = {@code realmserviceProviderId} (see {@link RealmScopedKey}). */
    RegisteredClient findById(final String realmScopedId);

    /** MT-3: {@code realmScopedClientId} = {@code realmclientId} (see {@link RealmScopedKey}). */
    RegisteredClient findByClientId(final String realmScopedClientId);
}
