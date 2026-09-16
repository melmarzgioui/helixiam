/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.credential;

/**
 * Helix IAM: pluggable credential type owned by the identity domain (subscriber). Each provider
 * knows how to verify one credential type at login (TOTP secret, recovery code, HOTP counter,
 * passkey, …). Providers are <b>auto-discovered</b>: drop a {@code @Component} implementing this
 * interface and {@link CredentialProviderRegistry} picks it up — no change to the generic AMQP
 * endpoint or the registry. This is the subscriber-side counterpart of the Authenticator SPI's
 * auto-discovery on the publisher.
 */
public interface CredentialProvider {

    /** Stable credential-type id, referenced by the publisher's authenticator (e.g. "hotp"). */
    String type();

    /** Verifies the user's submitted input for this credential, consuming/advancing as needed. */
    boolean verify(String userId, String input);
}
