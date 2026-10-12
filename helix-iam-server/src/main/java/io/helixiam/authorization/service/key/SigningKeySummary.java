/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

/**
 * One stored realm signing key as the admin console lists it: its reference and public parts only. There is no way to
 * reach the private key from here.
 *
 * @param keyRef           the reference to put in a provider's {@code accessKeyRef} ({@code software:<realm>/<name>})
 * @param name             the name it was imported under
 * @param algorithm        the JWS algorithm its curve decides ({@code ES256}, {@code ES384}, {@code ES512})
 * @param certificateChain leaf first, without the root (what goes into {@code x5c})
 * @param createdAt        when it was imported
 */
public record SigningKeySummary(String keyRef, String name, String algorithm, List<X509Certificate> certificateChain,
                                Instant createdAt) {

    public SigningKeySummary {
        certificateChain = List.copyOf(certificateChain);
    }

    @Override
    public String toString() {
        return "SigningKeySummary[" + keyRef + ", " + algorithm + "]";
    }
}
