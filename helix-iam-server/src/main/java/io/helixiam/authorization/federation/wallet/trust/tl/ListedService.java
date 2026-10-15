/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * One current trust service read from a verified list: its certificate (the service digital identity) and where it
 * came from.
 *
 * @param certificate the service's X.509 certificate (a PID provider's issuing CA, for a PID list)
 * @param serviceType the service type URI ({@code ServiceTypeIdentifier})
 * @param serviceName the service name (English when present, else the first)
 * @param provider    the trust service provider or trusted entity name
 * @param country     the provider's territory: the list's {@code SchemeTerritory}, or the entity's country for a LoTE
 * @param status      the current status URI, or null when the list has no per-service status (LoTE)
 */
public record ListedService(X509Certificate certificate, String serviceType, String serviceName, String provider,
                            String country, String status) {

    public ListedService {
        Objects.requireNonNull(certificate, "certificate");
        Objects.requireNonNull(serviceType, "serviceType");
    }
}
