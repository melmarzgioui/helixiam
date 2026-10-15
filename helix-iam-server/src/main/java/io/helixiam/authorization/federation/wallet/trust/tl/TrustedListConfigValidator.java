/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import java.net.URI;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The admin rules for a trusted list source; field → message (the admin API's {@code fieldErrors}), empty when the
 * settings are usable. Messages never echo PEM content.
 */
public final class TrustedListConfigValidator {

    public static final int MAX_GRACE_HOURS = 720;
    public static final int MAX_SERVICE_TYPES = 20;
    public static final int MAX_TERRITORIES = 40;
    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9._-]{1,64}");
    private static final Pattern TERRITORY = Pattern.compile("[A-Z]{2}");
    private static final Pattern URI_SCHEME = Pattern.compile("(?i)(https?|urn):.+");

    private TrustedListConfigValidator() {
    }

    public static Map<String, String> validate(final TrustedListSource.Config c) {
        final Map<String, String> e = new LinkedHashMap<>();
        if (c.name() == null || !NAME.matcher(c.name()).matches()) {
            e.put("name", "The name must be 1-64 characters of A-Z, a-z, 0-9, '.', '_' or '-'");
        }
        checkUrl(c.url(), e);
        if (c.format() == null) {
            e.put("format", "Choose the list format");
        }
        try {
            for (final java.security.cert.X509Certificate cert : PemCertificates.parse(c.signerCertificates())) {
                final String problem = PemCertificates.keyProblem(cert);
                if (problem != null) {
                    e.put("signerCertificates", problem + " (RSA 2048 bits or more, or EC P-256 or stronger)");
                    break;
                }
            }
        } catch (final IllegalArgumentException ex) {
            e.put("signerCertificates", ex.getMessage());
        }
        if (c.serviceTypes().isEmpty()) {
            e.put("serviceTypes", "At least one service type is required");
        } else if (c.serviceTypes().size() > MAX_SERVICE_TYPES) {
            e.put("serviceTypes", "At most " + MAX_SERVICE_TYPES + " service types");
        } else if (!uris(c.serviceTypes())) {
            e.put("serviceTypes", "Each service type must be an absolute URI (http, https or urn), listed once");
        }
        if (!c.acceptedStatuses().isEmpty()) {
            if (!uris(c.acceptedStatuses())) {
                e.put("acceptedStatuses", "Each status must be an absolute URI, listed once");
            } else if (c.acceptedStatuses().stream().anyMatch(TrustedListSpec.NEVER_ACCEPTED::contains)) {
                e.put("acceptedStatuses", "A withdrawn or deprecated service can never be accepted");
            }
        }
        if (c.territories().size() > MAX_TERRITORIES) {
            e.put("territories", "At most " + MAX_TERRITORIES + " territories");
        } else if (c.territories().stream().anyMatch(t -> t == null || !TERRITORY.matcher(t).matches())
                || new HashSet<>(c.territories()).size() != c.territories().size()) {
            e.put("territories", "Territories are two upper-case letters (as in the list: NL, DE, EL, EU), listed once");
        }
        if (c.graceHours() < 0 || c.graceHours() > MAX_GRACE_HOURS) {
            e.put("graceHours", "The grace period must be 0-" + MAX_GRACE_HOURS + " hours");
        }
        return e;
    }

    private static void checkUrl(final String url, final Map<String, String> e) {
        if (url == null || url.isBlank()) {
            e.put("url", "The list URL is required");
            return;
        }
        if (url.length() > 2048) {
            e.put("url", "The list URL is too long");
            return;
        }
        try {
            final URI uri = new URI(url.trim());
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getRawUserInfo() != null
                    || uri.getRawFragment() != null) {
                e.put("url", "The list URL must be an https URL without user information or fragment");
            }
        } catch (final Exception ex) {
            e.put("url", "The list URL is not a valid URL");
        }
    }

    private static boolean uris(final List<String> values) {
        final Set<String> seen = new HashSet<>();
        for (final String v : values) {
            if (v == null || v.length() > 512 || !URI_SCHEME.matcher(v).matches() || v.chars().anyMatch(ch -> ch <= ' ')
                    || !seen.add(v)) {
                return false;
            }
        }
        return true;
    }
}
