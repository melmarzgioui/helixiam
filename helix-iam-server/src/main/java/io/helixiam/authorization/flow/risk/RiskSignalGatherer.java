/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.risk;

import io.helixiam.authorization.security.net.ClientIpResolver;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Helix IAM (adaptive auth): pulls the raw request signals — client IP, User-Agent and the
 * remembered-device cookie — off an {@link HttpServletRequest}, and derives a stable, privacy-
 * preserving device fingerprint (a SHA-256 hash of the cookie value; the raw cookie never leaves
 * the browser→server boundary in stored form). Pure given a request, so it is unit-testable with
 * a mock request and carries no Spring dependency beyond the stereotype.
 */
@Component
public class RiskSignalGatherer {

    /** Cookie carrying the opaque remembered-device token (set on a successful low-risk login). */
    public static final String DEVICE_COOKIE = "helix_device";

    public record RawSignals(String ip, String userAgent, String deviceFingerprint, String rawDeviceToken) {
    }

    private final ClientIpResolver clientIps;

    /** Resolves the client IP with the application's {@link ClientIpResolver} at request time. */
    public RiskSignalGatherer() {
        this(null);
    }

    @Autowired
    public RiskSignalGatherer(final ClientIpResolver clientIps) {
        this.clientIps = clientIps;
    }

    public RawSignals gather(final HttpServletRequest request) {
        if (request == null) {
            return new RawSignals(null, null, null, null);
        }
        final String ip = (clientIps == null ? ClientIpResolver.current() : clientIps).resolve(request);
        final String userAgent = request.getHeader("User-Agent");
        final String rawToken = deviceCookie(request);
        final String fingerprint = rawToken == null ? null : sha256(rawToken);
        return new RawSignals(ip, userAgent, fingerprint, rawToken);
    }

    private static String deviceCookie(final HttpServletRequest request) {
        final Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (final Cookie cookie : cookies) {
            if (DEVICE_COOKIE.equals(cookie.getName()) && cookie.getValue() != null && !cookie.getValue().isBlank()) {
                return cookie.getValue();
            }
        }
        return null;
    }

    /** SHA-256 hex of the device token (so only a hash is ever persisted / compared). */
    public static String sha256(final String value) {
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e); // never on a standard JRE
        }
    }
}
