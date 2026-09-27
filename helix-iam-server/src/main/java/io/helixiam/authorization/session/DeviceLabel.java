/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import java.util.Locale;

/**
 * rc.6 item 7b: the browser and operating system of a sign-in, as the account console shows it ("Firefox on Windows").
 * Read from the {@code User-Agent} header at sign-in; only these two short names are kept, never the header itself.
 * A value it does not recognise is null (the console then says "Unknown browser").
 *
 * @param browser Chrome, Edge, Firefox, Safari, Opera, Samsung Internet; null when unknown
 * @param os      Windows, macOS, iPhone, iPad, Android, ChromeOS, Linux; null when unknown
 */
public record DeviceLabel(String browser, String os) {

    /** Nothing recognised. */
    public static final DeviceLabel UNKNOWN = new DeviceLabel(null, null);

    /** The browser and system named by {@code userAgent} (null or blank: {@link #UNKNOWN}). */
    public static DeviceLabel parse(final String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            return UNKNOWN;
        }
        final String ua = userAgent.length() > 512 ? userAgent.substring(0, 512) : userAgent;
        return new DeviceLabel(browserOf(ua), osOf(ua));
    }

    private static String browserOf(final String ua) {
        // Order matters: Edge, Opera and Samsung Internet also say "Chrome"; Chrome also says "Safari".
        if (ua.contains("Edg/") || ua.contains("EdgA/") || ua.contains("EdgiOS/")) {
            return "Edge";
        }
        if (ua.contains("OPR/") || ua.contains("Opera")) {
            return "Opera";
        }
        if (ua.contains("SamsungBrowser/")) {
            return "Samsung Internet";
        }
        if (ua.contains("Firefox/") || ua.contains("FxiOS/")) {
            return "Firefox";
        }
        if (ua.contains("Chrome/") || ua.contains("CriOS/") || ua.contains("Chromium/")) {
            return "Chrome";
        }
        if (ua.contains("Safari/") && ua.contains("Version/")) {
            return "Safari";
        }
        return null;
    }

    private static String osOf(final String ua) {
        final String lower = ua.toLowerCase(Locale.ROOT);
        if (lower.contains("iphone")) {
            return "iPhone";
        }
        if (lower.contains("ipad")) {
            return "iPad";
        }
        if (lower.contains("android")) {
            return "Android";
        }
        if (lower.contains("windows")) {
            return "Windows";
        }
        if (lower.contains("cros")) {
            return "ChromeOS";
        }
        if (lower.contains("mac os x") || lower.contains("macintosh")) {
            return "macOS";
        }
        if (lower.contains("linux")) {
            return "Linux";
        }
        return null;
    }
}
