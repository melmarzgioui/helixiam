/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.scim;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helix IAM E7 (SCIM 2.0): minimal SCIM filter parsing (RFC 7644 §3.4.2.2). Helix supports the single
 * equality filter that real provisioning clients (Okta, Azure AD) send to look up a resource before
 * create — {@code userName eq "x"} / {@code displayName eq "x"} — which is enough to make
 * create-or-update idempotent.
 */
public final class ScimFilters {

    private static final Pattern USERNAME_EQ =
            Pattern.compile("^\\s*userName\\s+eq\\s+\"([^\"]*)\"\\s*$", Pattern.CASE_INSENSITIVE);
    private static final Pattern DISPLAYNAME_EQ =
            Pattern.compile("^\\s*displayName\\s+eq\\s+\"([^\"]*)\"\\s*$", Pattern.CASE_INSENSITIVE);

    private ScimFilters() {
    }

    /** The value {@code x} of a {@code userName eq "x"} filter, or {@code null} when the filter is absent/other. */
    public static String userNameEq(final String filter) {
        return match(USERNAME_EQ, filter);
    }

    /** The value {@code x} of a {@code displayName eq "x"} filter, or {@code null}. */
    public static String displayNameEq(final String filter) {
        return match(DISPLAYNAME_EQ, filter);
    }

    private static String match(final Pattern pattern, final String filter) {
        if (filter == null || filter.isBlank()) {
            return null;
        }
        final Matcher m = pattern.matcher(filter);
        return m.matches() ? m.group(1) : null;
    }
}
