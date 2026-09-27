/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

/**
 * One mailbox of a rendered email: the address and an optional display name ({@code null} or blank = none).
 */
public record EmailAddress(String address, String name) {

    public EmailAddress {
        if (address == null || address.isBlank()) {
            throw new IllegalArgumentException("An email address is required");
        }
        address = address.trim();
        name = name == null || name.isBlank() ? null : name.trim();
        if (containsLineBreak(address) || (name != null && containsLineBreak(name))) {
            throw new IllegalArgumentException("An email address or name must not contain a line break");
        }
    }

    public static EmailAddress of(final String address) {
        return new EmailAddress(address, null);
    }

    public static EmailAddress of(final String address, final String name) {
        return new EmailAddress(address, name);
    }

    private static boolean containsLineBreak(final String value) {
        return value.indexOf('\r') >= 0 || value.indexOf('\n') >= 0;
    }
}
