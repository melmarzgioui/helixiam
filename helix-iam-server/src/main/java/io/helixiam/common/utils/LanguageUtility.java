/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.utils;

/**
 * Vendored verbatim (package renamed only) from io.helixiam.subscriber.starter.utils.LanguageUtility.
 */
public final class LanguageUtility {

    private LanguageUtility() {
        throw new IllegalAccessError();
    }

    public static boolean containsArabic(final String str) {

        if(str != null && !str.isEmpty()) {
            try {
                for (int i = 0; i < str.length(); i++) {
                    final char letter = str.charAt(i);

                    if (letter >= 0x0600 && letter <= 0x06E0) {
                        return true;
                    }
                }
            } catch (final Exception e) {
                // swallow, not important
            }
        }

        return false;
    }
}
