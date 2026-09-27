/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.log;

import java.util.regex.Pattern;

/**
 * Neutralises user-controlled values before they are passed to a logger, so a CR/LF (or any other control
 * character) in a username, client id, realm id, e-mail address or request parameter cannot forge an extra
 * log line or corrupt the terminal.
 *
 * <p>Every line break ({@code \R}: CR, LF, CRLF, VT, FF, NEL, U+2028, U+2029) becomes one {@code _}, and every
 * remaining control character (Unicode category {@code Cc}, e.g. TAB, NUL, ESC, DEL) becomes {@code _} too.
 * Ordinary text, including non-ASCII letters, is returned unchanged.
 *
 * <p>This is the code-level half of the defence; the other half is the log layout itself
 * ({@code %enc{%m}{CRLF}} in {@code log4j2-spring.xml}). The line-break removal is deliberately a plain
 * {@link String#replaceAll(String, String)} call on every path, because that is the form static analysis
 * (CodeQL {@code java/log-injection}) recognises as a sanitiser. Do not add an early "nothing to replace"
 * return that skips it.
 */
public final class LogSafe {

    private static final String REPLACEMENT = "_";

    /** Control characters that are not line breaks (those are already gone by the time this runs). */
    private static final Pattern CONTROL = Pattern.compile("\\p{Cc}");

    private LogSafe() {
    }

    /**
     * Returns {@code value} with line breaks and other control characters replaced by {@code _}, or
     * {@code null} when {@code value} is {@code null} (so the logger still prints {@code null}).
     */
    public static String sanitize(final String value) {
        if (value == null) {
            return null;
        }
        final String noLineBreaks = value.replaceAll("\\R", "_");
        return CONTROL.matcher(noLineBreaks).replaceAll(REPLACEMENT);
    }

    /**
     * Sanitises {@code value.toString()}; {@code null} stays {@code null}. For ids, enums, collections and other
     * non-String values that are logged with a {@code {}} placeholder.
     */
    public static String sanitize(final Object value) {
        return value == null ? null : sanitize(value.toString());
    }
}
