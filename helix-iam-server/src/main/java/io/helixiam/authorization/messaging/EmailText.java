/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import org.springframework.web.util.HtmlUtils;

import java.util.Locale;
import java.util.Set;

/**
 * Item 3: the plain-text part of an HTML email, derived from its HTML body, so the email is usable in a client that
 * shows only text (or a provider that sends only the text part). Every link stays: a link whose text differs from its
 * URL becomes {@code Label: URL}, a bare URL stays a URL. Paragraphs, headings, list items and table rows become
 * blank-line separated blocks, {@code <br>} a line break, and entities are decoded. Styles, scripts and the head are
 * dropped, as are {@code javascript:} and other non-web links (their text is kept).
 *
 * <p>One left-to-right pass over the input (no regular expressions), so its cost is linear in the body length.
 */
public final class EmailText {

    private static final Set<String> BLOCKS = Set.of("p", "div", "tr", "table", "h1", "h2", "h3", "h4", "h5", "h6",
            "li", "ul", "ol", "blockquote", "section", "hr");
    private static final Set<String> SKIPPED = Set.of("style", "script", "head", "title");

    private EmailText() {
    }

    /** The plain text of {@code html}; empty for null. */
    public static String fromHtml(final String html) {
        if (html == null || html.isEmpty()) {
            return "";
        }
        final Builder out = new Builder();
        String skipping = null;
        String href = null;
        int anchorStart = -1;
        int i = 0;
        final int n = html.length();
        while (i < n) {
            final char c = html.charAt(i);
            if (c != '<') {
                final int next = html.indexOf('<', i);
                final int end = next < 0 ? n : next;
                if (skipping == null) {
                    out.text(HtmlUtils.htmlUnescape(html.substring(i, end)));
                }
                i = end;
                continue;
            }
            final int close = tagEnd(html, i + 1);
            if (close < 0) {
                break; // an unclosed tag at the end: dropped
            }
            final String tag = html.substring(i + 1, close);
            i = close + 1;
            final boolean closing = tag.startsWith("/");
            final String name = tagName(tag, closing ? 1 : 0);
            if (skipping != null) {
                if (closing && name.equals(skipping)) {
                    skipping = null;
                }
                continue;
            }
            if (!closing && SKIPPED.contains(name)) {
                skipping = name;
            } else if ("br".equals(name)) {
                out.lineBreak();
            } else if (BLOCKS.contains(name)) {
                out.blockBreak();
            } else if ("a".equals(name) && !closing) {
                if (anchorStart >= 0) {
                    out.endAnchor(anchorStart, href);
                }
                href = webUrl(attribute(tag, "href"));
                anchorStart = out.mark();
            } else if ("a".equals(name) && anchorStart >= 0) {
                out.endAnchor(anchorStart, href);
                anchorStart = -1;
                href = null;
            }
        }
        if (anchorStart >= 0) {
            out.endAnchor(anchorStart, href);
        }
        return out.result();
    }

    /** The index of the {@code >} that ends the tag starting at {@code from} (quotes respected), or -1. */
    private static int tagEnd(final String s, final int from) {
        char quote = 0;
        for (int j = from; j < s.length(); j++) {
            final char c = s.charAt(j);
            if (quote != 0) {
                if (c == quote) {
                    quote = 0;
                }
            } else if (c == '"' || c == '\'') {
                quote = c;
            } else if (c == '>') {
                return j;
            }
        }
        return -1;
    }

    private static String tagName(final String tag, final int from) {
        int j = from;
        while (j < tag.length() && Character.isLetterOrDigit(tag.charAt(j))) {
            j++;
        }
        return tag.substring(from, j).toLowerCase(Locale.ROOT);
    }

    /** The value of the double- or single-quoted attribute {@code name} in {@code tag}, decoded; null when absent. */
    private static String attribute(final String tag, final String name) {
        final String lower = tag.toLowerCase(Locale.ROOT);
        int from = 0;
        while (true) {
            final int at = lower.indexOf(name + "=", from);
            if (at < 0) {
                return null;
            }
            from = at + name.length() + 1;
            if (at > 0 && !Character.isWhitespace(lower.charAt(at - 1))) {
                continue;
            }
            if (from >= tag.length()) {
                return null;
            }
            final char quote = tag.charAt(from);
            if (quote != '"' && quote != '\'') {
                return null;
            }
            final int end = tag.indexOf(quote, from + 1);
            return end < 0 ? null : HtmlUtils.htmlUnescape(tag.substring(from + 1, end)).trim();
        }
    }

    private static String webUrl(final String href) {
        if (href == null) {
            return null;
        }
        final String lower = href.toLowerCase(Locale.ROOT);
        return lower.startsWith("https://") || lower.startsWith("http://") || lower.startsWith("mailto:") ? href : null;
    }

    /** Collects the text: whitespace collapsed, blocks separated by one blank line, lines trimmed. */
    private static final class Builder {

        private final StringBuilder out = new StringBuilder();
        /** Pending whitespace: 0 none, 1 a space, 2 a line break, 3 a blank line. */
        private int pending;

        void text(final String text) {
            for (int k = 0; k < text.length(); k++) {
                final char c = text.charAt(k);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f') {
                    pending = Math.max(pending, 1);
                } else {
                    flush();
                    out.append(c);
                }
            }
        }

        void lineBreak() {
            pending = Math.max(pending, 2);
        }

        void blockBreak() {
            pending = 3;
        }

        int mark() {
            flush();
            return out.length();
        }

        void endAnchor(final int start, final String href) {
            if (href == null) {
                return;
            }
            final String label = out.substring(start).strip();
            if (label.isEmpty() || label.equals(href)) {
                out.setLength(start);
                out.append(href);
            } else if (!label.equals(href.replaceFirst("^mailto:", ""))) {
                out.append(": ").append(href);
            }
        }

        private void flush() {
            if (out.isEmpty()) {
                pending = 0;
                return;
            }
            if (pending == 1) {
                out.append(' ');
            } else if (pending == 2) {
                out.append('\n');
            } else if (pending == 3) {
                out.append("\n\n");
            }
            pending = 0;
        }

        String result() {
            return out.toString().strip();
        }
    }
}
