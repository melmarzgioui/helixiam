/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import org.springframework.web.util.HtmlUtils;

import java.util.Locale;

/**
 * The shared layout every HTML email is sent in: a centred 560 px card on the brand's background, the brand's logo
 * (or its name) on top, the template body, and a footer (the theme's footer text, else "Sent by {name}.", and the
 * theme's privacy / terms / support links). Colours come from the {@link EmailBranding} (the theme's light palette).
 * Built from tables with inline styles so it renders the same in Outlook, Gmail, Apple Mail and on phones.
 *
 * <p>In a template body, a link marked {@code data-button} ({@code <a href="{{link}}" data-button>Sign in</a>})
 * becomes a solid button in the brand colour.
 */
public final class EmailLayout {

    static final String FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif";
    /** A monospace stack for codes. */
    static final String MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace";

    private EmailLayout() {
    }

    public static String wrap(final EmailBranding branding, final String subject, final String bodyHtml) {
        return wrap(branding, subject, bodyHtml, Locale.ENGLISH);
    }

    /** The email document in {@code locale}'s language ({@code <html lang>} and the default footer line). */
    public static String wrap(final EmailBranding branding, final String subject, final String bodyHtml,
                              final Locale locale) {
        final EmailBranding b = branding == null ? EmailBranding.helixIam() : branding;
        final Locale l = locale == null ? Locale.ENGLISH : locale;
        final String name = esc(b.name());
        final String nameSpan = "<span style=\"font-family:" + FONT + ";font-size:18px;font-weight:700;color:" + b.ink()
                + ";\">" + name + "</span>";
        final String header = b.logoUrl() != null
                ? "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr>"
                    + "<td style=\"padding-right:12px;\"><img src=\"" + esc(b.logoUrl()) + "\" alt=\"\" "
                    + "height=\"36\" style=\"display:block;height:36px;width:auto;max-width:200px;border:0;\"></td>"
                    + "<td>" + nameSpan + "</td></tr></table>"
                : nameSpan;
        final String lang = esc(l.getLanguage().isEmpty() ? "en" : l.getLanguage());
        return "<!DOCTYPE html>\n<html lang=\"" + lang + "\"><head><meta charset=\"UTF-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                + "<meta name=\"color-scheme\" content=\"light\"><title>" + esc(subject == null ? "" : subject)
                + "</title></head>\n<body style=\"margin:0;padding:0;background-color:" + b.background() + ";\">"
                + "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" bgcolor=\""
                + b.background() + "\" style=\"background-color:" + b.background() + ";\"><tr><td align=\"center\" "
                + "style=\"padding:32px 16px;\">"
                + "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" "
                + "style=\"max-width:560px;width:100%;\">"
                + "<tr><td style=\"padding:0 8px 20px 8px;\">" + header + "</td></tr>"
                + "<tr><td bgcolor=\"" + b.card() + "\" style=\"background-color:" + b.card() + ";border:1px solid "
                + b.border() + ";border-radius:8px;padding:32px 32px 28px 32px;font-family:" + FONT
                + ";font-size:15px;line-height:1.6;color:" + b.ink() + ";\">"
                + buttons(bodyHtml == null ? "" : bodyHtml, b.color(), b.onColor())
                + "</td></tr>"
                + "<tr><td style=\"padding:16px 8px 0 8px;font-family:" + FONT + ";font-size:12px;line-height:1.5;color:"
                + b.inkMuted() + ";\">" + footer(b, l) + "</td></tr>"
                + "</table></td></tr></table></body></html>\n";
    }

    /** The footer: the theme's footer text (else "Sent by {name}.") and its legal links, escaped. */
    private static String footer(final EmailBranding b, final Locale locale) {
        final String line = b.footerText() != null ? b.footerText()
                : ("nl".equals(locale.getLanguage()) ? "Verstuurd door " : "Sent by ") + b.name() + ".";
        final StringBuilder out = new StringBuilder(esc(line));
        final StringBuilder links = new StringBuilder();
        link(links, b.privacyUrl(), "Privacy", b.inkMuted());
        link(links, b.termsUrl(), "nl".equals(locale.getLanguage()) ? "Voorwaarden" : "Terms", b.inkMuted());
        link(links, b.supportUrl(), "nl".equals(locale.getLanguage()) ? "Hulp" : "Support", b.inkMuted());
        if (!links.isEmpty()) {
            out.append("<br>").append(links);
        }
        return out.toString();
    }

    private static void link(final StringBuilder out, final String url, final String label, final String color) {
        if (url == null) {
            return;
        }
        if (!out.isEmpty()) {
            out.append(" &middot; ");
        }
        out.append("<a href=\"").append(esc(url)).append("\" style=\"color:").append(color)
                .append(";text-decoration:underline;\">").append(label).append("</a>");
    }

    /**
     * {@code <a href="…" data-button>Label</a>} → a table-based button with the brand colour (Outlook-safe).
     *
     * <p>Same matches as {@code <a\\s+href="([^"]*)"\\s+data-button\\s*>(.*?)</a>} (case-insensitive, dot-all), found
     * in one left-to-right pass. That regex rescanned the rest of the body for every opening tag without a closing
     * {@code </a>}, quadratic in the body length (CodeQL #253, java/polynomial-redos).
     */
    private static String buttons(final String body, final String color, final String onColor) {
        final int lastClose = lastIndexOfIgnoreCase(body, "</a>");
        final StringBuilder out = new StringBuilder(body.length());
        int copied = 0;
        int from = 0;
        while (true) {
            final int start = indexOfIgnoreCase(body, "<a", from);
            if (start < 0 || start >= lastClose) {
                break; // no closing tag after here: nothing more can match
            }
            final int[] open = buttonOpening(body, start);
            final int close = open == null || open[2] > lastClose ? -1 : indexOfIgnoreCase(body, "</a>", open[2]);
            if (close < 0) {
                from = start + 1;
                continue;
            }
            out.append(body, copied, start).append(button(body.substring(open[0], open[1]),
                    body.substring(open[2], close), color, onColor));
            copied = close + "</a>".length();
            from = copied;
        }
        return out.append(body, copied, body.length()).toString();
    }

    private static String button(final String href, final String label, final String color, final String onColor) {
        return "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" "
                + "style=\"margin:8px 0;\"><tr><td bgcolor=\"" + color + "\" style=\"border-radius:6px;background-color:"
                + color + ";\"><a href=\"" + href + "\" target=\"_blank\" style=\"display:inline-block;"
                + "padding:12px 24px;font-family:" + FONT + ";font-size:15px;font-weight:600;color:" + onColor + ";"
                + "text-decoration:none;border-radius:6px;background-color:" + color + ";\">" + label + "</a></td></tr></table>";
    }

    /**
     * Parses {@code <a\\s+href="…"\\s+data-button\\s*>} at {@code start}: {href start, href end, tag end}, or null. Linear in
     * the tag's length (the href runs to the next quote).
     */
    private static int[] buttonOpening(final String s, final int start) {
        int i = start + 2;
        final int afterA = skipSpace(s, i);
        if (afterA == i || !regionIs(s, afterA, "href=\"")) {
            return null;
        }
        final int hrefStart = afterA + "href=\"".length();
        final int hrefEnd = s.indexOf('"', hrefStart);
        if (hrefEnd < 0) {
            return null;
        }
        i = hrefEnd + 1;
        final int afterHref = skipSpace(s, i);
        if (afterHref == i || !regionIs(s, afterHref, "data-button")) {
            return null;
        }
        i = skipSpace(s, afterHref + "data-button".length());
        return i < s.length() && s.charAt(i) == '>' ? new int[]{hrefStart, hrefEnd, i + 1} : null;
    }

    /** The index after the whitespace ({@code \\s}: space, tab, LF, VT, FF, CR) at {@code i}. */
    private static int skipSpace(final String s, final int i) {
        int j = i;
        while (j < s.length() && isSpace(s.charAt(j))) {
            j++;
        }
        return j;
    }

    private static boolean isSpace(final char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == 0x0B || c == '\f' || c == '\r';
    }

    /** ASCII case-insensitive, like {@code Pattern.CASE_INSENSITIVE}. */
    private static boolean regionIs(final String s, final int at, final String token) {
        if (at < 0 || at + token.length() > s.length()) {
            return false;
        }
        for (int k = 0; k < token.length(); k++) {
            if (asciiLower(s.charAt(at + k)) != token.charAt(k)) {
                return false;
            }
        }
        return true;
    }

    private static int indexOfIgnoreCase(final String s, final String token, final int from) {
        for (int i = Math.max(0, from); i + token.length() <= s.length(); i++) {
            if (regionIs(s, i, token)) {
                return i;
            }
        }
        return -1;
    }

    private static int lastIndexOfIgnoreCase(final String s, final String token) {
        for (int i = s.length() - token.length(); i >= 0; i--) {
            if (regionIs(s, i, token)) {
                return i;
            }
        }
        return -1;
    }

    private static char asciiLower(final char c) {
        return c >= 'A' && c <= 'Z' ? (char) (c + ('a' - 'A')) : c;
    }

    /** HTML-escapes the markup characters only (UTF-8 text such as © stays as it is). */
    private static String esc(final String value) {
        return HtmlUtils.htmlEscape(value == null ? "" : value, "UTF-8");
    }
}
