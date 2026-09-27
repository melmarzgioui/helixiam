/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import org.springframework.web.util.HtmlUtils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The shared layout every HTML email is sent in: a centred 560 px card on a warm background, the brand's logo (or
 * its name) on top, the template body, and a small footer. Built from tables with inline styles so it renders the
 * same in Outlook, Gmail, Apple Mail and on phones.
 *
 * <p>In a template body, a link marked {@code data-button} ({@code <a href="{{link}}" data-button>Sign in</a>})
 * becomes a solid button in the brand colour.
 */
public final class EmailLayout {

    private static final String FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif";
    private static final Pattern BUTTON = Pattern.compile("<a\\s+href=\"([^\"]*)\"\\s+data-button\\s*>(.*?)</a>",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    private EmailLayout() {
    }

    public static String wrap(final EmailBranding branding, final String subject, final String bodyHtml) {
        final EmailBranding b = branding == null ? EmailBranding.helixIam() : branding;
        final String name = HtmlUtils.htmlEscape(b.name());
        final String nameSpan = "<span style=\"font-family:" + FONT + ";font-size:18px;font-weight:700;color:#1f2a24;\">"
                + name + "</span>";
        final String header = b.logoUrl() != null
                ? "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\"><tr>"
                    + "<td style=\"padding-right:12px;\"><img src=\"" + HtmlUtils.htmlEscape(b.logoUrl()) + "\" alt=\"\" "
                    + "height=\"36\" style=\"display:block;height:36px;width:auto;max-width:200px;border:0;\"></td>"
                    + "<td>" + nameSpan + "</td></tr></table>"
                : nameSpan;
        return "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"UTF-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                + "<meta name=\"color-scheme\" content=\"light\"><title>" + HtmlUtils.htmlEscape(subject == null ? "" : subject)
                + "</title></head>\n<body style=\"margin:0;padding:0;background-color:#f6f1e9;\">"
                + "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" bgcolor=\"#f6f1e9\" "
                + "style=\"background-color:#f6f1e9;\"><tr><td align=\"center\" style=\"padding:32px 16px;\">"
                + "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" "
                + "style=\"max-width:560px;width:100%;\">"
                + "<tr><td style=\"padding:0 8px 20px 8px;\">" + header + "</td></tr>"
                + "<tr><td bgcolor=\"#ffffff\" style=\"background-color:#ffffff;border:1px solid #e6dfd3;border-radius:8px;"
                + "padding:32px 32px 28px 32px;font-family:" + FONT + ";font-size:15px;line-height:1.6;color:#1f2a24;\">"
                + buttons(bodyHtml == null ? "" : bodyHtml, b.color())
                + "</td></tr>"
                + "<tr><td style=\"padding:16px 8px 0 8px;font-family:" + FONT + ";font-size:12px;line-height:1.5;color:#7a7468;\">"
                + "Sent by " + name + ".</td></tr>"
                + "</table></td></tr></table></body></html>\n";
    }

    /** {@code <a href="…" data-button>Label</a>} → a table-based button with the brand colour (Outlook-safe). */
    private static String buttons(final String body, final String color) {
        final Matcher m = BUTTON.matcher(body);
        final StringBuilder out = new StringBuilder();
        while (m.find()) {
            final String button = "<table role=\"presentation\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" "
                    + "style=\"margin:8px 0;\"><tr><td bgcolor=\"" + color + "\" style=\"border-radius:6px;background-color:"
                    + color + ";\"><a href=\"" + m.group(1) + "\" target=\"_blank\" style=\"display:inline-block;"
                    + "padding:12px 24px;font-family:" + FONT + ";font-size:15px;font-weight:600;color:#ffffff;"
                    + "text-decoration:none;border-radius:6px;background-color:" + color + ";\">" + m.group(2) + "</a></td></tr></table>";
            m.appendReplacement(out, Matcher.quoteReplacement(button));
        }
        m.appendTail(out);
        return out.toString();
    }
}
