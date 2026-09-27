/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import io.helixiam.authorization.messaging.EmailText;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * A fully rendered email, as every {@link EmailTransport} receives it.
 *
 * <ul>
 *   <li>{@code messageId}: stable for one logical email. A retry of the same email reuses it, so a transport that
 *       supports idempotency (or the SMTP {@code Message-ID} header) can recognise a duplicate. Create one with
 *       {@link #newMessageId()} when the email is first composed and keep it with the message.</li>
 *   <li>{@code from}: the sender. A transport may fill it from the provider's configured from-address when null;
 *       see {@link #withDefaultFrom}.</li>
 *   <li>{@code to}: one or more recipients; {@code replyTo} is optional.</li>
 *   <li>{@code html} and {@code text}: the HTML body (null for a plain-text email) and the plain-text part. The text
 *       part is never empty: for an HTML email without one it is derived from the HTML with every link kept
 *       ({@link EmailText#fromHtml}).</li>
 *   <li>{@code headers}: extra headers, limited to {@link #ALLOWED_HEADERS} (none are used today).</li>
 * </ul>
 */
public record EmailMessage(String messageId, EmailAddress from, List<EmailAddress> to, EmailAddress replyTo,
                           String subject, String html, String text, Map<String, String> headers) {

    /** The only extra headers a caller may set (non-transactional mail; none today). */
    public static final Set<String> ALLOWED_HEADERS = Set.of("list-unsubscribe", "list-unsubscribe-post");

    public EmailMessage {
        if (messageId == null || messageId.isBlank()) {
            throw new IllegalArgumentException("A message id is required");
        }
        if (to == null || to.isEmpty()) {
            throw new IllegalArgumentException("At least one recipient is required");
        }
        to = List.copyOf(to);
        subject = subject == null ? "" : subject.replaceAll("[\\r\\n]+", " ");
        html = html == null || html.isEmpty() ? null : html;
        if (text == null) {
            text = html == null ? "" : EmailText.fromHtml(html);
        }
        final Map<String, String> safe = new LinkedHashMap<>();
        if (headers != null) {
            headers.forEach((k, v) -> {
                if (k == null || !ALLOWED_HEADERS.contains(k.toLowerCase(Locale.ROOT))) {
                    throw new IllegalArgumentException("Header not allowed: " + k);
                }
                if (v == null || v.indexOf('\r') >= 0 || v.indexOf('\n') >= 0) {
                    throw new IllegalArgumentException("Header value not allowed for " + k);
                }
                safe.put(k, v);
            });
        }
        headers = Map.copyOf(safe);
    }

    /** A new, random message id for a newly composed email. */
    public static String newMessageId() {
        return UUID.randomUUID().toString();
    }

    /**
     * An email to one recipient, with a new message id. {@code html} is true when {@code body} is HTML; {@code text}
     * is the plain-text part (null derives it from the HTML; for a plain email the body is the text).
     */
    public static EmailMessage of(final EmailAddress from, final String to, final String subject, final String body,
                                  final boolean html, final String text) {
        return new EmailMessage(newMessageId(), from, List.of(EmailAddress.of(to)), null, subject,
                html ? body : null, html ? text : (body == null ? "" : body), Map.of());
    }

    /** The first recipient (every email HelixIAM sends has one). */
    public EmailAddress primaryRecipient() {
        return to.get(0);
    }

    /** True for an email with an HTML part. */
    public boolean isHtml() {
        return html != null;
    }

    /** This message, with {@code from} filled from the provider's from-address when it has none. */
    public EmailMessage withDefaultFrom(final String fromAddress, final String fromName) {
        if (from != null || fromAddress == null || fromAddress.isBlank()) {
            return this;
        }
        return new EmailMessage(messageId, EmailAddress.of(fromAddress, fromName), to, replyTo, subject, html, text,
                headers);
    }
}
