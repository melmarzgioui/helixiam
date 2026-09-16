package io.helixiam.authorization.flow.magiclink;

/**
 * Helix IAM: a passwordless magic-link email to deliver — the recipient + the clickable login link.
 * The transport is a {@link MagicLinkSender} (SMTP adapter in prod, logging in dev).
 */
public record MagicLinkMessage(String userId, String email, String link) {
}
