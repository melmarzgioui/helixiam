/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.magiclink;

/** A sign-in link to email to a user. */
public record MagicLinkMessage(String realmId, String userId, String email, String link, long ttlMinutes) {
}
