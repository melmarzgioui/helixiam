/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.emailverification;

/** C3: an email-verification link to send to a user's address. */
public record EmailVerificationMessage(String realmId, String userId, String email, String link, long ttlHours) {
}
