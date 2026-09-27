/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

/** Which brand an email for {@code realm} is sent under. */
@FunctionalInterface
public interface EmailBrandingSource {

    EmailBranding brandingFor(String realm);
}
