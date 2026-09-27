/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.magiclink;

/** Delivers a magic sign-in link. The default implementation emails it through the realm's email provider. */
@FunctionalInterface
public interface MagicLinkSender {

    void send(MagicLinkMessage message);
}
