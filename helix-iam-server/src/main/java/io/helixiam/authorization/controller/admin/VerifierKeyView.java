/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.service.key.SigningKeySummary;

/**
 * Task 24: one verifier access key as the admin API returns it — its reference and the leaf certificate's public
 * facts, never the private key.
 *
 * @param keyRef      what a wallet provider's {@code accessKeyRef} takes ({@code software:<realm>/<name>})
 * @param name        the name it was imported under
 * @param algorithm   {@code ES256}, {@code ES384} or {@code ES512}
 * @param createdAt   ISO-8601 instant of the import, or null when unknown
 * @param chainLength certificates in the stored (x5c) chain, root excluded
 * @param certificate the leaf (access) certificate
 */
public record VerifierKeyView(String keyRef, String name, String algorithm, String createdAt, int chainLength,
                              CertificateView certificate) {

    public static VerifierKeyView of(final SigningKeySummary key) {
        return new VerifierKeyView(key.keyRef(), key.name(), key.algorithm(),
                key.createdAt() == null ? null : key.createdAt().toString(), key.certificateChain().size(),
                CertificateView.of(key.certificateChain().get(0)));
    }
}
