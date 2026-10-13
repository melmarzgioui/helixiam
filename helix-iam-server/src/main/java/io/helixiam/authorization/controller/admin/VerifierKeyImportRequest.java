/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Task 24: the console's "Import access key" form — a verifier access-certificate key and its chain, imported into the
 * realm's software key store ({@link io.helixiam.authorization.service.key.RealmSigningKeys#importKey}). The private
 * key is write-only: no response ever carries it.
 *
 * @param name                the key name, unique in the realm (it becomes {@code software:<realm>/<name>})
 * @param privateKeyPem       the EC P-256/P-384/P-521 private key, PKCS#8 or SEC1 PEM, unencrypted
 * @param certificateChainPem the access certificate chain, leaf first (a trailing root is dropped)
 */
public record VerifierKeyImportRequest(
        @NotBlank(message = "A key name is required.")
        @Pattern(regexp = "[A-Za-z0-9._-]{1,64}",
                message = "Key name must be 1-64 characters of A-Z, a-z, 0-9, '.', '_' or '-'.") String name,
        @NotBlank(message = "A PEM private key is required.")
        @Size(max = 65_536, message = "The private key is too large.") String privateKeyPem,
        @NotBlank(message = "A PEM certificate chain is required.")
        @Size(max = 262_144, message = "The certificate chain is too large.") String certificateChainPem) {

    /** Never shows the private key. */
    @Override
    public String toString() {
        return "VerifierKeyImportRequest[name=" + name + "]";
    }
}
