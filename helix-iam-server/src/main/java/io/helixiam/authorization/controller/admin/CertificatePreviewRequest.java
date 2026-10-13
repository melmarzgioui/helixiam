/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Task 24: a PEM certificate bundle (e.g. wallet trust anchors) the console wants to preview before saving. */
public record CertificatePreviewRequest(
        @NotBlank(message = "Paste or upload at least one PEM certificate.")
        @Size(max = 262_144, message = "The certificate bundle is too large.") String pem) {
}
