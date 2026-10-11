/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

/** The outcome of a successful verification: only what the broker needs, never the raw presentation. */
public record VerifiedPresentation(String format,              // "dc+sd-jwt" | "mso_mdoc"
        java.util.Map<String, Object> claims,                   // normalised JSON-ish
        String issuerSubjectDn, String issuerSerialHex, String statusResult) {}
