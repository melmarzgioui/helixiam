/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

/**
 * The outcome of a successful verification: only what the broker needs, never the raw presentation.
 *
 * <p>{@code credentialType} ties the presentation to its DCQL credential query: for {@code dc+sd-jwt} it is the type
 * under which the credential was accepted (its {@code vct} when that is accepted, otherwise the first accepted
 * {@code aka_vcts} entry), for {@code mso_mdoc} the Document's {@code docType}.
 */
public record VerifiedPresentation(String format,              // "dc+sd-jwt" | "mso_mdoc"
        String credentialType,                                  // accepted vct | docType
        java.util.Map<String, Object> claims,                   // normalised JSON-ish
        String issuerSubjectDn, String issuerSerialHex, String statusResult) {}
