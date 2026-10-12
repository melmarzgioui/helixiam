/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

/**
 * A wallet verification failure. The message is a <em>safe detail</em>: it must never contain presentation content,
 * PID values, nonces or keys, because it reaches logs and audit events.
 *
 * <p>Task 22: {@link #format()} and {@link #issuerDn()} are optional audit context — the presentation format
 * ({@code dc+sd-jwt} / {@code mso_mdoc}) and the issuer's certificate subject DN (public certificate data, never a PID
 * value) — set by a caller that knows them ({@link #withFormat}, {@link #withIssuerDn}) without overwriting a value a
 * deeper layer already attached. Both are {@code null} when the failure happened before that context was available.
 */
public final class WalletVerificationException extends RuntimeException {
    private final WalletErrorCode code;
    private String format;
    private String issuerDn;

    public WalletVerificationException(WalletErrorCode code, String safeDetail) { super(safeDetail); this.code = code; }

    public WalletErrorCode code() { return code; }

    public String format() { return format; }

    public String issuerDn() { return issuerDn; }

    /** Attaches {@code format}, unless one is already set; returns {@code this}. */
    public WalletVerificationException withFormat(final String format) {
        if (this.format == null) {
            this.format = format;
        }
        return this;
    }

    /** Attaches {@code issuerDn}, unless one is already set; returns {@code this}. */
    public WalletVerificationException withIssuerDn(final String issuerDn) {
        if (this.issuerDn == null) {
            this.issuerDn = issuerDn;
        }
        return this;
    }
}
