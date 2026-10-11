/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

/**
 * A wallet verification failure. The message is a <em>safe detail</em>: it must never contain presentation content,
 * PID values, nonces or keys, because it reaches logs and audit events.
 */
public final class WalletVerificationException extends RuntimeException {
    private final WalletErrorCode code;
    public WalletVerificationException(WalletErrorCode code, String safeDetail) { super(safeDetail); this.code = code; }
    public WalletErrorCode code() { return code; }
}
