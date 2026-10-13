/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * The success shape of a decrypted OpenID4VP Authorization Response (§8.1): {@code vp_token} as a JSON object keyed
 * by DCQL credential query id, and the {@code state} the Verifier sent in the request, if any.
 * {@link VpResponseDecryptor} never returns this for a wallet error response (§8.5); that is a
 * {@link WalletVerificationException} instead.
 */
public record DecryptedResponse(JsonNode vpToken, String state) {
}
