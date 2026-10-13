/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.wallet.status.StatusPolicy;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;

/**
 * Everything a {@link PresentationVerifier} checks a presentation against, fixed per transaction.
 *
 * <p>{@code acceptedVcts} is a set because national PIDs carry their own {@code vct} (e.g. {@code urn:eudi:pid:de:1},
 * spec notes §PID); a credential is accepted when its {@code vct} or one of its {@code aka_vcts} is in the set.
 * {@code allowLegacyVcSdJwtTyp} (default {@code false}) additionally accepts the pre-rename {@code vc+sd-jwt} JOSE
 * {@code typ}.
 */
public record VerificationContext(String clientId, String nonce, String responseUri, byte[] encryptionJwkThumbprint,
        java.time.Instant now, java.time.Duration clockSkew, TrustAnchors anchors, StatusPolicy statusPolicy,
        java.util.Set<String> acceptedVcts, String acceptedDoctype, boolean allowLegacyVcSdJwtTyp) {}
