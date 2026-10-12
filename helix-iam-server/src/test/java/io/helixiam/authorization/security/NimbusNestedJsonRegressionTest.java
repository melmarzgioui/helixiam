/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Regression for CVE-2025-53864 / GHSA-xwmg-2g98-w7v9: Nimbus before 10.0.2 (and before 9.37.4 on the 9.x line)
 * recursed without bound on deeply nested JSON in a JWT claim set, so an attacker-supplied JWT (for example a
 * private_key_jwt client assertion, or any token SAS parses) could kill the request thread with a StackOverflowError. The patched versions
 * refuse the input with a ParseException.
 */
class NimbusNestedJsonRegressionTest {

    private static final int DEPTH = 10_000;

    private static String nestedClaims() {
        return "{\"a\":" + "[".repeat(DEPTH) + "]".repeat(DEPTH) + "}";
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void claimsSetParseRefusesDeepNestingWithoutStackOverflow() {
        assertThatThrownBy(() -> JWTClaimsSet.parse(nestedClaims())).isInstanceOf(ParseException.class);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void signedJwtClaimsRefuseDeepNestingWithoutStackOverflow() {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String jwt = b64.encodeToString("{\"alg\":\"ES256\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(nestedClaims().getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(new byte[64]);
        assertThatThrownBy(() -> SignedJWT.parse(jwt).getJWTClaimsSet()).isInstanceOf(ParseException.class);
    }
}
