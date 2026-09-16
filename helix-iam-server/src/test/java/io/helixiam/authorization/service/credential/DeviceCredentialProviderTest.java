/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.credential;

import io.helixiam.authorization.service.device.DeviceCredentialService;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E4.1: the device factor as an auto-discovered {@link CredentialProvider} (type
 * "device"). The publisher packs the device assertion (deviceId + base64url challenge + signature)
 * as JSON; this decodes it and routes to {@link DeviceCredentialService#verifyAssertion}.
 */
class DeviceCredentialProviderTest {

    private final DeviceCredentialService service = mock(DeviceCredentialService.class);
    private final DeviceCredentialProvider provider = new DeviceCredentialProvider(service);

    @Test
    void typeIsDevice() {
        assertThat(provider.type()).isEqualTo("device");
    }

    @Test
    void decodesTheAssertionJsonAndRoutesToTheService() {
        final byte[] challenge = "chal".getBytes();
        final byte[] signature = new byte[]{1, 2, 3};
        final String b64 = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);
        final String sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
        final String input = "{\"deviceId\":\"device-1\",\"challenge\":\"" + b64 + "\",\"signature\":\"" + sigB64 + "\"}";

        when(service.verifyAssertion(eq("user-1"), eq("device-1"), eq(challenge), eq(signature))).thenReturn(true);

        assertThat(provider.verify("user-1", input)).isTrue();
    }

    @Test
    void returnsFalseOnMalformedInput() {
        assertThat(provider.verify("user-1", "not json")).isFalse();
    }
}
