/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** SSRF: importing SAML metadata by URL never makes the server fetch an internal address. */
class SamlMetadataImportE2eTest extends AbstractE2eTest {

    @Test
    void internalAndPlainHttpUrls_areRefused_withoutNetworkDetails() {
        final E2eAdminSession admin = adminSession();
        for (final String url : new String[] {
                baseUrl() + "/actuator/health",                      // the server itself (http, loopback)
                "https://127.0.0.1:" + baseUrl().replaceAll(".*:", "") + "/x",
                "https://169.254.169.254/latest/meta-data/",         // cloud instance metadata
                "https://10.0.0.1/metadata",
                "http://example.com/metadata"}) { // plain http: metadata must come over https
            final E2eHttp.Response r = admin.post("/admin/realms/master/saml-clients/import-url", Map.of("url", url));
            assertThat(r.status()).as(url + " -> " + r).isEqualTo(400);
            assertThat(r.body()).as(url).doesNotContain("Connection refused").doesNotContain("timed out");
        }
    }
}
