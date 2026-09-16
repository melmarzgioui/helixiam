/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.fapi;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM B11 (FAPI / RFC 8705): the client certificate that bound the token is resolved either from a
 * real TLS handshake (the servlet {@code jakarta.servlet.request.X509Certificate} attribute) or — the
 * common KubeDNA deployment, where TLS terminates at the api-gateway / reverse proxy — from a configured
 * forwarded PEM header. Resolution is the seam; the binding decision lives in the token customizer.
 */
class ClientCertificateResolverTest {

    private static final String PEM = """
            -----BEGIN CERTIFICATE-----
            MIIDFzCCAf+gAwIBAgIUOTWYrQTDI0JxoEIgT80xIlVZ1NowDQYJKoZIhvcNAQEL
            BQAwGzEZMBcGA1UEAwwQZmFwaS10ZXN0LWNsaWVudDAeFw0yNjA2MjkxOTU4NDJa
            Fw0zNjA2MjYxOTU4NDJaMBsxGTAXBgNVBAMMEGZhcGktdGVzdC1jbGllbnQwggEi
            MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCt0AGZGXjTNCPtnRKN2Lo63VeR
            GU0WsRfS81mQiv3tYtr06pIYDfjaIBgCmF8Vnwte8UnDo3r57FwhdTg7JzmB3yFN
            rjtDEHMUO/jIrmA/89creb0WUVle2bo0uY4ukuFML+aYRtf8UtaXM58RxhjE3nGH
            0PNfak7+QDmrtCM0EG39eiVVtp0CRUwbEAj8qSG6Hr44DGZjwdKIfUNUZM3GCvGq
            9+mNEH5OVV4qB6Pv0zS2ULIUm6dV676BTLMzkh+64oUcDOVbvCZH/9wjRYkuVw10
            bsleSCFC/QPbtIAOV2VstlBRzUln2hwZaCuoTgQ500iYpxuSuwL4tSUA+AWPAgMB
            AAGjUzBRMB0GA1UdDgQWBBR2PYaCqHpWYDzBuEHk2Td5VV6lBDAfBgNVHSMEGDAW
            gBR2PYaCqHpWYDzBuEHk2Td5VV6lBDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
            DQEBCwUAA4IBAQBeiyHARYRo5LyuEdv0wE9ZGP7ITD+4sYwCPFf2xL5x2IVv9ohX
            d4gs3S8tC0rfS2yYmKo/OVkexZb/8z1zXQjqrLXwhZgPFHAF3hd7UrjHwPgUsH+u
            P033ZvCsffiwnG4aMFNhByhoZySByeAigirKF5mYO4eTTvRJ88q+nrwo0ZyEVFAW
            9SVZ7VbG8iE0OIlIaXYVDjhzodjmscOStoPYxdNZFT77DHrx+S2L2itZXCycOHwe
            4aS54ItNObKjZ0LDWw+LMs1ePpUN0TegDJnCZudtgxepK8aNyCoC0T0I4GmzPjQT
            0+Rde+5V/Ws9gB7ugA8Ft2+DDDix5NffZFbq
            -----END CERTIFICATE-----
            """;
    private static final String EXPECTED = "KLParsNx7STe-lpzzAZB3-y-bd2dLDGKpO_xs9FheyQ";

    private final ClientCertificateResolver resolver = new ClientCertificateResolver("X-Client-Cert");

    @Test
    void resolvesFromTheRealTlsHandshakeAttribute() throws Exception {
        final X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(PEM.getBytes(StandardCharsets.UTF_8)));
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute("jakarta.servlet.request.X509Certificate", new X509Certificate[]{cert});

        assertThat(resolver.resolve(request)).isPresent()
                .map(CertificateThumbprint::x5tS256).contains(EXPECTED);
    }

    @Test
    void resolvesFromTheConfiguredForwardedHeader() {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Client-Cert", java.net.URLEncoder.encode(PEM, StandardCharsets.UTF_8));

        assertThat(resolver.resolve(request)).isPresent()
                .map(CertificateThumbprint::x5tS256).contains(EXPECTED);
    }

    @Test
    void emptyWhenNoCertificatePresented() {
        assertThat(resolver.resolve(new MockHttpServletRequest())).isEmpty();
    }
}
