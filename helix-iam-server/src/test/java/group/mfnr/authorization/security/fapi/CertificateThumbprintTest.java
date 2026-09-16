package group.mfnr.authorization.security.fapi;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM B11 (FAPI, RFC 8705): the {@code x5t#S256} confirmation thumbprint is the base64url-encoded
 * (no padding) SHA-256 over the DER encoding of the client certificate. The expected value below was
 * computed independently with OpenSSL for a fixed self-signed cert
 * ({@code openssl x509 -outform DER | openssl dgst -sha256 -binary | base64url}), so this test is not
 * circular — it pins the exact RFC-8705 thumbprint, the PEM parsing, and the url-safe/no-pad encoding.
 */
class CertificateThumbprintTest {

    /** A fixed self-signed RSA test certificate (CN=fapi-test-client). */
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

    /** Computed independently with OpenSSL for the cert above. */
    private static final String EXPECTED = "KLParsNx7STe-lpzzAZB3-y-bd2dLDGKpO_xs9FheyQ";

    @Test
    void computesRfc8705ThumbprintFromCertificate() {
        final X509Certificate cert = CertificateThumbprint.parsePem(PEM).orElseThrow();
        assertThat(CertificateThumbprint.x5tS256(cert)).isEqualTo(EXPECTED);
    }

    @Test
    void parsesUrlEncodedPem() {
        // A reverse proxy commonly forwards the cert URL-encoded (nginx $ssl_client_escaped_cert) —
        // every special char is percent-encoded, so the decoder must round-trip it back to the PEM.
        final String urlEncoded = java.net.URLEncoder.encode(PEM, StandardCharsets.UTF_8);
        final Optional<X509Certificate> cert = CertificateThumbprint.parsePem(urlEncoded);
        assertThat(cert).isPresent();
        assertThat(CertificateThumbprint.x5tS256(cert.get())).isEqualTo(EXPECTED);
    }

    @Test
    void returnsEmptyForBlankOrGarbage() {
        assertThat(CertificateThumbprint.parsePem(null)).isEmpty();
        assertThat(CertificateThumbprint.parsePem("   ")).isEmpty();
        assertThat(CertificateThumbprint.parsePem("not a certificate")).isEmpty();
    }
}
