package io.helixiam.authorization.security.fapi;

import jakarta.servlet.http.HttpServletRequest;

import java.security.cert.X509Certificate;
import java.util.Optional;

/**
 * Helix IAM B11 (FAPI / RFC 8705): resolves the client certificate that should bind an access token.
 * Two sources, in order:
 * <ol>
 *   <li>the real TLS handshake — the servlet container exposes the chain as the
 *       {@code jakarta.servlet.request.X509Certificate} request attribute (mTLS terminated at the JVM);</li>
 *   <li>a forwarded PEM header — the common KubeDNA topology where TLS terminates at the api-gateway /
 *       reverse proxy, which forwards the verified client cert (e.g. nginx {@code ssl_client_escaped_cert})
 *       in a configured header.</li>
 * </ol>
 * Returns empty when no certificate is presented, so a non-mTLS request simply yields no binding.
 */
public class ClientCertificateResolver {

    /** Servlet spec attribute populated by the container when a client cert is presented over mTLS. */
    private static final String X509_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    private final String forwardedHeader;

    public ClientCertificateResolver(final String forwardedHeader) {
        this.forwardedHeader = forwardedHeader;
    }

    public Optional<X509Certificate> resolve(final HttpServletRequest request) {
        if (request == null) {
            return Optional.empty();
        }
        final Object attr = request.getAttribute(X509_ATTRIBUTE);
        if (attr instanceof X509Certificate[] chain && chain.length > 0 && chain[0] != null) {
            return Optional.of(chain[0]);
        }
        if (forwardedHeader != null && !forwardedHeader.isBlank()) {
            return CertificateThumbprint.parsePem(request.getHeader(forwardedHeader));
        }
        return Optional.empty();
    }
}
