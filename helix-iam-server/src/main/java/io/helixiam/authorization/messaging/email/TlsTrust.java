/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * TLS trust for the email transports. Certificates are always verified: the JDK's trusted roots, plus the
 * certificates of an optional PEM bundle (a private relay's CA). There is no "trust all" mode. Host names are
 * verified by the caller (the JDK HTTP client does it by default; the SMTP driver turns on
 * {@code mail.smtp.ssl.checkserveridentity}).
 */
public final class TlsTrust {

    private static final int MAX_CACHED = 64;
    private static final Map<String, SSLContext> CACHE = new ConcurrentHashMap<>();

    private TlsTrust() {
    }

    /** The SSL context trusting the JDK roots plus {@code pemBundle} (null or blank = the JDK roots only). */
    public static SSLContext context(final String pemBundle) {
        if (pemBundle == null || pemBundle.isBlank()) {
            try {
                return SSLContext.getDefault();
            } catch (final GeneralSecurityException e) {
                throw new IllegalStateException("No default TLS context", e);
            }
        }
        final SSLContext cached = CACHE.get(pemBundle);
        if (cached != null) {
            return cached;
        }
        final SSLContext created = build(parse(pemBundle));
        if (CACHE.size() >= MAX_CACHED) {
            CACHE.clear();
        }
        CACHE.put(pemBundle, created);
        return created;
    }

    /**
     * The X.509 certificates of a PEM bundle.
     *
     * @throws IllegalArgumentException when it holds no certificate or cannot be read
     */
    public static List<X509Certificate> parse(final String pemBundle) {
        if (pemBundle == null || pemBundle.isBlank()) {
            throw new IllegalArgumentException("The CA bundle is empty");
        }
        try {
            final Collection<? extends Certificate> certs = CertificateFactory.getInstance("X.509")
                    .generateCertificates(new ByteArrayInputStream(pemBundle.trim().getBytes(StandardCharsets.US_ASCII)));
            final List<X509Certificate> out = new ArrayList<>();
            for (final Certificate c : certs) {
                if (c instanceof X509Certificate x) {
                    out.add(x);
                }
            }
            if (out.isEmpty()) {
                throw new IllegalArgumentException("The CA bundle holds no certificate");
            }
            return out;
        } catch (final CertificateException e) {
            throw new IllegalArgumentException("The CA bundle is not a PEM certificate list", e);
        }
    }

    private static SSLContext build(final List<X509Certificate> bundle) {
        try {
            final KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null, null);
            for (int i = 0; i < bundle.size(); i++) {
                store.setCertificateEntry("bundle-" + i, bundle.get(i));
            }
            final X509TrustManager custom = trustManager(store);
            final X509TrustManager system = trustManager(null);
            final SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[] {new EitherTrustManager(custom, system)}, null);
            return ctx;
        } catch (final Exception e) {
            throw new IllegalStateException("Could not build the TLS trust for the CA bundle", e);
        }
    }

    private static X509TrustManager trustManager(final KeyStore store) throws GeneralSecurityException {
        final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(store);
        for (final TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager x) {
                return x;
            }
        }
        throw new IllegalStateException("No X.509 trust manager");
    }

    /** Trusts a chain that either the bundle or the JDK roots validate (both do full path validation). */
    private record EitherTrustManager(X509TrustManager bundle, X509TrustManager system) implements X509TrustManager {

        @Override
        public void checkClientTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
            throw new CertificateException("Client certificates are not accepted here");
        }

        @Override
        public void checkServerTrusted(final X509Certificate[] chain, final String authType) throws CertificateException {
            try {
                bundle.checkServerTrusted(chain, authType);
            } catch (final CertificateException first) {
                try {
                    system.checkServerTrusted(chain, authType);
                } catch (final CertificateException second) {
                    first.addSuppressed(second);
                    throw first;
                }
            }
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            final List<X509Certificate> all = new ArrayList<>(List.of(bundle.getAcceptedIssuers()));
            all.addAll(List.of(system.getAcceptedIssuers()));
            return all.toArray(new X509Certificate[0]);
        }
    }
}
