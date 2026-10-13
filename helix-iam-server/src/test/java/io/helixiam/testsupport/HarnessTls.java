/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.testsupport;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The e2e harness CA: {@link #TLS} serves https on localhost / 127.0.0.1, and {@link #install()} makes the JVM's
 * default SSL context trust it in addition to the JVM's own CAs. Outbound fetches that use the default context (the
 * token endpoint's client JWKS, for instance, which must be https outside dev) can then reach a harness listener.
 * Installed by {@code AbstractE2eTest} before the application starts.
 */
public final class HarnessTls {

    public static final TestTls TLS = TestTls.create("e2e-harness");
    private static volatile boolean installed;

    private HarnessTls() {
    }

    public static synchronized void install() {
        if (installed) {
            return;
        }
        try {
            final TrustManagerFactory jvm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            jvm.init((KeyStore) null);
            final X509TrustManager jvmTrust = (X509TrustManager) jvm.getTrustManagers()[0];
            final KeyStore harness = KeyStore.getInstance(KeyStore.getDefaultType());
            harness.load(null, null);
            int i = 0;
            for (final X509Certificate ca : io.helixiam.authorization.messaging.email.TlsTrust.parse(TLS.caPem())) {
                harness.setCertificateEntry("harness-" + i++, ca);
            }
            final TrustManagerFactory own = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            own.init(harness);
            final X509TrustManager harnessTrust = (X509TrustManager) own.getTrustManagers()[0];
            final X509TrustManager both = new X509TrustManager() {
                @Override
                public void checkClientTrusted(final X509Certificate[] chain, final String authType)
                        throws CertificateException {
                    jvmTrust.checkClientTrusted(chain, authType);
                }

                @Override
                public void checkServerTrusted(final X509Certificate[] chain, final String authType)
                        throws CertificateException {
                    try {
                        jvmTrust.checkServerTrusted(chain, authType);
                    } catch (final CertificateException e) {
                        harnessTrust.checkServerTrusted(chain, authType);
                    }
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    final List<X509Certificate> all = new ArrayList<>(Arrays.asList(jvmTrust.getAcceptedIssuers()));
                    all.addAll(Arrays.asList(harnessTrust.getAcceptedIssuers()));
                    return all.toArray(new X509Certificate[0]);
                }
            };
            final SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[] {both}, null);
            SSLContext.setDefault(ctx);
            installed = true;
        } catch (final Exception e) {
            throw new IllegalStateException("Could not install the e2e harness trust", e);
        }
    }
}
