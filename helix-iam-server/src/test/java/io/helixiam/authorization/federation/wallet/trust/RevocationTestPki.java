/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust;

import com.sun.net.httpserver.HttpServer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;

/**
 * A test PKI of any depth with CRLs and OCSP responses signed by BouncyCastle, and a local stub server for them.
 */
final class RevocationTestPki {

    private static final AtomicLong SERIAL = new AtomicLong(System.nanoTime());

    private RevocationTestPki() {
    }

    /** An OCSP answer for one certificate. */
    enum OcspStatus { GOOD, REVOKED, UNKNOWN }

    /** A CA: its key and certificate (self-signed for a root). */
    static final class Ca {
        final KeyPair keys;
        final X509Certificate cert;

        private Ca(final KeyPair keys, final X509Certificate cert) {
            this.keys = keys;
            this.cert = cert;
        }

        static Ca root(final String name) {
            final KeyPair keys = ecKey();
            final X500Name subject = new X500Name("CN=" + name);
            return new Ca(keys, sign(builder(subject, subject, keys, keys, true), keys));
        }

        /** A CA below this one, with optional revocation pointers. */
        Ca issueCa(final String name, final String crlUrl, final String ocspUrl) {
            final KeyPair child = ecKey();
            final X509v3CertificateBuilder b = builder(name(cert), new X500Name("CN=" + name), child, keys, true);
            pointers(b, crlUrl, ocspUrl);
            return new Ca(child, sign(b, keys));
        }

        /** An end-entity issuer-signing certificate below this CA, with optional revocation pointers. */
        X509Certificate issueLeaf(final String name, final String crlUrl, final String ocspUrl) {
            final KeyPair child = ecKey();
            final X509v3CertificateBuilder b = builder(name(cert), new X500Name("CN=" + name), child, keys, false);
            pointers(b, crlUrl, ocspUrl);
            return sign(b, keys);
        }

        /** A DER CRL of this CA, valid from 5 minutes ago until {@code nextUpdate}, revoking {@code serials}. */
        byte[] crl(final Instant nextUpdate, final BigInteger... serials) {
            return crlSignedBy(keys, nextUpdate, serials);
        }

        /** As {@link #crl}, but signed with another key (same issuer name): never acceptable. */
        byte[] crlSignedBy(final KeyPair signer, final Instant nextUpdate, final BigInteger... serials) {
            return crlSignedBy(signer, Instant.now().minus(Duration.ofMinutes(5)), nextUpdate, serials);
        }

        /** A DER CRL of this CA with the given thisUpdate / nextUpdate. */
        byte[] crlAt(final Instant thisUpdate, final Instant nextUpdate, final BigInteger... serials) {
            return crlSignedBy(keys, thisUpdate, nextUpdate, serials);
        }

        byte[] crlSignedBy(final KeyPair signer, final Instant thisUpdate, final Instant nextUpdate,
                final BigInteger... serials) {
            final Instant now = Instant.now();
            final X509v2CRLBuilder b = new X509v2CRLBuilder(name(cert), Date.from(thisUpdate));
            if (nextUpdate != null) {
                b.setNextUpdate(Date.from(nextUpdate));
            }
            for (final BigInteger serial : serials) {
                b.addCRLEntry(serial, Date.from(now.minus(Duration.ofMinutes(1))), CRLReason.keyCompromise);
            }
            try {
                return b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate())).getEncoded();
            } catch (final Exception e) {
                throw new IllegalStateException(e);
            }
        }

        /**
         * A responder for the certificates this CA issued: answers every request entry with {@code statuses}
         * (default GOOD), signed by this CA, {@code nextUpdate} as given ({@code null}: none).
         */
        Function<byte[], byte[]> ocspResponder(final Map<BigInteger, OcspStatus> statuses, final Instant nextUpdate) {
            return ocspResponder(statuses, nextUpdate, keys);
        }

        Function<byte[], byte[]> ocspResponder(final Map<BigInteger, OcspStatus> statuses, final Instant nextUpdate,
                final KeyPair signer) {
            return request -> {
                try {
                    final OCSPReq req = new OCSPReq(request);
                    final BasicOCSPRespBuilder b = new BasicOCSPRespBuilder(
                            new RespID(name(cert)));
                    final Date thisUpdate = Date.from(Instant.now().minus(Duration.ofMinutes(1)));
                    for (final Req r : req.getRequestList()) {
                        final OcspStatus s = statuses.getOrDefault(r.getCertID().getSerialNumber(), OcspStatus.GOOD);
                        final CertificateStatus cs = switch (s) {
                            case GOOD -> CertificateStatus.GOOD;
                            case REVOKED -> new RevokedStatus(Date.from(Instant.now().minus(Duration.ofHours(1))),
                                    CRLReason.keyCompromise);
                            case UNKNOWN -> new UnknownStatus();
                        };
                        b.addResponse(r.getCertID(), cs, thisUpdate, nextUpdate == null ? null : Date.from(nextUpdate),
                                null);
                    }
                    return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, b.build(
                            new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate()),
                            new X509CertificateHolder[0], new Date())).getEncoded();
                } catch (final Exception e) {
                    throw new IllegalStateException(e);
                }
            };
        }

        TrustAnchors anchors(final TrustAnchors.RevocationMode mode) {
            return TrustAnchors.fromPem(pem(cert), null, mode);
        }
    }

    /** An unrelated key (wrong-signer tests). */
    static KeyPair ecKey() {
        try {
            final KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec("secp256r1"));
            return gen.generateKeyPair();
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String pem(final X509Certificate cert) {
        try {
            return "-----BEGIN CERTIFICATE-----\n"
                    + java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded())
                    + "\n-----END CERTIFICATE-----\n";
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** True when {@code response} is a parseable successful OCSP response (sanity check of the stub). */
    static boolean isOcsp(final byte[] response) {
        try {
            return new OCSPResp(response).getStatus() == OCSPRespBuilder.SUCCESSFUL;
        } catch (final Exception e) {
            return false;
        }
    }

    private static X500Name name(final X509Certificate cert) {
        return X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
    }

    private static X509v3CertificateBuilder builder(final X500Name issuer, final X500Name subject,
            final KeyPair subjectKeys, final KeyPair issuerKeys, final boolean ca) {
        final Instant now = Instant.now();
        try {
            final JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
            final X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(issuer,
                    BigInteger.valueOf(SERIAL.incrementAndGet()), Date.from(now.minus(Duration.ofDays(1))),
                    Date.from(now.plus(Duration.ofDays(365))), subject, subjectKeys.getPublic())
                    .addExtension(Extension.basicConstraints, true, ca ? new BasicConstraints(5)
                            : new BasicConstraints(false))
                    .addExtension(Extension.keyUsage, true, new KeyUsage(ca ? KeyUsage.keyCertSign | KeyUsage.cRLSign
                            : KeyUsage.digitalSignature))
                    .addExtension(Extension.subjectKeyIdentifier, false,
                            ext.createSubjectKeyIdentifier(subjectKeys.getPublic()));
            if (issuerKeys != subjectKeys) {
                b.addExtension(Extension.authorityKeyIdentifier, false,
                        ext.createAuthorityKeyIdentifier(issuerKeys.getPublic()));
            }
            return b;
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static void pointers(final X509v3CertificateBuilder b, final String crlUrl, final String ocspUrl) {
        try {
            if (crlUrl != null) {
                b.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[] {
                        new DistributionPoint(new DistributionPointName(new GeneralNames(
                                new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl))), null, null)}));
            }
            if (ocspUrl != null) {
                b.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(
                        AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl)));
            }
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static X509Certificate sign(final X509v3CertificateBuilder b, final KeyPair signer) {
        try {
            return new JcaX509CertificateConverter().getCertificate(
                    b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate())));
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A canned answer. */
    record Answer(int status, byte[] body, long delayMillis, String location) {
        static Answer ok(final byte[] body) {
            return new Answer(200, body, 0, null);
        }
    }

    /** A localhost HTTP server for CRL / OCSP stubs; every request is counted per path and its Host recorded. */
    static final class Stub implements AutoCloseable {
        private final HttpServer http;
        private final Map<String, Function<byte[], Answer>> routes = new ConcurrentHashMap<>();
        private final Map<String, AtomicLong> counts = new ConcurrentHashMap<>();
        final List<String> hosts = new CopyOnWriteArrayList<>();

        Stub() throws Exception {
            http = HttpServer.create(new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), 0), 0);
            http.createContext("/", exchange -> {
                try (exchange) {
                    final byte[] request = exchange.getRequestBody().readAllBytes();
                    final String path = exchange.getRequestURI().getPath();
                    counts.computeIfAbsent(path, p -> new AtomicLong()).incrementAndGet();
                    hosts.add(exchange.getRequestHeaders().getFirst("Host"));
                    final Function<byte[], Answer> route = routes.get(path);
                    final Answer answer = route == null ? new Answer(404, new byte[0], 0, null) : route.apply(request);
                    if (answer.delayMillis() > 0) {
                        Thread.sleep(answer.delayMillis());
                    }
                    if (answer.location() != null) {
                        exchange.getResponseHeaders().add("Location", answer.location());
                    }
                    exchange.sendResponseHeaders(answer.status(), answer.body().length == 0 ? -1
                            : answer.body().length);
                    if (answer.body().length > 0) {
                        try (OutputStream out = exchange.getResponseBody()) {
                            out.write(answer.body());
                        }
                    }
                } catch (final InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (final java.io.IOException e) {
                    // client gave up
                }
            });
            http.setExecutor(java.util.concurrent.Executors.newCachedThreadPool(r -> {
                final Thread t = new Thread(r, "revocation-stub");
                t.setDaemon(true);
                return t;
            }));
            http.start();
        }

        int port() {
            return http.getAddress().getPort();
        }

        String url(final String path) {
            return "http://127.0.0.1:" + port() + path;
        }

        void serve(final String path, final byte[] body) {
            routes.put(path, r -> Answer.ok(body));
        }

        void route(final String path, final Function<byte[], Answer> route) {
            routes.put(path, route);
        }

        void ocsp(final String path, final Function<byte[], byte[]> responder) {
            routes.put(path, r -> Answer.ok(responder.apply(r)));
        }

        long count(final String path) {
            final AtomicLong c = counts.get(path);
            return c == null ? 0 : c.get();
        }

        @Override
        public void close() {
            http.stop(0);
        }
    }
}
