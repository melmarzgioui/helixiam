/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.status;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.helixiam.authorization.federation.wallet.VerificationContext;
import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.sdjwt.SdJwtVcPresentationVerifier;
import io.helixiam.authorization.federation.wallet.status.StatusPolicy.OnUnavailable;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki.Leaf;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki.LeafSpec;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import io.helixiam.authorization.federation.wallet.trust.IssuerTrustValidator;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;
import io.helixiam.authorization.messaging.email.TlsTrust;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.testsupport.TestTls;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.zip.Deflater;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * {@link TokenStatusListClient} against a local HTTPS stub (the {@code CloudflareApiMock} pattern: a JDK
 * {@link HttpsServer} with a {@link TestTls} certificate, every request recorded). Status List Tokens are signed by a
 * {@link TestPki} leaf; the client trusts the PKI's root, the same anchors a credential would chain to.
 */
class TokenStatusListClientTest {

    private static final String JWT_TYPE = "application/statuslist+jwt";
    private static final String CWT_TYPE = "application/statuslist+cwt";
    private static final Duration MAX_CACHE = Duration.ofSeconds(900);

    private static TestTls tls;
    private static SSLContext clientTls;
    private static TestPki pki;
    private static Leaf signer;

    private StatusStub stub;
    private TestClock clock;
    private TrustAnchors anchors;
    private final List<String> audits = new CopyOnWriteArrayList<>();

    @BeforeAll
    static void pki() {
        tls = TestTls.create("status-list");
        clientTls = TlsTrust.context(tls.caPem());
        pki = TestPki.create("Status");
        signer = pki.issueLeaf(LeafSpec.defaults().withSubject("CN=Test Status Issuer,O=HelixIAM Test"));
    }

    @BeforeEach
    void setUp() {
        stub = StatusStub.https(tls);
        clock = new TestClock(Instant.now());
        anchors = pki.trustAnchors(TrustAnchors.RevocationMode.OFF);
    }

    @AfterEach
    void tearDown() {
        stub.close();
    }

    // ------------------------------------------------------------------------------------------- status values

    @Test
    void validIndexIsValid() {
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0, 1, 0, 0}));
        assertThat(client(failClosed()).evaluate(new StatusReference(0, uri("/lists/1")), anchors))
                .isEqualTo(StatusEvaluator.VALID);
        assertThat(client(failClosed()).evaluate(new StatusReference(2, uri("/lists/1")), anchors))
                .isEqualTo(StatusEvaluator.VALID);
    }

    @Test
    void revokedIndexIsCredentialRevoked() {
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0, 1, 0, 0}));
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(1, uri("/lists/1")), anchors),
                WalletErrorCode.CREDENTIAL_REVOKED);
    }

    @Test
    void suspendedIndexIsCredentialSuspended() {
        stub.serveJwt(jwt(uri("/lists/2"), 2, new int[] {0, 2}));
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(1, uri("/lists/2")), anchors),
                WalletErrorCode.CREDENTIAL_SUSPENDED);
    }

    @Test
    void twoBitListDecodesEveryValue() {
        // 0 VALID, 1 INVALID, 2 SUSPENDED, 3 application-specific (treated as revoked)
        stub.serveJwt(jwt(uri("/lists/2bit"), 2, new int[] {1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3}));
        final TokenStatusListClient client = client(failClosed());
        final String u = uri("/lists/2bit");
        assertThat(client.evaluate(new StatusReference(2, u), anchors)).isEqualTo(StatusEvaluator.VALID);
        assertThat(client.evaluate(new StatusReference(6, u), anchors)).isEqualTo(StatusEvaluator.VALID);
        assertCode(() -> client.evaluate(new StatusReference(0, u), anchors), WalletErrorCode.CREDENTIAL_REVOKED);
        assertCode(() -> client.evaluate(new StatusReference(1, u), anchors), WalletErrorCode.CREDENTIAL_SUSPENDED);
        assertCode(() -> client.evaluate(new StatusReference(3, u), anchors), WalletErrorCode.CREDENTIAL_REVOKED);
        assertCode(() -> client.evaluate(new StatusReference(9, u), anchors), WalletErrorCode.CREDENTIAL_SUSPENDED);
        assertCode(() -> client.evaluate(new StatusReference(11, u), anchors), WalletErrorCode.CREDENTIAL_REVOKED);
        assertThat(stub.requests()).hasSize(1); // all served from one cached list
    }

    @Test
    void eightBitUnknownValueIsRevoked() {
        stub.serveJwt(jwt(uri("/lists/8bit"), 8, new int[] {0, 0x0C, 0xFF}));
        final TokenStatusListClient client = client(failClosed());
        assertCode(() -> client.evaluate(new StatusReference(1, uri("/lists/8bit")), anchors),
                WalletErrorCode.CREDENTIAL_REVOKED);
        assertCode(() -> client.evaluate(new StatusReference(2, uri("/lists/8bit")), anchors),
                WalletErrorCode.CREDENTIAL_REVOKED);
    }

    @Test
    void indexOutOfBoundsIsRejectedEvenWhenFailOpen() {
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0, 0, 0, 0})); // one byte: indices 0..7
        assertCode(() -> client(failOpen()).evaluate(new StatusReference(8, uri("/lists/1")), anchors),
                WalletErrorCode.INVALID_RESPONSE);
        assertThat(audits).isEmpty();
    }

    @Test
    void revokedIsRevokedEvenWhenFailOpen() {
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0, 1}));
        assertCode(() -> client(failOpen()).evaluate(new StatusReference(1, uri("/lists/1")), anchors),
                WalletErrorCode.CREDENTIAL_REVOKED);
        assertThat(audits).isEmpty();
    }

    @Test
    void suspendedIsSuspendedEvenWhenFailOpen() {
        stub.serveJwt(jwt(uri("/lists/2"), 2, new int[] {2}));
        assertCode(() -> client(failOpen()).evaluate(new StatusReference(0, uri("/lists/2")), anchors),
                WalletErrorCode.CREDENTIAL_SUSPENDED);
        assertThat(audits).isEmpty();
    }

    @Test
    void sendsStatusListJwtAcceptHeader() {
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0}));
        client(failClosed()).evaluate(new StatusReference(0, uri("/lists/1")), anchors);
        assertThat(stub.requests()).singleElement().satisfies(r -> {
            assertThat(r.accept()).isEqualTo(JWT_TYPE);
            assertThat(r.path()).isEqualTo("/lists/1");
        });
    }

    // ------------------------------------------------------------------------------------------- token validation

    @Test
    void subjectNotEqualToUriIsStatusUnavailable() {
        stub.serveJwt(jwt(uri("/lists/other"), 1, new int[] {0}));
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void untrustedSignerIsStatusUnavailable() {
        final Leaf stranger = TestPki.create("Stranger").issueLeaf(LeafSpec.defaults());
        stub.serveJwt(jwt(stranger, uri("/lists/1"), 1, new int[] {0}, b -> b));
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void tamperedSignatureIsStatusUnavailable() {
        final String good = jwt(uri("/lists/1"), 1, new int[] {0});
        final String otherPayload = jwt(uri("/lists/1"), 1, new int[] {1}).split("\\.")[1];
        final String[] parts = good.split("\\.");
        stub.serveJwt(parts[0] + "." + otherPayload + "." + parts[2]);
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void missingX5cIsStatusUnavailable() {
        stub.serveJwt(jwt(signer, uri("/lists/1"), 1, new int[] {0}, b -> new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("statuslist+jwt"))));
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void wrongTypIsStatusUnavailable() {
        stub.serveJwt(jwt(signer, uri("/lists/1"), 1, new int[] {0}, b -> b.type(new JOSEObjectType("JWT"))));
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void expiredTokenIsStatusUnavailable() {
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0}, c -> c.expirationTime(Date.from(
                clock.instant().minus(Duration.ofMinutes(5))))));
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void tokenIssuedInTheFutureIsStatusUnavailable() {
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0}, c -> c.issueTime(Date.from(
                clock.instant().plus(Duration.ofMinutes(5))))));
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void bitsOutsideOneTwoFourEightIsStatusUnavailable() {
        stub.serveJwt(jwt(uri("/lists/1"), 3, new int[] {0}));
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void lstThatIsNotZlibIsStatusUnavailable() {
        stub.serveJwt(signJwt(signer, header(signer), baseClaims(uri("/lists/1"))
                .claim("status_list", Map.of("bits", 1, "lst", b64url("not zlib".getBytes()))).build()));
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void zipBombIsLimitExceeded() {
        final byte[] bomb = zlib(new byte[3 * 1024 * 1024]); // 3 MB of zeros, a few KB compressed
        assertThat(bomb.length).isLessThan(16 * 1024);
        stub.serveJwt(signJwt(signer, header(signer), baseClaims(uri("/lists/bomb"))
                .claim("status_list", Map.of("bits", 1, "lst", b64url(bomb))).build()));
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(0, uri("/lists/bomb")), anchors),
                WalletErrorCode.LIMIT_EXCEEDED);
    }

    @Test
    @Timeout(value = 5, unit = TimeUnit.SECONDS)
    void hugeZipBombIsLimitExceededQuickly() {
        stub.serveJwt(signJwt(signer, header(signer), baseClaims(uri("/lists/bomb")).claim("status_list",
                Map.of("bits", 1, "lst", b64url(StatusListTokenTest.zlibOfZeros(256L * 1024 * 1024)))).build()));
        assertCode(() -> client(failOpen()).evaluate(new StatusReference(0, uri("/lists/bomb")), anchors),
                WalletErrorCode.LIMIT_EXCEEDED);
        assertThat(audits).isEmpty();
    }

    @Test
    void listOfExactlyTwoMegabytesIsAccepted() {
        final byte[] list = new byte[2 * 1024 * 1024];
        list[list.length - 1] = 1; // the very last index (8 * 2 MB - 8) is revoked
        stub.serveJwt(signJwt(signer, header(signer), baseClaims(uri("/lists/big"))
                .claim("status_list", Map.of("bits", 1, "lst", b64url(zlib(list)))).build()));
        final TokenStatusListClient client = client(failClosed());
        assertThat(client.evaluate(new StatusReference(0, uri("/lists/big")), anchors))
                .isEqualTo(StatusEvaluator.VALID);
        assertCode(() -> client.evaluate(new StatusReference(8 * (list.length - 1), uri("/lists/big")), anchors),
                WalletErrorCode.CREDENTIAL_REVOKED);
    }

    @Test
    void bodyOverOneMegabyteIsLimitExceeded() {
        stub.respond(r -> StubResponse.ok(JWT_TYPE, new byte[1024 * 1024 + 1]));
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.LIMIT_EXCEEDED);
    }

    @Test
    void httpErrorIsStatusUnavailable() {
        stub.respond(r -> new StubResponse(503, null, new byte[0], 0, null));
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    // ------------------------------------------------------------------------------------------- SSRF / transport

    @Test
    void httpUriIsRefusedWithoutConnecting() {
        try (StatusStub plain = StatusStub.http()) {
            plain.serveJwt(jwt("http://localhost:" + plain.port() + "/lists/1", 1, new int[] {0}));
            final OutboundUrlGuard guard = new OutboundUrlGuard(false, "localhost:" + plain.port());
            final TokenStatusListClient client = client(failClosed(), guard);
            assertCode(() -> client.evaluate(new StatusReference(0, "http://localhost:" + plain.port() + "/lists/1"),
                    anchors), WalletErrorCode.STATUS_UNAVAILABLE);
            assertThat(plain.requests()).isEmpty();
        }
    }

    @Test
    void nonHttpSchemesAreRefused() {
        for (final String u : List.of("ftp://localhost/lists/1", "file:///etc/passwd", "lists/1", "not a uri")) {
            assertCode(() -> client(failClosed()).evaluate(new StatusReference(0, u), anchors),
                    WalletErrorCode.STATUS_UNAVAILABLE);
        }
        assertThat(stub.requests()).isEmpty();
    }

    @Test
    void statusListUri_privateAddress_isRefusedWithoutConnecting() {
        stub.serveJwt(jwt("https://127.0.0.1:" + stub.port() + "/lists/1", 1, new int[] {0}));
        final TokenStatusListClient client = client(failClosed());
        assertCode(() -> client.evaluate(new StatusReference(0, "https://127.0.0.1:" + stub.port() + "/lists/1"),
                anchors), WalletErrorCode.STATUS_UNAVAILABLE);
        assertCode(() -> client.evaluate(new StatusReference(0, "https://169.254.169.254/latest/meta-data"),
                anchors), WalletErrorCode.STATUS_UNAVAILABLE);
        assertCode(() -> client.evaluate(new StatusReference(0, "https://[::1]:" + stub.port() + "/lists/1"),
                anchors), WalletErrorCode.STATUS_UNAVAILABLE);
        assertThat(stub.requests()).isEmpty();
    }

    @Test
    void hostNotInAllowedHostsIsRefusedWithoutConnecting() {
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0}));
        final TokenStatusListClient client = client(policy(OnUnavailable.FAIL_CLOSED, List.of("status.example")));
        assertCode(() -> client.evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
        assertThat(stub.requests()).isEmpty();
    }

    @Test
    void hostInAllowedHostsIsFetchedCaseInsensitively() {
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0}));
        final TokenStatusListClient client = client(policy(OnUnavailable.FAIL_CLOSED, List.of("LocalHost")));
        assertThat(client.evaluate(new StatusReference(0, uri("/lists/1")), anchors))
                .isEqualTo(StatusEvaluator.VALID);
    }

    @Test
    void redirectToAPrivateAddressIsNotFollowed() {
        stub.respond(r -> new StubResponse(302, null, new byte[0], 0,
                "https://127.0.0.1:" + stub.port() + "/internal"));
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
        assertThat(stub.requests()).extracting(Request::path).containsExactly("/lists/1");
    }

    @Test
    void redirectToHttpIsNotFollowed() {
        stub.respond(r -> new StubResponse(302, null, new byte[0], 0,
                "http://localhost:" + stub.port() + "/plain"));
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
        assertThat(stub.requests()).extracting(Request::path).containsExactly("/lists/1");
    }

    @Test
    void redirectOnTheSameHostIsFollowed() {
        final String token = jwt(uri("/lists/1"), 1, new int[] {0, 1});
        stub.respond(r -> r.path().equals("/lists/1")
                ? new StubResponse(302, null, new byte[0], 0, "/cdn/lists/1")
                : StubResponse.ok(JWT_TYPE, token.getBytes(StandardCharsets.US_ASCII)));
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(1, uri("/lists/1")), anchors),
                WalletErrorCode.CREDENTIAL_REVOKED);
        assertThat(stub.requests()).extracting(Request::path).containsExactly("/lists/1", "/cdn/lists/1");
    }

    @Test
    void tooManyRedirectsIsStatusUnavailable() {
        stub.respond(r -> new StubResponse(302, null, new byte[0], 0, r.path() + "x"));
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
        assertThat(stub.requests()).hasSize(4); // the original + 3 redirects
    }

    @Test
    void unreachableIsStatusUnavailableWhenFailClosed() {
        final String u = "https://localhost:" + freePort() + "/lists/1";
        assertCode(() -> client(failClosed(), guardFor(u)).evaluate(new StatusReference(0, u), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
        assertThat(audits).isEmpty();
    }

    @Test
    void unreachableIsValidWithAnAuditEntryWhenFailOpen() {
        final String u = "https://localhost:" + freePort() + "/lists/1";
        assertThat(client(failOpen(), guardFor(u)).evaluate(new StatusReference(0, u), anchors))
                .isEqualTo(StatusEvaluator.VALID);
        assertThat(audits).containsExactly("localhost|STATUS_UNAVAILABLE");
    }

    @Test
    void refusedUriFailsClosedEvenWhenFailOpen() {
        assertCode(() -> client(failOpen()).evaluate(new StatusReference(0, "https://169.254.169.254/x"), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
        assertThat(audits).isEmpty();
    }

    @Test
    void zipBombFailsClosedEvenWhenFailOpen() {
        stub.serveJwt(signJwt(signer, header(signer), baseClaims(uri("/lists/bomb"))
                .claim("status_list", Map.of("bits", 1, "lst", b64url(zlib(new byte[3 * 1024 * 1024])))).build()));
        assertCode(() -> client(failOpen()).evaluate(new StatusReference(0, uri("/lists/bomb")), anchors),
                WalletErrorCode.LIMIT_EXCEEDED);
        assertThat(audits).isEmpty();
    }

    /** What a failure class must do under FAIL_OPEN_WITH_AUDIT (under FAIL_CLOSED all are refused). */
    enum Outcome { CLOSED_UNAVAILABLE, CLOSED_LIMIT, OPEN }

    /** The reference to evaluate, the guard (null: the default localhost guard), allowedHosts and the form. */
    record Scenario(String uri, OutboundUrlGuard guard, List<String> allowedHosts, boolean cwt) {
        static Scenario of(final String uri) {
            return new Scenario(uri, null, List.of(), false);
        }
    }

    /**
     * Every failure class (fix round 1 ruling). Policy refusals and integrity failures, and every other non-transient
     * failure, fail closed under both policies; only transient availability failures (connect/read error, timeout,
     * 5xx, DNS resolution failure) may fail open.
     */
    enum Failure {
        // ---- policy refusals
        HTTP_URI(Outcome.CLOSED_UNAVAILABLE, t -> Scenario.of("http://localhost:" + t.stub.port() + "/lists/1")),
        PRIVATE_ADDRESS(Outcome.CLOSED_UNAVAILABLE,
                t -> Scenario.of("https://127.0.0.1:" + t.stub.port() + "/lists/1")),
        METADATA_ADDRESS(Outcome.CLOSED_UNAVAILABLE, t -> Scenario.of("https://169.254.169.254/latest/meta-data")),
        NOT_IN_ALLOWED_HOSTS(Outcome.CLOSED_UNAVAILABLE, t -> {
            t.stub.serveJwt(t.jwt(t.uri("/lists/1"), 1, new int[] {0}));
            return new Scenario(t.uri("/lists/1"), null, List.of("status.example"), false);
        }),
        REDIRECT_TO_PRIVATE(Outcome.CLOSED_UNAVAILABLE, t -> {
            t.stub.respond(r -> new StubResponse(302, null, new byte[0], 0,
                    "https://127.0.0.1:" + t.stub.port() + "/internal"));
            return Scenario.of(t.uri("/lists/1"));
        }),
        REDIRECT_TO_HTTP(Outcome.CLOSED_UNAVAILABLE, t -> {
            t.stub.respond(r -> new StubResponse(302, null, new byte[0], 0,
                    "http://localhost:" + t.stub.port() + "/plain"));
            return Scenario.of(t.uri("/lists/1"));
        }),
        // ---- integrity of the fetched list
        BAD_SIGNATURE(Outcome.CLOSED_UNAVAILABLE, t -> {
            final String good = t.jwt(t.uri("/lists/1"), 1, new int[] {0});
            final String[] parts = good.split("\\.");
            t.stub.serveJwt(parts[0] + "." + t.jwt(t.uri("/lists/1"), 1, new int[] {1}).split("\\.")[1] + "."
                    + parts[2]);
            return Scenario.of(t.uri("/lists/1"));
        }),
        UNTRUSTED_SIGNER(Outcome.CLOSED_UNAVAILABLE, t -> {
            t.stub.serveJwt(t.jwt(TestPki.create("Stranger").issueLeaf(LeafSpec.defaults()), t.uri("/lists/1"), 1,
                    new int[] {0}, b -> b));
            return Scenario.of(t.uri("/lists/1"));
        }),
        MISSING_X5C(Outcome.CLOSED_UNAVAILABLE, t -> {
            t.stub.serveJwt(t.jwt(signer, t.uri("/lists/1"), 1, new int[] {0},
                    b -> new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("statuslist+jwt"))));
            return Scenario.of(t.uri("/lists/1"));
        }),
        WRONG_TYP(Outcome.CLOSED_UNAVAILABLE, t -> {
            t.stub.serveJwt(t.jwt(signer, t.uri("/lists/1"), 1, new int[] {0},
                    b -> b.type(new JOSEObjectType("JWT"))));
            return Scenario.of(t.uri("/lists/1"));
        }),
        DISALLOWED_ALG(Outcome.CLOSED_UNAVAILABLE, t -> {
            final String[] parts = t.jwt(t.uri("/lists/1"), 1, new int[] {0}).split("\\.");
            final String header = b64url(("{\"alg\":\"HS256\",\"typ\":\"statuslist+jwt\"}")
                    .getBytes(StandardCharsets.UTF_8));
            t.stub.serveJwt(header + "." + parts[1] + "." + parts[2]);
            return Scenario.of(t.uri("/lists/1"));
        }),
        SUB_MISMATCH(Outcome.CLOSED_UNAVAILABLE, t -> {
            t.stub.serveJwt(t.jwt(t.uri("/lists/other"), 1, new int[] {0}));
            return Scenario.of(t.uri("/lists/1"));
        }),
        CWT_BAD_SIGNATURE(Outcome.CLOSED_UNAVAILABLE, t -> {
            t.stub.serveCwt(t.cwt(signer, t.uri("/cwt/1"), 1, new int[] {0}, Map.of("tamper", true)));
            return new Scenario(t.uri("/cwt/1"), null, List.of(), true);
        }),
        CWT_SUB_MISMATCH(Outcome.CLOSED_UNAVAILABLE, t -> {
            t.stub.serveCwt(t.cwt(signer, t.uri("/cwt/other"), 1, new int[] {0}, Map.of()));
            return new Scenario(t.uri("/cwt/1"), null, List.of(), true);
        }),
        // ---- other non-transient failures
        EXPIRED_TOKEN(Outcome.CLOSED_UNAVAILABLE, t -> {
            t.stub.serveJwt(t.jwt(t.uri("/lists/1"), 1, new int[] {0}, c -> c.expirationTime(Date.from(
                    t.clock.instant().minus(Duration.ofMinutes(5))))));
            return Scenario.of(t.uri("/lists/1"));
        }),
        MALFORMED_LIST(Outcome.CLOSED_UNAVAILABLE, t -> {
            t.stub.serveJwt(signJwt(signer, header(signer), t.baseClaims(t.uri("/lists/1"))
                    .claim("status_list", Map.of("bits", 1, "lst", b64url("not zlib".getBytes()))).build()));
            return Scenario.of(t.uri("/lists/1"));
        }),
        NOT_FOUND(Outcome.CLOSED_UNAVAILABLE, t -> {
            t.stub.respond(r -> new StubResponse(404, null, new byte[0], 0, null));
            return Scenario.of(t.uri("/lists/1"));
        }),
        TOO_MANY_REDIRECTS(Outcome.CLOSED_UNAVAILABLE, t -> {
            t.stub.respond(r -> new StubResponse(302, null, new byte[0], 0, r.path() + "x"));
            return Scenario.of(t.uri("/lists/1"));
        }),
        ZIP_BOMB(Outcome.CLOSED_LIMIT, t -> {
            t.stub.serveJwt(signJwt(signer, header(signer), t.baseClaims(t.uri("/lists/1"))
                    .claim("status_list", Map.of("bits", 1, "lst", b64url(zlib(new byte[3 * 1024 * 1024]))))
                    .build()));
            return Scenario.of(t.uri("/lists/1"));
        }),
        BODY_TOO_LARGE(Outcome.CLOSED_LIMIT, t -> {
            t.stub.respond(r -> StubResponse.ok(JWT_TYPE, new byte[1024 * 1024 + 1]));
            return Scenario.of(t.uri("/lists/1"));
        }),
        // ---- transient availability failures
        CONNECTION_REFUSED(Outcome.OPEN, t -> {
            final String u = "https://localhost:" + freePort() + "/lists/1";
            return new Scenario(u, guardFor(u), List.of(), false);
        }),
        SERVER_ERROR(Outcome.OPEN, t -> {
            t.stub.respond(r -> new StubResponse(503, null, new byte[0], 0, null));
            return Scenario.of(t.uri("/lists/1"));
        }),
        DNS_FAILURE(Outcome.OPEN, t -> Scenario.of("https://status-list.invalid/lists/1")),
        READ_TIMEOUT(Outcome.OPEN, t -> {
            t.stub.respond(r -> new StubResponse(200, JWT_TYPE, new byte[64], -6_000, null));
            return Scenario.of(t.uri("/lists/1"));
        });

        final Outcome failOpenOutcome;
        final Function<TokenStatusListClientTest, Scenario> arrange;

        Failure(final Outcome failOpenOutcome, final Function<TokenStatusListClientTest, Scenario> arrange) {
            this.failOpenOutcome = failOpenOutcome;
            this.arrange = arrange;
        }
    }

    @ParameterizedTest
    @EnumSource(Failure.class)
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    void everyFailureClassFollowsTheRulingUnderBothPolicies(final Failure failure) {
        final Scenario scenario = failure.arrange.apply(this);
        final WalletErrorCode closedCode = failure.failOpenOutcome == Outcome.CLOSED_LIMIT
                ? WalletErrorCode.LIMIT_EXCEEDED : WalletErrorCode.STATUS_UNAVAILABLE;

        assertCode(() -> evaluator(scenario, OnUnavailable.FAIL_CLOSED).evaluate(
                new StatusReference(0, scenario.uri()), anchors, sameIssuer()), closedCode);
        assertThat(audits).isEmpty();

        final StatusEvaluator failOpen = evaluator(scenario, OnUnavailable.FAIL_OPEN_WITH_AUDIT);
        if (failure.failOpenOutcome == Outcome.OPEN) {
            assertThat(failOpen.evaluate(new StatusReference(0, scenario.uri()), anchors, sameIssuer()))
                    .isEqualTo(StatusEvaluator.VALID);
            assertThat(audits).singleElement().asString().endsWith("|STATUS_UNAVAILABLE");
        } else {
            assertCode(() -> failOpen.evaluate(new StatusReference(0, scenario.uri()), anchors, sameIssuer()),
                    closedCode);
            assertThat(audits).isEmpty();
        }
    }

    private StatusEvaluator evaluator(final Scenario scenario, final OnUnavailable onUnavailable) {
        final StatusPolicy policy = policy(onUnavailable, scenario.allowedHosts());
        final TokenStatusListClient client = scenario.guard() == null ? client(policy)
                : client(policy, scenario.guard());
        return scenario.cwt() ? client.cwtEvaluator() : client;
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    void connectTimeoutIsThreeSeconds() throws Exception {
        final TokenStatusListClient client = client(failClosed());
        assertThat(client.connectTimeout()).isEqualTo(Duration.ofSeconds(3));
        // A loopback listener whose accept queue is full and never drained: the kernel drops further SYNs, so a connect
        // hangs until the 3 s connect timeout, well before the 5 s deadline. (No routing assumption: an "unroutable"
        // address such as 10.255.255.1 answers at once on some networks.)
        final OutboundUrlGuard permissive = OutboundUrlGuard.permissive();
        try (BlackHole hole = BlackHole.open()) {
            final long start = System.nanoTime();
            assertCode(() -> client(failClosed(), permissive).evaluate(
                    new StatusReference(0, "https://127.0.0.1:" + hole.port() + "/lists/1"), anchors),
                    WalletErrorCode.STATUS_UNAVAILABLE);
            final Duration took = Duration.ofNanos(System.nanoTime() - start);
            assertThat(took).isGreaterThanOrEqualTo(Duration.ofMillis(2_900)).isLessThan(Duration.ofMillis(4_500));
        }
    }

    /** A loopback port that accepts no more connections: its backlog is filled and never accepted. */
    private record BlackHole(ServerSocket server, List<java.net.Socket> fillers) implements AutoCloseable {

        static BlackHole open() throws IOException {
            final ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
            final List<java.net.Socket> fillers = new ArrayList<>();
            final InetSocketAddress address = new InetSocketAddress(InetAddress.getLoopbackAddress(),
                    server.getLocalPort());
            for (int i = 0; i < 256; i++) {
                final java.net.Socket socket = new java.net.Socket();
                try {
                    socket.connect(address, 1_000); // generous: a loaded host still fills the queue
                    fillers.add(socket);
                } catch (final java.net.SocketTimeoutException full) {
                    socket.close();
                    return new BlackHole(server, fillers);
                }
            }
            throw new IllegalStateException("the loopback accept queue never filled up");
        }

        int port() {
            return server.getLocalPort();
        }

        @Override
        public void close() throws IOException {
            for (final java.net.Socket socket : fillers) {
                socket.close();
            }
            server.close();
        }
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void slowDnsCountsAgainstTheFetchDeadline() {
        // The guard's own resolution runs inside the 5 s deadline: a resolver that never answers in time cannot hold a
        // wallet login for longer than the read timeout.
        final OutboundUrlGuard slow = new OutboundUrlGuard(false, List.of("slow-dns.test:" + stub.port()), host -> {
            try {
                Thread.sleep(15_000);
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            throw new java.net.UnknownHostException(host);
        });
        final long start = System.nanoTime();
        assertCode(() -> client(failClosed(), slow).evaluate(
                new StatusReference(0, "https://slow-dns.test:" + stub.port() + "/lists/1"), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(5_900));
        assertThat(stub.requests()).isEmpty();
    }

    @Test
    void theFetchConnectsToTheAddressTheGuardValidated() throws Exception {
        // DNS rebinding: the first answer is the (allowlisted) stub address, every later one the metadata address. The
        // list is fetched (TLS verified against the original name, not the address), and the name is resolved once.
        final TestTls named = TestTls.createFor("status-rebind", "status.rebind.test");
        try (StatusStub rebind = StatusStub.https(named)) {
            final String u = "https://status.rebind.test:" + rebind.port() + "/lists/1";
            rebind.serveJwt(jwt(u, 1, new int[] {0}));
            final java.util.concurrent.atomic.AtomicInteger lookups = new java.util.concurrent.atomic.AtomicInteger();
            final OutboundUrlGuard guard = new OutboundUrlGuard(false, List.of("status.rebind.test:" + rebind.port()),
                    host -> {
                        final byte[] ip = lookups.getAndIncrement() == 0 ? new byte[] {127, 0, 0, 1}
                                : new byte[] {(byte) 169, (byte) 254, (byte) 169, (byte) 254};
                        return new InetAddress[] {InetAddress.getByAddress(host, ip)};
                    });
            final TokenStatusListClient client = new TokenStatusListClient(failClosed(), new IssuerTrustValidator(guard),
                    guard, TlsTrust.context(named.caPem()), clock, (host, code, detail) -> audits.add(host));

            assertThat(client.evaluate(new StatusReference(0, u), anchors)).isEqualTo(StatusEvaluator.VALID);
            assertThat(lookups).hasValue(1);
            assertThat(rebind.requests()).hasSize(1);
        }
    }

    @Test
    void theTlsCertificateMustMatchTheOriginalHostName() {
        // pinned to 127.0.0.1, but the certificate (localhost / 127.0.0.1) does not name "other.test"
        final OutboundUrlGuard guard = new OutboundUrlGuard(false, List.of("other.test:" + stub.port()),
                host -> new InetAddress[] {InetAddress.getByAddress(host, new byte[] {127, 0, 0, 1})});
        final String u = "https://other.test:" + stub.port() + "/lists/1";
        stub.serveJwt(jwt(u, 1, new int[] {0}));
        assertCode(() -> client(failClosed(), guard).evaluate(new StatusReference(0, u), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
        assertThat(stub.requests()).isEmpty();
    }

    @Test
    void aTlsHostNameFailureFailsClosedEvenWhenFailOpen() {
        final OutboundUrlGuard guard = new OutboundUrlGuard(false, List.of("other.test:" + stub.port()),
                host -> new InetAddress[] {InetAddress.getByAddress(host, new byte[] {127, 0, 0, 1})});
        final String u = "https://other.test:" + stub.port() + "/lists/1";
        stub.serveJwt(jwt(u, 1, new int[] {0}));
        assertCode(() -> client(failOpen(), guard).evaluate(new StatusReference(0, u), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
        assertThat(audits).isEmpty();
    }

    @Test
    void anUntrustedTlsCertificateFailsClosedEvenWhenFailOpen() {
        final TestTls stranger = TestTls.create("status-stranger");
        try (StatusStub other = StatusStub.https(stranger)) {
            final String u = "https://localhost:" + other.port() + "/lists/1";
            other.serveJwt(jwt(u, 1, new int[] {0}));
            assertCode(() -> client(failOpen(), guardFor(u)).evaluate(new StatusReference(0, u), anchors),
                    WalletErrorCode.STATUS_UNAVAILABLE);
            assertThat(audits).isEmpty();
        }
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void aMalformedHttpAnswerFailsClosedEvenWhenFailOpen() throws Exception {
        try (javax.net.ssl.SSLServerSocket raw = (javax.net.ssl.SSLServerSocket) tls.serverContext()
                .getServerSocketFactory().createServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))) {
            final Thread t = new Thread(() -> {
                while (!raw.isClosed()) {
                    try (java.net.Socket s = raw.accept()) {
                        final InputStream in = s.getInputStream();
                        int st = 0;
                        int c;
                        while (st < 4 && (c = in.read()) >= 0) {
                            st = (c == '\r' && (st == 0 || st == 2)) || (c == '\n' && (st == 1 || st == 3)) ? st + 1
                                    : c == '\r' ? 1 : 0;
                        }
                        s.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 9\r\n\r\nhi"
                                .getBytes(StandardCharsets.US_ASCII));
                        s.getOutputStream().flush();
                    } catch (final IOException e) {
                        // next
                    }
                }
            }, "malformed-status");
            t.setDaemon(true);
            t.start();
            final String u = "https://localhost:" + raw.getLocalPort() + "/lists/1";
            assertCode(() -> client(failOpen(), guardFor(u)).evaluate(new StatusReference(0, u), anchors),
                    WalletErrorCode.STATUS_UNAVAILABLE);
            assertThat(audits).isEmpty();
        }
    }

    @Test
    void aConnectFailureIsStillTransient() {
        final String u = "https://localhost:" + freePort() + "/lists/1";
        assertThat(client(failOpen(), guardFor(u)).evaluate(new StatusReference(0, u), anchors))
                .isEqualTo(StatusEvaluator.VALID);
        assertThat(audits).containsExactly("localhost|STATUS_UNAVAILABLE");
    }

    @Test
    void anUnresolvableHostIsStillTransient() {
        final OutboundUrlGuard nx = new OutboundUrlGuard(false, List.of(), host -> {
            throw new java.net.UnknownHostException(host);
        });
        final String u = "https://nx.status.test/lists/1";
        assertThat(client(failOpen(), nx).evaluate(new StatusReference(0, u), anchors))
                .isEqualTo(StatusEvaluator.VALID);
        assertThat(audits).containsExactly("nx.status.test|STATUS_UNAVAILABLE");
    }

    @Test
    void maxCacheAbove900SecondsIsClampedTo900() {
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0}, c -> c.claim("ttl", 86_400)));
        final TokenStatusListClient client = client(new StatusPolicy(true, OnUnavailable.FAIL_CLOSED,
                Duration.ofDays(1), List.of()));
        client.evaluate(new StatusReference(0, uri("/lists/1")), anchors);
        clock.advance(Duration.ofSeconds(899));
        client.evaluate(new StatusReference(0, uri("/lists/1")), anchors);
        assertThat(stub.requests()).hasSize(1);
        clock.advance(Duration.ofSeconds(2));
        client.evaluate(new StatusReference(0, uri("/lists/1")), anchors);
        assertThat(stub.requests()).hasSize(2);
    }

    @Test
    void negativeMaxCacheIsAConfigurationError() {
        assertThatThrownBy(() -> client(new StatusPolicy(true, OnUnavailable.FAIL_CLOSED, Duration.ofSeconds(-1),
                List.of()))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void nullMaxCacheMeans900Seconds() {
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0}, c -> c.claim("ttl", 86_400)));
        final TokenStatusListClient client = client(new StatusPolicy(true, OnUnavailable.FAIL_CLOSED, null,
                List.of()));
        client.evaluate(new StatusReference(0, uri("/lists/1")), anchors);
        clock.advance(Duration.ofSeconds(901));
        client.evaluate(new StatusReference(0, uri("/lists/1")), anchors);
        assertThat(stub.requests()).hasSize(2);
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    void slowServerTimesOutWithinTheReadTimeout() {
        stub.respond(r -> new StubResponse(200, JWT_TYPE,
                jwt(uri("/lists/1"), 1, new int[] {0}).getBytes(StandardCharsets.US_ASCII), 6_000, null));
        final long start = System.nanoTime();
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
        final Duration elapsed = Duration.ofNanos(System.nanoTime() - start);
        assertThat(elapsed).isGreaterThanOrEqualTo(Duration.ofMillis(4_500)).isLessThan(Duration.ofMillis(5_900));
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    void tricklingBodyTimesOutWithinTheReadTimeout() {
        stub.respond(r -> new StubResponse(200, JWT_TYPE, new byte[64], -6_000, null)); // headers, then a stall
        final long start = System.nanoTime();
        assertCode(() -> client(failClosed()).evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(5_900));
    }

    // ------------------------------------------------------------------------------------------- cache

    @Test
    void cacheHitMakesNoSecondRequestWithinTtl() {
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0, 1}, c -> c.claim("ttl", 300)));
        final TokenStatusListClient client = client(failClosed());
        client.evaluate(new StatusReference(0, uri("/lists/1")), anchors);
        clock.advance(Duration.ofSeconds(299));
        assertCode(() -> client.evaluate(new StatusReference(1, uri("/lists/1")), anchors),
                WalletErrorCode.CREDENTIAL_REVOKED);
        assertThat(stub.requests()).hasSize(1);
    }

    @Test
    void cacheIsRefreshedAfterTtl() {
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0}, c -> c.claim("ttl", 300)));
        final TokenStatusListClient client = client(failClosed());
        client.evaluate(new StatusReference(0, uri("/lists/1")), anchors);
        clock.advance(Duration.ofSeconds(301));
        client.evaluate(new StatusReference(0, uri("/lists/1")), anchors);
        assertThat(stub.requests()).hasSize(2);
    }

    @Test
    void cacheNeverOutlivesMaxCache() {
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0}, c -> c.claim("ttl", 86_400)));
        final TokenStatusListClient client = client(new StatusPolicy(true, OnUnavailable.FAIL_CLOSED,
                Duration.ofSeconds(60), List.of()));
        client.evaluate(new StatusReference(0, uri("/lists/1")), anchors);
        clock.advance(Duration.ofSeconds(59));
        client.evaluate(new StatusReference(0, uri("/lists/1")), anchors);
        assertThat(stub.requests()).hasSize(1);
        clock.advance(Duration.ofSeconds(2));
        client.evaluate(new StatusReference(0, uri("/lists/1")), anchors);
        assertThat(stub.requests()).hasSize(2);
    }

    @Test
    void cacheNeverOutlivesTheTokenExp() {
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0}, c -> c.claim("ttl", 600)
                .expirationTime(Date.from(clock.instant().plus(Duration.ofSeconds(120))))));
        final TokenStatusListClient client = client(failClosed());
        client.evaluate(new StatusReference(0, uri("/lists/1")), anchors);
        clock.advance(Duration.ofSeconds(121));
        // past exp: the cache entry is gone and the list is refetched (still within the 60 s clock skew)
        client.evaluate(new StatusReference(0, uri("/lists/1")), anchors);
        assertThat(stub.requests()).hasSize(2);
        clock.advance(Duration.ofSeconds(60));
        // beyond exp + skew: the stub still serves the same token, which is now expired
        assertCode(() -> client.evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
        assertThat(stub.requests()).hasSize(3);
    }

    @Test
    void cacheIsNotSharedAcrossDifferentAnchors() {
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0}));
        final TokenStatusListClient client = client(failClosed());
        client.evaluate(new StatusReference(0, uri("/lists/1")), anchors);
        final TrustAnchors other = TestPki.create("Other").trustAnchors(TrustAnchors.RevocationMode.OFF);
        assertCode(() -> client.evaluate(new StatusReference(0, uri("/lists/1")), other),
                WalletErrorCode.STATUS_UNAVAILABLE);
        assertThat(stub.requests()).hasSize(2);
    }

    @Test
    void cacheIsBoundedByDecodedBytesAndEvictsTheLeastRecentlyUsed() {
        // three lists of 4 KB decoded each; a 10 000 byte budget holds two of them
        stub.respond(r -> StubResponse.ok(JWT_TYPE, signJwt(signer, header(signer), baseClaims(uri(r.path()))
                .claim("status_list", Map.of("bits", 1, "lst", b64url(zlib(new byte[4096])))).build())
                .getBytes(StandardCharsets.US_ASCII)));
        final StatusListCache cache = new StatusListCache(64, 10_000);
        final TokenStatusListClient client = client(failClosed(), cache);
        for (final String list : List.of("/lists/a", "/lists/b", "/lists/c")) {
            client.evaluate(new StatusReference(0, uri(list)), anchors);
        }
        assertThat(cache.entries()).isEqualTo(2);
        assertThat(cache.bytes()).isEqualTo(8192);

        client.evaluate(new StatusReference(0, uri("/lists/b")), anchors);
        client.evaluate(new StatusReference(0, uri("/lists/c")), anchors);
        client.evaluate(new StatusReference(0, uri("/lists/a")), anchors);
        assertThat(stub.requests().stream().map(Request::path))
                .containsExactly("/lists/a", "/lists/b", "/lists/c", "/lists/a");
    }

    @Test
    void cacheIsBoundedByEntryCount() {
        stub.respond(r -> StubResponse.ok(JWT_TYPE, jwt(uri(r.path()), 1, new int[] {0})
                .getBytes(StandardCharsets.US_ASCII)));
        final StatusListCache cache = new StatusListCache(2, StatusListCache.DEFAULT_MAX_BYTES);
        final TokenStatusListClient client = client(failClosed(), cache);
        for (final String list : List.of("/lists/a", "/lists/b", "/lists/c")) {
            client.evaluate(new StatusReference(0, uri(list)), anchors);
        }
        assertThat(cache.entries()).isEqualTo(2);
    }

    @Test
    void theDefaultBudgetHoldsAtMost32MegabytesOfDecodedLists() {
        // 20 lists of the largest accepted size (2 MB decoded): 40 MB without a byte budget
        final byte[] compressed = zlib(new byte[StatusListToken.MAX_INFLATED_BYTES]);
        stub.respond(r -> StubResponse.ok(JWT_TYPE, signJwt(signer, header(signer), baseClaims(uri(r.path()))
                .claim("status_list", Map.of("bits", 1, "lst", b64url(compressed))).build())
                .getBytes(StandardCharsets.US_ASCII)));
        final StatusListCache cache = new StatusListCache();
        final TokenStatusListClient client = client(failClosed(), cache);
        for (int i = 0; i < 20; i++) {
            client.evaluate(new StatusReference(0, uri("/lists/" + i)), anchors);
        }
        assertThat(StatusListCache.DEFAULT_MAX_BYTES).isEqualTo(32L * 1024 * 1024);
        assertThat(cache.bytes()).isLessThanOrEqualTo(StatusListCache.DEFAULT_MAX_BYTES);
        assertThat(cache.entries()).isEqualTo(16);
    }

    @Test
    void aListLargerThanTheBudgetIsNotCached() {
        stub.respond(r -> StubResponse.ok(JWT_TYPE, signJwt(signer, header(signer), baseClaims(uri(r.path()))
                .claim("status_list", Map.of("bits", 1, "lst", b64url(zlib(new byte[4096])))).build())
                .getBytes(StandardCharsets.US_ASCII)));
        final StatusListCache cache = new StatusListCache(64, 1_000);
        final TokenStatusListClient client = client(failClosed(), cache);
        client.evaluate(new StatusReference(0, uri("/lists/a")), anchors);
        client.evaluate(new StatusReference(0, uri("/lists/a")), anchors);
        assertThat(cache.entries()).isZero();
        assertThat(stub.requests()).hasSize(2);
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void concurrentEvaluationsShareOneFetch() throws Exception {
        final byte[] token = jwt(uri("/lists/1"), 1, new int[] {0}).getBytes(StandardCharsets.US_ASCII);
        stub.respond(r -> new StubResponse(200, JWT_TYPE, token, 400, null));
        final TokenStatusListClient client = client(failClosed());
        final java.util.concurrent.CountDownLatch go = new java.util.concurrent.CountDownLatch(1);
        final java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(8);
        try {
            final List<java.util.concurrent.Future<String>> results = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                results.add(pool.submit(() -> {
                    go.await();
                    return client.evaluate(new StatusReference(0, uri("/lists/1")), anchors);
                }));
            }
            go.countDown();
            for (final var r : results) {
                assertThat(r.get(20, TimeUnit.SECONDS)).isEqualTo(StatusEvaluator.VALID);
            }
        } finally {
            pool.shutdownNow();
        }
        assertThat(stub.requests()).hasSize(1);
    }

    @Test
    void aStricterProviderNeverGetsAListAnotherProviderCached() {
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0}));
        final StatusListCache cache = new StatusListCache();
        final TokenStatusListClient open = client(failClosed(), cache);
        open.evaluate(new StatusReference(0, uri("/lists/1")), anchors);
        final TokenStatusListClient strict = client(policy(OnUnavailable.FAIL_OPEN_WITH_AUDIT,
                List.of("status.other.example")), cache);
        assertCode(() -> strict.evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
        assertThat(audits).isEmpty(); // a policy refusal, never the fail-open path
        assertThat(stub.requests()).hasSize(1);
    }

    @Test
    void oneCacheServesClientsWithDifferentMaxCache() {
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0}, c -> c.claim("ttl", 600)));
        final StatusListCache cache = new StatusListCache();
        final TokenStatusListClient longer = client(failClosed(), cache);
        final TokenStatusListClient shorter = client(new StatusPolicy(true, OnUnavailable.FAIL_CLOSED,
                Duration.ofSeconds(60), List.of()), cache);
        longer.evaluate(new StatusReference(0, uri("/lists/1")), anchors);
        clock.advance(Duration.ofSeconds(61));
        shorter.evaluate(new StatusReference(0, uri("/lists/1")), anchors); // past ITS maxCache: refetched
        assertThat(stub.requests()).hasSize(2);
        longer.evaluate(new StatusReference(0, uri("/lists/1")), anchors); // within its 600 s ttl: cached
        assertThat(stub.requests()).hasSize(2);
    }

    @Test
    void failuresAreNotCached() {
        stub.respond(r -> new StubResponse(503, null, new byte[0], 0, null));
        final TokenStatusListClient client = client(failClosed());
        assertCode(() -> client.evaluate(new StatusReference(0, uri("/lists/1")), anchors),
                WalletErrorCode.STATUS_UNAVAILABLE);
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0}));
        assertThat(client.evaluate(new StatusReference(0, uri("/lists/1")), anchors))
                .isEqualTo(StatusEvaluator.VALID);
    }

    // ------------------------------------------------------------------------------------------- CWT (mdoc)

    @Test
    void cwtStatusListIsEvaluated() {
        stub.serveCwt(cwt(signer, uri("/cwt/1"), 1, new int[] {0, 1}, Map.of()));
        final StatusEvaluator cwt = client(failClosed()).cwtEvaluator();
        assertThat(cwt.evaluate(new StatusReference(0, uri("/cwt/1")), anchors, sameIssuer()))
                .isEqualTo(StatusEvaluator.VALID);
        assertCode(() -> cwt.evaluate(new StatusReference(1, uri("/cwt/1")), anchors, sameIssuer()),
                WalletErrorCode.CREDENTIAL_REVOKED);
        assertThat(stub.requests()).singleElement().satisfies(r -> assertThat(r.accept()).isEqualTo(CWT_TYPE));
    }

    @Test
    void cwtWithBadSignatureIsStatusUnavailable() {
        stub.serveCwt(cwt(signer, uri("/cwt/1"), 1, new int[] {0}, Map.of("tamper", true)));
        assertCode(() -> client(failClosed()).cwtEvaluator().evaluate(new StatusReference(0, uri("/cwt/1")), anchors, sameIssuer()),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void cwtFromAnUntrustedSignerIsStatusUnavailable() {
        final Leaf stranger = TestPki.create("Stranger").issueLeaf(LeafSpec.defaults());
        stub.serveCwt(cwt(stranger, uri("/cwt/1"), 1, new int[] {0}, Map.of()));
        assertCode(() -> client(failClosed()).cwtEvaluator().evaluate(new StatusReference(0, uri("/cwt/1")), anchors, sameIssuer()),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void cwtWithWrongSubjectIsStatusUnavailable() {
        stub.serveCwt(cwt(signer, uri("/cwt/other"), 1, new int[] {0}, Map.of()));
        assertCode(() -> client(failClosed()).cwtEvaluator().evaluate(new StatusReference(0, uri("/cwt/1")), anchors, sameIssuer()),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void cwtWithWrongTypeIsStatusUnavailable() {
        stub.serveCwt(cwt(signer, uri("/cwt/1"), 1, new int[] {0}, Map.of("typ", "application/cwt")));
        assertCode(() -> client(failClosed()).cwtEvaluator().evaluate(new StatusReference(0, uri("/cwt/1")), anchors, sameIssuer()),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void cwtWithX5chainOnlyInTheUnprotectedHeaderIsStatusUnavailable() {
        stub.serveCwt(cwt(signer, uri("/cwt/1"), 1, new int[] {0}, Map.of("unprotectedX5chain", true)));
        assertCode(() -> client(failClosed()).cwtEvaluator().evaluate(new StatusReference(0, uri("/cwt/1")), anchors, sameIssuer()),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void cwtExpiredIsStatusUnavailable() {
        stub.serveCwt(cwt(signer, uri("/cwt/1"), 1, new int[] {0},
                Map.of("exp", clock.instant().minusSeconds(300).getEpochSecond())));
        assertCode(() -> client(failClosed()).cwtEvaluator().evaluate(new StatusReference(0, uri("/cwt/1")), anchors, sameIssuer()),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void cwtUntaggedIsStatusUnavailable() {
        stub.serveCwt(cwt(signer, uri("/cwt/1"), 1, new int[] {0}, Map.of("untagged", true)));
        assertCode(() -> client(failClosed()).cwtEvaluator().evaluate(new StatusReference(0, uri("/cwt/1")), anchors, sameIssuer()),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void cwtZipBombIsLimitExceeded() {
        stub.serveCwt(cwt(signer, uri("/cwt/1"), 1, new int[] {0}, Map.of("lst", zlib(new byte[3 * 1024 * 1024]))));
        assertCode(() -> client(failClosed()).cwtEvaluator().evaluate(new StatusReference(0, uri("/cwt/1")), anchors, sameIssuer()),
                WalletErrorCode.LIMIT_EXCEEDED);
    }

    // ------------------------------------------------------------------------------------------- ISO §12.3.6 signer
    // docs/eudi-wallet-spec-notes.md §6.5: without a status_list "certificate" the list's signer must belong to the
    // MSO signer's issuer; with one, the list must chain to that certificate. Both under either policy.

    /** Anchors trusting the status PKI and an unrelated second PKI. */
    private static TrustAnchors bothRoots(final TestPki other) {
        return new TrustAnchors(java.util.Set.of(new java.security.cert.TrustAnchor(pki.root(), null),
                new java.security.cert.TrustAnchor(other.root(), null)), List.of(), TrustAnchors.RevocationMode.OFF);
    }

    @Test
    void mdocListSignedByAnUnrelatedTrustedCaIsRefusedWithoutCertificate() {
        final TestPki other = TestPki.create("Unrelated Status");
        final Leaf otherSigner = other.issueLeaf(LeafSpec.defaults());
        final Leaf msoSigner = pki.issueLeaf(LeafSpec.defaults());
        final TrustAnchors trusted = bothRoots(other);
        stub.serveCwt(cwt(otherSigner, uri("/cwt/1"), 1, new int[] {0}, Map.of()));
        final StatusEvaluator cwt = client(failOpen()).cwtEvaluator();
        final StatusReference ref = new StatusReference(0, uri("/cwt/1"));

        assertThat(cwt.evaluate(ref, trusted, mdocIssuer(otherSigner.chain(), trusted, null)))
                .as("the list itself is trusted, for its own issuer's credentials").isEqualTo(StatusEvaluator.VALID);
        assertCode(() -> cwt.evaluate(ref, trusted, mdocIssuer(msoSigner.chain(), trusted, null)),
                WalletErrorCode.STATUS_UNAVAILABLE);
        assertThat(audits).as("a signer refusal is never fail-open").isEmpty();
    }

    @Test
    void mdocListSignedUnderTheMsoSignersIssuerIsAccepted() {
        final Leaf msoSigner = pki.issueLeaf(LeafSpec.defaults());
        stub.serveCwt(cwt(signer, uri("/cwt/1"), 1, new int[] {0}, Map.of()));

        assertThat(client(failClosed()).cwtEvaluator().evaluate(new StatusReference(0, uri("/cwt/1")), anchors,
                mdocIssuer(msoSigner.chain(), anchors, null))).isEqualTo(StatusEvaluator.VALID);
    }

    @Test
    void mdocListSignedByTheMsoSignerItselfIsAccepted() {
        stub.serveCwt(cwt(signer, uri("/cwt/1"), 1, new int[] {0}, Map.of()));

        assertThat(client(failClosed()).cwtEvaluator().evaluate(new StatusReference(0, uri("/cwt/1")), anchors,
                mdocIssuer(signer.chain(), anchors, null))).isEqualTo(StatusEvaluator.VALID);
    }

    @Test
    void mdocListMustChainToTheStatusListCertificateWhenOneIsGiven() throws Exception {
        final TestPki other = TestPki.create("Delegated Status");
        final Leaf otherSigner = other.issueLeaf(LeafSpec.defaults());
        final Leaf msoSigner = pki.issueLeaf(LeafSpec.defaults());
        final TrustAnchors trusted = bothRoots(other);
        final byte[] certificate = other.intermediate().getEncoded();
        final StatusEvaluator cwt = client(failClosed()).cwtEvaluator();

        stub.serveCwt(cwt(otherSigner, uri("/cwt/delegated"), 1, new int[] {0}, Map.of()));
        assertThat(cwt.evaluate(new StatusReference(0, uri("/cwt/delegated")), trusted,
                mdocIssuer(msoSigner.chain(), trusted, certificate))).isEqualTo(StatusEvaluator.VALID);

        stub.serveCwt(cwt(signer, uri("/cwt/issuer"), 1, new int[] {0}, Map.of()));
        assertCode(() -> cwt.evaluate(new StatusReference(0, uri("/cwt/issuer")), trusted,
                mdocIssuer(msoSigner.chain(), trusted, certificate)), WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void mdocStatusListCertificateThatIsNotACertificateIsRefused() {
        stub.serveCwt(cwt(signer, uri("/cwt/1"), 1, new int[] {0}, Map.of()));

        assertCode(() -> client(failOpen()).cwtEvaluator().evaluate(new StatusReference(0, uri("/cwt/1")), anchors,
                mdocIssuer(signer.chain(), anchors, new byte[] {1, 2, 3})),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    // Fix round 1 (review Critical 1, ruling 1): the rule runs on the PKIX-validated path, and the list signer must chain
    // to the MSO signer's own issuing CA. The attacker below appends the victim's anchor to its own list chain.

    /** Two issuing CAs, each trusted directly as an anchor (as IACAs are for mDL). */
    private static TrustAnchors issuingCaAnchors(final TestPki a, final TestPki b) {
        return new TrustAnchors(java.util.Set.of(new java.security.cert.TrustAnchor(a.intermediate(), null),
                new java.security.cert.TrustAnchor(b.intermediate(), null)), List.of(), TrustAnchors.RevocationMode.OFF);
    }

    @Test
    void mdocListOfASiblingIssuerWithTheVictimsAnchorAppendedIsRefused() {
        final TestPki attacker = TestPki.create("Attacker Issuer");
        final Leaf victimDs = pki.issueLeaf(LeafSpec.defaults());
        final Leaf attackerList = attacker.issueLeaf(LeafSpec.defaults());
        final Leaf forged = new Leaf(attackerList.certificate(), attackerList.privateKey(),
                List.of(attackerList.certificate(), attacker.intermediate(), pki.intermediate()));
        final TrustAnchors trusted = issuingCaAnchors(pki, attacker);
        stub.serveCwt(cwt(forged, uri("/cwt/forged"), 1, new int[] {0}, Map.of()));

        assertCode(() -> client(failOpen()).cwtEvaluator().evaluate(new StatusReference(0, uri("/cwt/forged")),
                trusted, mdocIssuer(victimDs.chain(), trusted, null)), WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void mdocListOfASiblingIssuerUnderTheSameRootIsRefused() {
        final TestPki sibling = pki.siblingIssuer("Sibling Status");
        final Leaf victimDs = pki.issueLeaf(LeafSpec.defaults());
        final Leaf siblingList = sibling.issueLeaf(LeafSpec.defaults());
        stub.serveCwt(cwt(siblingList, uri("/cwt/sibling"), 1, new int[] {0}, Map.of()));
        final StatusEvaluator cwt = client(failOpen()).cwtEvaluator();

        assertCode(() -> cwt.evaluate(new StatusReference(0, uri("/cwt/sibling")), anchors,
                mdocIssuer(victimDs.chain(), anchors, null)), WalletErrorCode.STATUS_UNAVAILABLE);
        assertThat(cwt.evaluate(new StatusReference(0, uri("/cwt/sibling")), anchors,
                mdocIssuer(sibling.issueLeaf(LeafSpec.defaults()).chain(), anchors, null)))
                .as("the sibling's own credentials").isEqualTo(StatusEvaluator.VALID);
    }

    @Test
    void mdocListWithTheCertificatesAnchorAppendedIsRefused() throws Exception {
        final TestPki attacker = TestPki.create("Attacker Certificate");
        final Leaf victimDs = pki.issueLeaf(LeafSpec.defaults());
        final Leaf attackerList = attacker.issueLeaf(LeafSpec.defaults());
        final Leaf forged = new Leaf(attackerList.certificate(), attackerList.privateKey(),
                List.of(attackerList.certificate(), attacker.intermediate(), pki.intermediate()));
        final TrustAnchors trusted = issuingCaAnchors(pki, attacker);
        stub.serveCwt(cwt(forged, uri("/cwt/forged-cert"), 1, new int[] {0}, Map.of()));
        final byte[] victimCa = pki.intermediate().getEncoded();

        assertCode(() -> client(failOpen()).cwtEvaluator().evaluate(new StatusReference(0, uri("/cwt/forged-cert")),
                trusted, mdocIssuer(victimDs.chain(), trusted, victimCa)),
                WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void jwtListHasNoIssuerBindingRule() {
        final TestPki other = TestPki.create("JWT Unrelated");
        final Leaf msoSigner = other.issueLeaf(LeafSpec.defaults());
        stub.serveJwt(jwt(uri("/lists/1"), 1, new int[] {0}));

        assertThat(client(failClosed()).evaluate(new StatusReference(0, uri("/lists/1")), anchors,
                mdocIssuer(msoSigner.chain(), bothRoots(other), null))).isEqualTo(StatusEvaluator.VALID);
    }

    @Test
    void jwtAndCwtAreCachedSeparately() {
        final String token = jwt(uri("/lists/1"), 1, new int[] {0});
        final byte[] cwt = cwt(signer, uri("/lists/1"), 1, new int[] {1}, Map.of());
        stub.respond(r -> CWT_TYPE.equals(r.accept()) ? StubResponse.ok(CWT_TYPE, cwt)
                : StubResponse.ok(JWT_TYPE, token.getBytes(StandardCharsets.US_ASCII)));
        final TokenStatusListClient client = client(failClosed());
        assertThat(client.evaluate(new StatusReference(0, uri("/lists/1")), anchors)).isEqualTo(StatusEvaluator.VALID);
        assertCode(() -> client.cwtEvaluator().evaluate(new StatusReference(0, uri("/lists/1")), anchors, sameIssuer()),
                WalletErrorCode.CREDENTIAL_REVOKED);
    }

    // ------------------------------------------------------------------------------------------- with the verifier

    @Test
    void sdJwtVerifierRejectsACredentialRevokedInItsStatusList() {
        final TestWallet wallet = TestWallet.create();
        final Leaf listSigner = wallet.pki().issueLeaf(LeafSpec.defaults().withSubject("CN=Status,O=HelixIAM Test"));
        stub.serveJwt(jwt(listSigner, uri("/lists/pid"), 1, new int[] {0, 0, 0, 1}, b -> b));
        final String vp = presentPid(wallet, new StatusReference(3, uri("/lists/pid")));
        final TokenStatusListClient client = client(failClosed());
        assertCode(() -> new SdJwtVcPresentationVerifier(new IssuerTrustValidator(), client).verify(vp,
                verifierContext(wallet, failClosed())), WalletErrorCode.CREDENTIAL_REVOKED);
    }

    @Test
    void sdJwtVerifierAcceptsAValidStatus() {
        final TestWallet wallet = TestWallet.create();
        final Leaf listSigner = wallet.pki().issueLeaf(LeafSpec.defaults().withSubject("CN=Status,O=HelixIAM Test"));
        stub.serveJwt(jwt(listSigner, uri("/lists/pid"), 1, new int[] {0, 0, 0, 1}, b -> b));
        final String vp = presentPid(wallet, new StatusReference(2, uri("/lists/pid")));
        assertThat(new SdJwtVcPresentationVerifier(new IssuerTrustValidator(), client(failClosed()))
                .verify(vp, verifierContext(wallet, failClosed())).statusResult()).isEqualTo(StatusEvaluator.VALID);
    }

    @Test
    void sdJwtVerifierFailsOpenOnlyThroughTheClientsAudit() {
        final TestWallet wallet = TestWallet.create();
        final String u = "https://localhost:" + freePort() + "/lists/pid";
        final String vp = presentPid(wallet, new StatusReference(0, u));
        assertThat(new SdJwtVcPresentationVerifier(new IssuerTrustValidator(), client(failOpen(), guardFor(u)))
                .verify(vp, verifierContext(wallet, failOpen())).statusResult()).isEqualTo(StatusEvaluator.VALID);
        assertThat(audits).containsExactly("localhost|STATUS_UNAVAILABLE");
    }

    private static String presentPid(final TestWallet wallet, final StatusReference ref) {
        final Instant now = Instant.now();
        final TestWallet.SdJwtCredential cred = wallet.sdJwtPid(Map.of("given_name", "Erika"),
                now.minusSeconds(3600), now.plus(Duration.ofDays(30)), java.util.Optional.of(ref));
        return wallet.present(cred, java.util.Set.of("given_name"), "x509_san_dns:verifier.example", "n-0S6_WzA2Mj");
    }

    private static VerificationContext verifierContext(final TestWallet wallet, final StatusPolicy policy) {
        return new VerificationContext("x509_san_dns:verifier.example", "n-0S6_WzA2Mj",
                "https://verifier.example/wallet/response", null, Instant.now(), Duration.ofSeconds(60),
                wallet.pki().trustAnchors(TrustAnchors.RevocationMode.OFF), policy,
                java.util.Set.of(TestWallet.PID_VCT), null, false);
    }

    // ------------------------------------------------------------------------------------------- audit sink

    @Test
    void auditLogSinkEmitsWalletStatusCheckFailed() {
        final AuditLog auditLog = mock(AuditLog.class);
        TokenStatusListClient.auditLogSink(auditLog).statusUnavailableAccepted("status.example",
                WalletErrorCode.STATUS_UNAVAILABLE, "timeout");
        final ArgumentCaptor<AuditEvent> event = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditLog).emit(event.capture());
        assertThat(event.getValue().type()).isEqualTo("WALLET_STATUS_CHECK_FAILED");
        assertThat(event.getValue().category()).isEqualTo(AuditEvent.AUTHN);
        assertThat(event.getValue().detail()).containsEntry("reason", "wallet.status_unavailable")
                .containsEntry("statusListHost", "status.example").containsEntry("decision", "FAIL_OPEN_WITH_AUDIT");
    }

    // ------------------------------------------------------------------------------------------- helpers

    private String uri(final String path) {
        return "https://localhost:" + stub.port() + path;
    }

    /** The credential issuer as the mdoc verifier passes it. */
    private CredentialIssuer mdocIssuer(final List<X509Certificate> chain, final TrustAnchors trusted,
            final byte[] certificate) {
        return new CredentialIssuer(new IssuerTrustValidator().validateChain(chain, trusted, clock.instant()),
                certificate);
    }

    /** The status list signer's own credentials: a credential issuer the default list may speak for. */
    private CredentialIssuer sameIssuer() {
        return mdocIssuer(signer.chain(), anchors, null);
    }

    private static StatusPolicy failClosed() {
        return policy(OnUnavailable.FAIL_CLOSED, List.of());
    }

    private static StatusPolicy failOpen() {
        return policy(OnUnavailable.FAIL_OPEN_WITH_AUDIT, List.of());
    }

    private static StatusPolicy policy(final OnUnavailable onUnavailable, final List<String> allowedHosts) {
        return new StatusPolicy(true, onUnavailable, MAX_CACHE, allowedHosts);
    }

    private TokenStatusListClient client(final StatusPolicy policy) {
        return client(policy, new OutboundUrlGuard(false, "localhost:" + stub.port()));
    }

    private TokenStatusListClient client(final StatusPolicy policy, final OutboundUrlGuard guard) {
        return new TokenStatusListClient(policy, new IssuerTrustValidator(guard), guard, clientTls, clock,
                (host, code, detail) -> audits.add(host + "|" + code));
    }

    private TokenStatusListClient client(final StatusPolicy policy, final StatusListCache cache) {
        final OutboundUrlGuard guard = new OutboundUrlGuard(false, "localhost:" + stub.port());
        return new TokenStatusListClient(policy, new IssuerTrustValidator(guard), guard, clientTls, clock,
                (host, code, detail) -> audits.add(host + "|" + code), cache);
    }

    private static OutboundUrlGuard guardFor(final String url) {
        final java.net.URI u = java.net.URI.create(url);
        return new OutboundUrlGuard(false, u.getHost() + ":" + u.getPort());
    }

    private static int freePort() {
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return s.getLocalPort();
        } catch (final IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void assertCode(final Runnable call, final WalletErrorCode code) {
        final WalletVerificationException e = catchThrowableOfType(WalletVerificationException.class, call::run);
        assertThat(e).as("expected %s", code).isNotNull();
        assertThat(e.code()).isEqualTo(code);
    }

    /** Packs {@code statuses} with {@code bits} per entry, LSB first (draft §4.1). */
    static byte[] pack(final int bits, final int[] statuses) {
        final int perByte = 8 / Math.max(1, bits);
        final byte[] out = new byte[Math.max(1, (statuses.length + perByte - 1) / perByte)];
        for (int i = 0; i < statuses.length; i++) {
            out[i / perByte] |= (byte) (statuses[i] << ((i % perByte) * bits));
        }
        return out;
    }

    static byte[] zlib(final byte[] data) {
        final Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        deflater.setInput(data);
        deflater.finish();
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final byte[] buf = new byte[8192];
        while (!deflater.finished()) {
            out.write(buf, 0, deflater.deflate(buf));
        }
        deflater.end();
        return out.toByteArray();
    }

    private static String b64url(final byte[] bytes) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String jwt(final String sub, final int bits, final int[] statuses) {
        return jwt(sub, bits, statuses, c -> c);
    }

    private String jwt(final String sub, final int bits, final int[] statuses,
            final Function<JWTClaimsSet.Builder, JWTClaimsSet.Builder> claims) {
        return signJwt(signer, header(signer), claims.apply(baseClaims(sub).claim("status_list",
                Map.of("bits", bits, "lst", b64url(zlib(pack(bits == 3 ? 1 : bits, statuses)))))).build());
    }

    private String jwt(final Leaf leaf, final String sub, final int bits, final int[] statuses,
            final Function<JWSHeader.Builder, JWSHeader.Builder> header) {
        return signJwt(leaf, header.apply(header(leaf)), baseClaims(sub).claim("status_list",
                Map.of("bits", bits, "lst", b64url(zlib(pack(bits, statuses))))).build());
    }

    private JWTClaimsSet.Builder baseClaims(final String sub) {
        return new JWTClaimsSet.Builder().subject(sub).issueTime(Date.from(clock.instant().minusSeconds(10)))
                .expirationTime(Date.from(clock.instant().plus(Duration.ofDays(1))));
    }

    private static JWSHeader.Builder header(final Leaf leaf) {
        final List<Base64> x5c = new ArrayList<>();
        for (final X509Certificate c : leaf.chain()) {
            try {
                x5c.add(Base64.encode(c.getEncoded()));
            } catch (final Exception e) {
                throw new IllegalStateException(e);
            }
        }
        return new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("statuslist+jwt"))
                .x509CertChain(x5c);
    }

    private static String signJwt(final Leaf leaf, final JWSHeader.Builder header, final JWTClaimsSet claims) {
        try {
            final SignedJWT jwt = new SignedJWT(header.build(), claims);
            jwt.sign(new ECDSASigner((ECPrivateKey) leaf.privateKey()));
            return jwt.serialize();
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * A Status List Token in CWT form (draft §5.2): COSE_Sign1_Tagged (18), protected header {1: -7, 16: type,
     * 33: x5chain}, payload {2: sub, 6: iat, 4: exp, 65534: ttl, 65533: {bits, lst}}. {@code options}: "tamper",
     * "typ", "unprotectedX5chain", "exp", "untagged", "lst".
     */
    private byte[] cwt(final Leaf leaf, final String sub, final int bits, final int[] statuses,
            final Map<String, Object> options) {
        try {
            final CBORFactory factory = new CBORFactory();
            final boolean unprotectedX5chain = Boolean.TRUE.equals(options.get("unprotectedX5chain"));
            final ByteArrayOutputStream protectedOut = new ByteArrayOutputStream();
            try (CBORGenerator g = (CBORGenerator) factory.createGenerator(protectedOut)) {
                g.writeStartObject(null, unprotectedX5chain ? 2 : 3); // 1, 16, and 33 unless it moves to unprotected
                g.writeFieldId(1);
                g.writeNumber(-7);
                g.writeFieldId(16);
                g.writeString((String) options.getOrDefault("typ", CWT_TYPE));
                if (!unprotectedX5chain) {
                    g.writeFieldId(33);
                    writeX5chain(g, leaf);
                }
                g.writeEndObject();
            }
            final byte[] protectedBytes = protectedOut.toByteArray();
            final ByteArrayOutputStream payloadOut = new ByteArrayOutputStream();
            try (CBORGenerator g = (CBORGenerator) factory.createGenerator(payloadOut)) {
                g.writeStartObject(null, 5); // 2 (sub), 6 (iat), 4 (exp), 65534 (ttl), 65533 (status)
                g.writeFieldId(2);
                g.writeString(sub);
                g.writeFieldId(6);
                g.writeNumber(clock.instant().minusSeconds(10).getEpochSecond());
                g.writeFieldId(4);
                g.writeNumber((long) options.getOrDefault("exp",
                        clock.instant().plus(Duration.ofDays(1)).getEpochSecond()));
                g.writeFieldId(65534);
                g.writeNumber(300);
                g.writeFieldId(65533);
                g.writeStartObject(null, 2); // bits, lst
                g.writeNumberField("bits", bits);
                g.writeBinaryField("lst", (byte[]) options.getOrDefault("lst", zlib(pack(bits, statuses))));
                g.writeEndObject();
                g.writeEndObject();
            }
            final byte[] payload = payloadOut.toByteArray();

            final ByteArrayOutputStream sigStructure = new ByteArrayOutputStream();
            sigStructure.write(0x84); // array(4)
            sigStructure.write(0x6A); // text(10)
            sigStructure.writeBytes("Signature1".getBytes(StandardCharsets.US_ASCII));
            writeBstr(sigStructure, protectedBytes);
            sigStructure.write(0x40); // external_aad = h''
            writeBstr(sigStructure, payload);
            final Signature ecdsa = Signature.getInstance("SHA256withECDSA");
            ecdsa.initSign(leaf.privateKey());
            ecdsa.update(sigStructure.toByteArray());
            final byte[] signature = ECDSA.transcodeSignatureToConcat(ecdsa.sign(), 64);
            if (Boolean.TRUE.equals(options.get("tamper"))) {
                signature[5] ^= 0x01;
            }

            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (CBORGenerator g = (CBORGenerator) factory.createGenerator(out)) {
                if (!Boolean.TRUE.equals(options.get("untagged"))) {
                    g.writeTag(18);
                }
                g.writeStartArray(null, 4); // COSE_Sign1: protected, unprotected, payload, signature
                g.writeBinary(protectedBytes);
                g.writeStartObject(null, unprotectedX5chain ? 1 : 0);
                if (unprotectedX5chain) {
                    g.writeFieldId(33);
                    writeX5chain(g, leaf);
                }
                g.writeEndObject();
                g.writeBinary(payload);
                g.writeBinary(signature);
                g.writeEndArray();
            }
            return out.toByteArray();
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static void writeX5chain(final CBORGenerator g, final Leaf leaf) throws Exception {
        g.writeStartArray(null, leaf.chain().size());
        for (final X509Certificate c : leaf.chain()) {
            g.writeBinary(c.getEncoded());
        }
        g.writeEndArray();
    }

    private static void writeBstr(final ByteArrayOutputStream out, final byte[] bytes) {
        final int len = bytes.length;
        if (len < 24) {
            out.write(0x40 | len);
        } else if (len < 256) {
            out.write(0x58);
            out.write(len);
        } else if (len < 65536) {
            out.write(0x59);
            out.write(len >> 8);
            out.write(len & 0xff);
        } else {
            out.write(0x5A);
            for (int shift = 24; shift >= 0; shift -= 8) {
                out.write((len >> shift) & 0xff);
            }
        }
        out.writeBytes(bytes);
    }

    // ------------------------------------------------------------------------------------------- stub server

    /** One recorded request. */
    record Request(String path, String accept) {
    }

    /**
     * A canned answer. {@code delayMillis > 0}: sleep before the headers; {@code < 0}: send the headers, then stall
     * that long before the body. {@code location}: a redirect target.
     */
    record StubResponse(int status, String contentType, byte[] body, long delayMillis, String location) {
        static StubResponse ok(final String contentType, final byte[] body) {
            return new StubResponse(200, contentType, body, 0, null);
        }
    }

    /** A local status-list server over HTTPS (or plain HTTP) that records every request it receives. */
    static final class StatusStub implements AutoCloseable {
        private final HttpServer server;
        private final List<Request> requests = new CopyOnWriteArrayList<>();
        private volatile Function<Request, StubResponse> responder = r -> new StubResponse(404, null, new byte[0], 0,
                null);

        private StatusStub(final TestTls tls) throws IOException {
            final InetSocketAddress address = new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}),
                    0);
            if (tls != null) {
                final HttpsServer s = HttpsServer.create(address, 0);
                s.setHttpsConfigurator(new HttpsConfigurator(tls.serverContext()));
                server = s;
            } else {
                server = HttpServer.create(address, 0);
            }
            server.createContext("/", this::handle);
            server.setExecutor(Executors.newCachedThreadPool(r -> {
                final Thread t = new Thread(r, "status-list-stub");
                t.setDaemon(true);
                return t;
            }));
            server.start();
        }

        static StatusStub https(final TestTls tls) {
            try {
                return new StatusStub(tls);
            } catch (final IOException e) {
                throw new IllegalStateException(e);
            }
        }

        static StatusStub http() {
            try {
                return new StatusStub(null);
            } catch (final IOException e) {
                throw new IllegalStateException(e);
            }
        }

        int port() {
            return server.getAddress().getPort();
        }

        List<Request> requests() {
            return List.copyOf(requests);
        }

        void respond(final Function<Request, StubResponse> value) {
            responder = value;
        }

        void serveJwt(final String token) {
            respond(r -> StubResponse.ok(JWT_TYPE, token.getBytes(StandardCharsets.US_ASCII)));
        }

        void serveCwt(final byte[] token) {
            respond(r -> StubResponse.ok(CWT_TYPE, token));
        }

        private void handle(final HttpExchange exchange) throws IOException {
            try (exchange; InputStream in = exchange.getRequestBody()) {
                in.readAllBytes();
                final Request request = new Request(exchange.getRequestURI().getPath(),
                        exchange.getRequestHeaders().getFirst("Accept"));
                requests.add(request);
                final StubResponse response = responder.apply(request);
                if (response.delayMillis() > 0) {
                    sleep(response.delayMillis());
                }
                if (response.contentType() != null) {
                    exchange.getResponseHeaders().add("Content-Type", response.contentType());
                }
                if (response.location() != null) {
                    exchange.getResponseHeaders().add("Location", response.location());
                }
                final byte[] body = response.body();
                if (response.delayMillis() < 0) {
                    exchange.sendResponseHeaders(response.status(), body.length + 1L);
                    final OutputStream out = exchange.getResponseBody();
                    out.write(body);
                    out.flush();
                    sleep(-response.delayMillis());
                    return;
                }
                exchange.sendResponseHeaders(response.status(), body.length == 0 ? -1 : body.length);
                if (body.length > 0) {
                    try (OutputStream out = exchange.getResponseBody()) {
                        out.write(body);
                    }
                }
            } catch (final IOException e) {
                // the client gave up (timeout tests): fine
            }
        }

        private static void sleep(final long millis) {
            try {
                Thread.sleep(millis);
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    /** A settable clock (cache-expiry tests). */
    static final class TestClock extends Clock {
        private volatile Instant now;

        TestClock(final Instant now) {
            this.now = now;
        }

        void advance(final Duration d) {
            now = now.plus(d);
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(final java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
