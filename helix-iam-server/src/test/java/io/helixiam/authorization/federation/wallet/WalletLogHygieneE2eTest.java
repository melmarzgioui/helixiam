/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import io.helixiam.authorization.amqp.federation.FederatedIdentityPublisher;
import io.helixiam.authorization.federation.AccountLinkingPolicy;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.federation.wallet.testwallet.Oid4vpWalletClient;
import io.helixiam.authorization.federation.wallet.testwallet.TestAccessKeys;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import io.helixiam.authorization.federation.wallet.transaction.InMemoryWalletTransactionStore;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.security.audit.HelixAuditProperties;
import io.helixiam.authorization.security.audit.HttpAuditForwarder;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.startup.DeploymentProfile;
import io.helixiam.testsupport.LogCapture;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Task 22 (spec &sect;15): "no PID value, token, nonce or key appears in logs at any level". Runs a real wallet login
 * (same-device and cross-device) and one failure, under {@link LogCapture#all()} (every logger, every level, exactly
 * what a production deployment's log aggregator would collect), and asserts none of the PID values, the nonce, the
 * {@code response_code}, a {@code vp_token} fragment (the issuer JWT and a disclosure, each by their first 20
 * characters — matching any later part would also catch a fragment), the ephemeral response key's {@code d}, the
 * holder key's {@code d}, the wallet pepper, or the resolved subject hash ever appear.
 *
 * <p>mdoc is not exercised here for time; its CBOR/COSE claims never reach this pipeline's log statements any
 * differently than SD-JWT's (same {@link WalletResponseHandler}, same {@code LogSafe.sanitize(..)} call sites), and
 * {@code MdocPresentationVerifierTest} / {@code CoseSign1Test} already assert nothing mdoc-specific (the MSO, device
 * signature, namespace values) leaks from their own layer.
 */
class WalletLogHygieneE2eTest {

    private static final String REALM = "acme";
    private static final String ALIAS = "eudi-wallet";
    private static final String BASE = "https://helix.example";
    private static final String HELIX_STATE = "helix-state-1";
    private static final String BINDING = "binding-hash-1";

    private static final TestPki ACCESS_PKI = TestPki.create("Hygiene Handler Access");
    private static final TestPki.Leaf ACCESS = ACCESS_PKI.issueLeaf(TestPki.LeafSpec.defaults());
    private static final TestWallet WALLET = TestWallet.create();

    private final InMemoryWalletTransactionStore store = new InMemoryWalletTransactionStore(Clock.systemUTC(), 100,
            null);
    private final TestAccessKeys keys = new TestAccessKeys(ACCESS, "eudi-access", REALM);
    private final FederatedIdentityPublisher identities = mock(FederatedIdentityPublisher.class);
    private final RealmWalletPepper pepper = mock(RealmWalletPepper.class);
    private final byte[] pepperBytes = randomBytes(32);
    /** A real AuditLog (no mock): proves the audit JSON line itself — which LogCapture.all() also sees — is clean. */
    private final AuditLog audit = new AuditLog(new ObjectMapper(), new HelixAuditProperties(),
            mock(HttpAuditForwarder.class));
    private final WalletResponseHandler handler;
    /** The transaction of the last {@link #fetched} login (never derivable from a redacted request/response URI). */
    private String lastTxId;

    WalletLogHygieneE2eTest() {
        when(pepper.pepper(any())).thenReturn(pepperBytes);
        handler = new WalletResponseHandler(new WalletSubjectResolver(pepper), new WalletLinkService(identities),
                AccountLinkingPolicy.defaults(), BASE, audit);
    }

    private static byte[] randomBytes(final int n) {
        final byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    private WalletIdentityProvider provider() {
        final Map<String, String> config = new HashMap<>();
        config.put("accessKeyRef", keys.ref(REALM));
        config.put("trustAnchors", WALLET.pki().rootPem());
        config.put("revocationChecking", "OFF");
        config.put("credentialFormats", "[\"dc+sd-jwt\"]");
        return new WalletIdentityProviders(new WalletConfigValidator(keys, DeploymentProfile.production()), keys,
                store, new OutboundUrlGuard(), audit)
                .build(REALM, WalletProviderConfig.fromStored(ALIAS, "Wallet", config));
    }

    private Oid4vpWalletClient.VerifiedRequest fetched(final WalletIdentityProvider provider,
                                                       final WalletTransaction.Flow flow) {
        final IdentityProvider.AuthnRequestContext context = new IdentityProvider.AuthnRequestContext(
                REALM, HELIX_STATE, BASE + "/realms/acme/broker/eudi-wallet/callback", BINDING);
        final IdentityProvider.RedirectResponse redirect = provider.start(context);
        lastTxId = redirect.location().substring(redirect.location().indexOf("tx=") + 3);
        final WalletTransaction created = store.byTransactionId(lastTxId).orElseThrow();
        final WalletTransaction tx = store.claimRequest(flow == WalletTransaction.Flow.SAME_DEVICE
                ? created.sameDeviceRequestId() : created.crossDeviceRequestId()).orElseThrow();
        final String jwt = new AuthorizationRequestFactory().signedRequestObject(tx, provider.config(),
                provider.signingKey(), BASE);
        return Oid4vpWalletClient.verifyRequest(provider.clientId(),
                AuthorizationRequestFactory.requestUri(BASE, tx, flow), jwt, Instant.now());
    }

    private WalletTransaction tx() {
        return store.byTransactionId(lastTxId).orElseThrow();
    }

    /**
     * {@link LogCapture#all()}, but also forces every logger to {@link Level#ALL} for the duration. This test runs
     * outside a booted Spring context, so Boot never loads {@code log4j2-spring.xml} (its Root level is {@code INFO})
     * — plain Log4j2's own built-in default is Root level {@code ERROR}, which would silently swallow every INFO/DEBUG
     * line this test needs to inspect, making every {@code doesNotContain} assertion vacuously true. Verified by a
     * throwaway sanity assertion during development (removed): without the level bump, the capture was empty.
     */
    private static final class FullCapture implements AutoCloseable {
        private final Level previousRootLevel;
        private final LogCapture capture;

        FullCapture() {
            final LoggerContext context = (LoggerContext) LogManager.getContext(false);
            this.previousRootLevel = context.getConfiguration().getRootLogger().getLevel();
            Configurator.setRootLevel(Level.ALL);
            this.capture = LogCapture.all();
        }

        String text() {
            return capture.text();
        }

        @Override
        public void close() {
            capture.close();
            Configurator.setRootLevel(previousRootLevel);
        }
    }

    private static Map<String, Object> pid() {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Hygiene-Erika");
        claims.put("family_name", "Hygiene-Mustermann");
        claims.put("birthdate", "1984-01-26");
        claims.put("issuing_country", "DE");
        claims.put("personal_administrative_number", "HYGIENE-PAN-0001");
        return claims;
    }

    private static Map<String, String[]> form(final String... pairs) {
        final Map<String, String[]> form = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            form.put(pairs[i], new String[] {pairs[i + 1]});
        }
        return form;
    }

    private static String responseId(final Oid4vpWalletClient.VerifiedRequest request) {
        return request.responseUri().substring(request.responseUri().lastIndexOf('/') + 1);
    }

    /** Everything a happy-path login must never leak into the logs, collected while it runs. */
    private record Secrets(List<String> pidValues, String nonce, String issuerJwtFragment,
            String disclosureFragment, String ephemeralJwkD, String holderJwkD, String pepperHex) {

        void assertAbsentFrom(final String text) {
            for (final String pid : pidValues) {
                assertThat(text).as("PID value '%s'", pid).doesNotContain(pid);
            }
            assertThat(text).as("nonce").doesNotContain(nonce);
            assertThat(text).as("vp_token issuer-JWT fragment").doesNotContain(issuerJwtFragment);
            assertThat(text).as("vp_token disclosure fragment").doesNotContain(disclosureFragment);
            assertThat(text).as("ephemeral response-key d").doesNotContain(ephemeralJwkD);
            assertThat(text).as("holder key d").doesNotContain(holderJwkD);
            assertThat(text).as("wallet pepper").doesNotContain(pepperHex);
        }
    }

    /** The presentation actually submitted, plus every secret it (and the transaction) carries. */
    private record Presentation(String raw, Secrets secrets) {
    }

    /** Builds exactly ONE presentation of {@link #pid()} — the same string is both asserted-against and submitted. */
    private Presentation present(final Oid4vpWalletClient.VerifiedRequest request, final WalletTransaction tx)
            throws java.text.ParseException {
        final Instant now = Instant.now();
        final TestWallet.SdJwtCredential credential = WALLET.sdJwtPid(pid(), now.minusSeconds(60),
                now.plusSeconds(3600), Optional.empty());
        final String presentation = WALLET.present(credential, pid().keySet(), request.clientId(), request.nonce());
        final String[] parts = presentation.split("~");
        // "DE" (issuing_country) is deliberately left out: two characters are too short to assert "never appears
        // anywhere in the whole log" without false positives (e.g. inside an unrelated base64/hex id).
        final Secrets secrets = new Secrets(List.of("Hygiene-Erika", "Hygiene-Mustermann", "1984-01-26",
                "HYGIENE-PAN-0001"), request.nonce(), parts[0].substring(0, 20), parts[1].substring(0, 20),
                ECKey.parse(tx.encryptionJwkJson()).getD().toString(),
                ((ECKey) WALLET.holderKey()).getD().toString(), HexFormat.of().formatHex(pepperBytes));
        return new Presentation(presentation, secrets);
    }

    @Test
    void sameDevice_happyPath_leaksNothing() throws Exception {
        try (FullCapture logs = new FullCapture()) {
            final WalletIdentityProvider provider = provider();
            final Oid4vpWalletClient.VerifiedRequest request = fetched(provider, WalletTransaction.Flow.SAME_DEVICE);
            final Presentation presentation = present(request, tx());

            final WalletResponseHandler.Result result = handler.handle(provider, REALM, responseId(request),
                    form("response", Oid4vpWalletClient.respond(request,
                            Map.of("pid_sd_jwt", List.of(presentation.raw())))));
            assertThat(result).isInstanceOf(WalletResponseHandler.Result.Accepted.class);
            final String subjectHash = VerifiedIdentityJson.readLogin(ALIAS, tx().verifiedIdentityJson())
                    .identity().externalSubject();
            final String code = ((WalletResponseHandler.Result.Accepted) result).redirectUri()
                    .replaceAll(".*response_code=", "");

            provider.callback(new IdentityProvider.CallbackContext(REALM,
                    Map.of(WalletIdentityProvider.RESPONSE_CODE_PARAM, code), HELIX_STATE, null, null, null,
                    BINDING));

            presentation.secrets().assertAbsentFrom(logs.text());
            assertThat(logs.text()).as("response_code").doesNotContain(code).as("subject hash")
                    .doesNotContain(subjectHash);
        }
    }

    @Test
    void crossDevice_happyPath_leaksNothing() throws Exception {
        try (FullCapture logs = new FullCapture()) {
            final WalletIdentityProvider provider = provider();
            final Oid4vpWalletClient.VerifiedRequest request = fetched(provider, WalletTransaction.Flow.CROSS_DEVICE);
            final WalletTransaction tx = tx();
            final Presentation presentation = present(request, tx);

            final WalletResponseHandler.Result result = handler.handle(provider, REALM, responseId(request),
                    form("response", Oid4vpWalletClient.respond(request,
                            Map.of("pid_sd_jwt", List.of(presentation.raw())))));
            assertThat(result).isEqualTo(new WalletResponseHandler.Result.Accepted(null));
            final String subjectHash = VerifiedIdentityJson.readLogin(ALIAS, tx().verifiedIdentityJson())
                    .identity().externalSubject();
            final String code = store.issueResponseCode(tx.transactionId(), BINDING).orElseThrow();

            provider.callback(new IdentityProvider.CallbackContext(REALM,
                    Map.of(WalletIdentityProvider.RESPONSE_CODE_PARAM, code), HELIX_STATE, null, null, null,
                    BINDING));

            presentation.secrets().assertAbsentFrom(logs.text());
            assertThat(logs.text()).as("response_code").doesNotContain(code).as("subject hash")
                    .doesNotContain(subjectHash);
        }
    }

    @Test
    void failurePath_leaksNothing() throws Exception {
        try (FullCapture logs = new FullCapture()) {
            final WalletIdentityProvider provider = provider();
            final Oid4vpWalletClient.VerifiedRequest request = fetched(provider, WalletTransaction.Flow.CROSS_DEVICE);
            final WalletTransaction tx = tx();
            final String nonce = request.nonce();
            final String ephemeralD = ECKey.parse(tx.encryptionJwkJson()).getD().toString();

            final WalletResponseHandler.Result result = handler.handle(provider, REALM, responseId(request),
                    form("error", "access_denied", "state", request.state()));

            assertThat(result).isEqualTo(new WalletResponseHandler.Result.WalletErrorRecorded());
            assertThat(logs.text()).as("nonce").doesNotContain(nonce).as("ephemeral response-key d")
                    .doesNotContain(ephemeralD).as("wallet pepper")
                    .doesNotContain(HexFormat.of().formatHex(pepperBytes));
        }
    }
}
