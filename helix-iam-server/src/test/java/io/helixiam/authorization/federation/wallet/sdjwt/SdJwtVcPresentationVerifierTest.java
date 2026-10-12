/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.sdjwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.Curve;
import io.helixiam.authorization.federation.wallet.VerificationContext;
import io.helixiam.authorization.federation.wallet.VerifiedPresentation;
import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.status.StatusEvaluator;
import io.helixiam.authorization.federation.wallet.status.StatusPolicy;
import io.helixiam.authorization.federation.wallet.status.StatusReference;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki.KeyType;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki.Leaf;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet.KeyBinding;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet.SdJwtCredential;
import io.helixiam.authorization.federation.wallet.trust.IssuerTrustValidator;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors.RevocationMode;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link SdJwtVcPresentationVerifier}: every check of RFC 9901 §7.1/§7.3 and SD-JWT VC (docs/eudi-wallet-spec-notes.md
 * §3, §4) has a positive and at least one negative test. Credentials come from {@link TestWallet}; each negative test
 * changes exactly one thing in an otherwise valid presentation.
 */
class SdJwtVcPresentationVerifierTest {

    private static final String CLIENT_ID = "x509_san_dns:verifier.example";
    private static final String NONCE = "n-0S6_WzA2Mj";
    private static final StatusReference STATUS_REF = new StatusReference(42, "https://status.example/lists/1");

    private static TestWallet wallet;
    private static TrustAnchors anchors;

    private final AtomicReference<StatusReference> evaluated = new AtomicReference<>();
    private StatusEvaluator status = (ref, a) -> {
        evaluated.set(ref);
        return StatusEvaluator.VALID;
    };

    @BeforeAll
    static void setUp() {
        wallet = TestWallet.create();
        anchors = wallet.pki().trustAnchors(RevocationMode.OFF);
    }

    // ------------------------------------------------------------------------------------------- fixtures

    private static Map<String, Object> pidClaims() {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Erika");
        claims.put("family_name", "Mustermann");
        claims.put("birthdate", "1964-08-12");
        claims.put("nationalities", List.of("DE"));
        claims.put("address", Map.of("locality", "Berlin", "country", "DE"));
        claims.put("personal_administrative_number", "PAN-0001");
        return claims;
    }

    private static SdJwtCredential pid(final TestWallet w) {
        final Instant now = Instant.now();
        return w.sdJwtPid(pidClaims(), now.minusSeconds(3600), now.plus(Duration.ofDays(30)), Optional.of(STATUS_REF));
    }

    private static String presentAll(final TestWallet w, final SdJwtCredential cred) {
        return w.present(cred, pidClaims().keySet(), CLIENT_ID, NONCE);
    }

    private static VerificationContext context() {
        return context(Instant.now(), false, false, Set.of(TestWallet.PID_VCT));
    }

    private static VerificationContext context(final Instant now, final boolean statusRequired,
            final boolean allowLegacyTyp, final Set<String> vcts) {
        return new VerificationContext(CLIENT_ID, NONCE, "https://verifier.example/wallet/response", null, now,
                Duration.ofSeconds(60), anchors,
                new StatusPolicy(statusRequired, StatusPolicy.OnUnavailable.FAIL_CLOSED, Duration.ofSeconds(900),
                        List.of()),
                vcts, null, allowLegacyTyp);
    }

    private SdJwtVcPresentationVerifier verifier() {
        return new SdJwtVcPresentationVerifier(new IssuerTrustValidator(), status);
    }

    private VerifiedPresentation verify(final String presentation) {
        return verifier().verify(presentation, context());
    }

    private void assertRejected(final String presentation, final VerificationContext ctx, final WalletErrorCode code) {
        assertThatThrownBy(() -> verifier().verify(presentation, ctx))
                .isInstanceOf(WalletVerificationException.class)
                .satisfies(e -> assertThat(((WalletVerificationException) e).code()).isEqualTo(code));
    }

    private void assertRejected(final String presentation, final WalletErrorCode code) {
        assertRejected(presentation, context(), code);
    }

    /** Replaces the issuer payload but keeps header and signature: an attacker's edit. */
    private static String withIssuerPayload(final String issuerJwt, final String payloadJson) {
        final String[] parts = issuerJwt.split("\\.");
        return parts[0] + "." + TestWallet.b64url(payloadJson) + "." + parts[2];
    }

    private static String payloadJson(final String jwt) {
        return new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8);
    }

    /** A JWS with an arbitrary header JSON, the given payload and an opaque (non-empty) signature. */
    private static String unsignedJws(final String headerJson, final String payloadJson) {
        return TestWallet.b64url(headerJson) + "." + TestWallet.b64url(payloadJson) + "."
                + TestWallet.b64url(new byte[64]);
    }

    // ------------------------------------------------------------------------------------------- positive

    @Test
    void formatIsDcSdJwt() {
        assertThat(verifier().format()).isEqualTo("dc+sd-jwt");
    }

    @Test
    void fullPidWithEs256IsVerified() {
        final SdJwtCredential cred = pid(wallet);

        final VerifiedPresentation result = verify(presentAll(wallet, cred));

        assertThat(result.format()).isEqualTo("dc+sd-jwt");
        assertThat(result.claims()).containsOnlyKeys(pidClaims().keySet().toArray(String[]::new));
        assertThat(result.claims()).containsEntry("given_name", "Erika")
                .containsEntry("nationalities", List.of("DE"))
                .containsEntry("address", Map.of("locality", "Berlin", "country", "DE"));
        assertThat(result.issuerSubjectDn())
                .isEqualTo(wallet.issuer().certificate().getSubjectX500Principal().getName());
        assertThat(result.issuerSerialHex()).isEqualTo(wallet.issuer().certificate().getSerialNumber().toString(16));
        assertThat(result.statusResult()).isEqualTo("VALID");
        assertThat(evaluated.get()).isEqualTo(STATUS_REF);
    }

    @Test
    void outputDropsStructuralAndMetadataClaims() {
        final TestWallet w = wallet.withPayloadClaim("nbf", Instant.now().minusSeconds(10).getEpochSecond())
                .withPayloadClaim("aka_vcts", List.of("urn:other:1"));
        final Map<String, Object> claims = verify(presentAll(w, pid(w))).claims();

        assertThat(claims).doesNotContainKeys("_sd", "_sd_alg", "cnf", "status", "iss", "vct", "iat", "nbf", "exp",
                "aka_vcts", "vct#integrity");
    }

    @Test
    void undisclosedClaimsAreAbsent() {
        final SdJwtCredential cred = pid(wallet);

        final VerifiedPresentation result = verify(wallet.present(cred, Set.of("given_name"), CLIENT_ID, NONCE));

        assertThat(result.claims()).containsOnlyKeys("given_name");
    }

    @Test
    void es384IssuerAndHolderAreVerified() {
        final Leaf p384 = wallet.pki().issueLeaf(TestPki.LeafSpec.defaults().withKeyType(KeyType.EC_P384));
        final TestWallet w = wallet.withIssuer(p384, JWSAlgorithm.ES384).withHolderKey(TestWallet.ecKey(Curve.P_384));

        assertThat(verify(presentAll(w, pid(w))).issuerSerialHex())
                .isEqualTo(p384.certificate().getSerialNumber().toString(16));
    }

    @Test
    void ps256WithRsa2048IssuerIsVerified() {
        final Leaf rsa = wallet.pki().issueLeaf(TestPki.LeafSpec.defaults().withKeyType(KeyType.RSA_2048));
        final TestWallet w = wallet.withIssuer(rsa, JWSAlgorithm.PS256);

        assertThat(verify(presentAll(w, pid(w))).claims()).containsKey("given_name");
    }

    @Test
    void sdAlgSha384IsUsedForDigestsAndSdHash() {
        final TestWallet w = wallet.withSdAlg("sha-384");

        assertThat(verify(presentAll(w, pid(w))).claims()).containsKey("family_name");
    }

    @Test
    void validityIsCheckedAgainstContextNowNotTheClock() {
        final Instant past = Instant.now().minus(Duration.ofHours(2));
        final SdJwtCredential cred = wallet.sdJwtPid(pidClaims(), past.minusSeconds(60), past.plusSeconds(600),
                Optional.empty());
        final String vp = wallet.present(cred, Set.of("given_name"),
                KeyBinding.of(CLIENT_ID, NONCE).withIat(past.minusSeconds(5)));

        assertThat(verifier().verify(vp, context(past, false, false, Set.of(TestWallet.PID_VCT))).claims())
                .containsKey("given_name");
        assertRejected(vp, WalletErrorCode.CREDENTIAL_EXPIRED);
    }

    // ------------------------------------------------------------------------------------------- typ

    @Test
    void legacyVcSdJwtTypIsRefusedWhenTheFlagIsOff() {
        final TestWallet w = wallet.withTyp("vc+sd-jwt");

        assertRejected(presentAll(w, pid(w)), WalletErrorCode.UNSUPPORTED_FORMAT);
    }

    @Test
    void legacyVcSdJwtTypIsAcceptedWhenTheFlagIsOn() {
        final TestWallet w = wallet.withTyp("vc+sd-jwt");

        assertThat(verifier().verify(presentAll(w, pid(w)),
                context(Instant.now(), false, true, Set.of(TestWallet.PID_VCT))).claims()).isNotEmpty();
    }

    @Test
    void otherOrMissingTypIsRefused() {
        assertRejected(presentAll(wallet.withTyp("example+sd-jwt"), pid(wallet.withTyp("example+sd-jwt"))),
                WalletErrorCode.UNSUPPORTED_FORMAT);
        assertRejected(presentAll(wallet.withTyp(null), pid(wallet.withTyp(null))),
                WalletErrorCode.UNSUPPORTED_FORMAT);
    }

    // ------------------------------------------------------------------------------------------- alg

    @Test
    void algNoneIsRefused() {
        final SdJwtCredential cred = pid(wallet);
        final String forged = unsignedJws("{\"alg\":\"none\",\"typ\":\"dc+sd-jwt\"}", payloadJson(cred.issuerJwt()));

        assertRejected(presentAll(wallet, cred.withIssuerJwt(forged)), WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void algHs256IsRefused() throws Exception {
        final SdJwtCredential cred = pid(wallet);
        final JWSObject hmac = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(new com.nimbusds.jose.JOSEObjectType("dc+sd-jwt")).build(),
                new Payload(payloadJson(cred.issuerJwt())));
        hmac.sign(new MACSigner(new byte[32]));

        assertRejected(presentAll(wallet, cred.withIssuerJwt(hmac.serialize())), WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void rs256IsRefusedEvenWithAnAcceptableRsaKey() {
        final Leaf rsa = wallet.pki().issueLeaf(TestPki.LeafSpec.defaults().withKeyType(KeyType.RSA_2048));
        final TestWallet w = wallet.withIssuer(rsa, JWSAlgorithm.RS256);

        assertRejected(presentAll(w, pid(w)), WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void algThatDoesNotMatchTheCertificateKeyIsRefused() {
        final Leaf p256 = wallet.issuer();
        final Leaf p384 = wallet.pki().issueLeaf(TestPki.LeafSpec.defaults().withKeyType(KeyType.EC_P384));
        // Signed with the P-384 key as ES384, but the x5c leaf is the P-256 certificate.
        final TestWallet signer = wallet.withIssuer(new Leaf(p256.certificate(), p384.privateKey(), p256.chain()),
                JWSAlgorithm.ES384);

        assertRejected(presentAll(signer, pid(signer)), WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    // ------------------------------------------------------------------------------------------- trust + signature

    @Test
    void untrustedChainIsRefused() {
        final TestWallet other = TestWallet.create(); // its own PKI, not in the configured anchors

        assertRejected(presentAll(other, pid(other)), WalletErrorCode.ISSUER_UNTRUSTED);
    }

    @Test
    void missingX5cIsRefused() {
        final TestWallet w = wallet.withoutX5c();

        assertRejected(presentAll(w, pid(w)), WalletErrorCode.ISSUER_UNTRUSTED);
    }

    @Test
    void tamperedIssuerPayloadFailsTheSignature() {
        final SdJwtCredential cred = pid(wallet);
        final String tampered = withIssuerPayload(cred.issuerJwt(),
                payloadJson(cred.issuerJwt()).replace("\"" + TestWallet.ISSUER + "\"", "\"https://evil.example\""));

        assertRejected(presentAll(wallet, cred.withIssuerJwt(tampered)), WalletErrorCode.ISSUER_SIGNATURE_INVALID);
    }

    @Test
    void signatureByAnotherKeyIsRefused() {
        final Leaf other = wallet.pki().issueLeaf(TestPki.LeafSpec.defaults());
        final TestWallet w = wallet.withIssuer(
                new Leaf(wallet.issuer().certificate(), other.privateKey(), wallet.issuer().chain()),
                JWSAlgorithm.ES256);

        assertRejected(presentAll(w, pid(w)), WalletErrorCode.ISSUER_SIGNATURE_INVALID);
    }

    @Test
    void duplicateKeyInIssuerPayloadIsRefused() {
        final SdJwtCredential cred = pid(wallet);
        // A correctly signed payload that says "vct" twice: Nimbus would keep the last (accepted) one.
        final String payload = payloadJson(cred.issuerJwt()).replaceFirst("\\{", "{\"vct\":\"urn:evil:1\",");
        final String jwt = wallet.signIssuerJwt(payload);

        assertRejected(presentAll(wallet, cred.withIssuerJwt(jwt)), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void critHeaderIsRefused() throws Exception {
        final SdJwtCredential cred = pid(wallet);
        final List<com.nimbusds.jose.util.Base64> x5c = new java.util.ArrayList<>();
        for (final java.security.cert.X509Certificate c : wallet.issuer().chain()) {
            x5c.add(com.nimbusds.jose.util.Base64.encode(c.getEncoded()));
        }
        final JWSObject jws = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new com.nimbusds.jose.JOSEObjectType("dc+sd-jwt")).x509CertChain(x5c)
                .customParam("ext", "x").criticalParams(Set.of("ext")).build(),
                new Payload(payloadJson(cred.issuerJwt())));
        jws.sign(new com.nimbusds.jose.crypto.ECDSASigner(
                (java.security.interfaces.ECPrivateKey) wallet.issuer().privateKey()));

        assertRejected(presentAll(wallet, cred.withIssuerJwt(jws.serialize())), WalletErrorCode.INVALID_RESPONSE);
    }

    // ------------------------------------------------------------------------------------------- iss / vct / time

    @Test
    void issIsOptional() {
        final TestWallet w = wallet.withPayloadClaim("iss", null);

        assertThat(verify(presentAll(w, pid(w))).claims()).containsKey("given_name");
    }

    @Test
    void nonStringIssIsRefused() {
        final TestWallet w = wallet.withPayloadClaim("iss", 7);

        assertRejected(presentAll(w, pid(w)), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void vctNotAcceptedIsRefused() {
        final TestWallet w = wallet.withVct("urn:eudi:pid:xx:1");

        assertRejected(presentAll(w, pid(w)), WalletErrorCode.VCT_NOT_ACCEPTED);
    }

    @Test
    void missingVctIsRefused() {
        final TestWallet w = wallet.withVct(null);

        assertRejected(presentAll(w, pid(w)), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void nationalVctInTheAcceptedSetIsAccepted() {
        final TestWallet w = wallet.withVct("urn:eudi:pid:de:1");

        assertThat(verifier().verify(presentAll(w, pid(w)),
                context(Instant.now(), false, false, Set.of(TestWallet.PID_VCT, "urn:eudi:pid:de:1"))).claims())
                .isNotEmpty();
    }

    @Test
    void akaVctInTheAcceptedSetIsAccepted() {
        final TestWallet w = wallet.withVct("urn:eudi:pid:xx:1").withPayloadClaim("aka_vcts", List.of(TestWallet.PID_VCT));

        assertThat(verify(presentAll(w, pid(w))).claims()).isNotEmpty();
    }

    @Test
    void credentialTypeIsTheVct() {
        assertThat(verify(presentAll(wallet, pid(wallet))).credentialType()).isEqualTo(TestWallet.PID_VCT);
    }

    @Test
    void nationalVctInTheAcceptedSetIsTheCredentialType() {
        final TestWallet w = wallet.withVct("urn:eudi:pid:de:1");

        assertThat(verifier().verify(presentAll(w, pid(w)),
                context(Instant.now(), false, false, Set.of(TestWallet.PID_VCT, "urn:eudi:pid:de:1")))
                .credentialType()).isEqualTo("urn:eudi:pid:de:1");
    }

    @Test
    void whenBothVctAndAnAkaVctAreAcceptedTheVctIsTheCredentialType() {
        final TestWallet w = wallet.withVct("urn:eudi:pid:de:1").withPayloadClaim("aka_vcts", List.of(TestWallet.PID_VCT));

        assertThat(verifier().verify(presentAll(w, pid(w)),
                context(Instant.now(), false, false, Set.of(TestWallet.PID_VCT, "urn:eudi:pid:de:1")))
                .credentialType()).isEqualTo("urn:eudi:pid:de:1");
    }

    @Test
    void credentialAcceptedThroughAkaVctsHasTheAcceptedAkaVctAsCredentialType() {
        final TestWallet w = wallet.withVct("urn:eudi:pid:xx:1")
                .withPayloadClaim("aka_vcts", List.of("urn:other:1", TestWallet.PID_VCT));

        assertThat(verify(presentAll(w, pid(w))).credentialType()).isEqualTo(TestWallet.PID_VCT);
    }

    @Test
    void expiredCredentialIsRefused() {
        final Instant now = Instant.now();
        final SdJwtCredential cred = wallet.sdJwtPid(pidClaims(), now.minusSeconds(7200), now.minusSeconds(61),
                Optional.empty());

        assertRejected(presentAll(wallet, cred), WalletErrorCode.CREDENTIAL_EXPIRED);
    }

    @Test
    void expiryWithinTheSkewIsAccepted() {
        final Instant now = Instant.now();
        final SdJwtCredential cred = wallet.sdJwtPid(pidClaims(), now.minusSeconds(7200), now.minusSeconds(30),
                Optional.empty());

        assertThat(verify(presentAll(wallet, cred)).claims()).isNotEmpty();
    }

    @Test
    void nbfInTheFutureBeyondTheSkewIsRefused() {
        final TestWallet w = wallet.withPayloadClaim("nbf", Instant.now().plusSeconds(120).getEpochSecond());

        assertRejected(presentAll(w, pid(w)), WalletErrorCode.CREDENTIAL_NOT_YET_VALID);
    }

    @Test
    void nbfWithinTheSkewIsAccepted() {
        final TestWallet w = wallet.withPayloadClaim("nbf", Instant.now().plusSeconds(30).getEpochSecond());

        assertThat(verify(presentAll(w, pid(w))).claims()).isNotEmpty();
    }

    @Test
    void issuerIatInTheFutureBeyondTheSkewIsRefused() {
        final Instant now = Instant.now();
        final SdJwtCredential cred = wallet.sdJwtPid(pidClaims(), now.plusSeconds(600), now.plus(Duration.ofDays(1)),
                Optional.empty());

        assertRejected(presentAll(wallet, cred), WalletErrorCode.CREDENTIAL_NOT_YET_VALID);
    }

    @Test
    void nonNumericNbfIsRefused() {
        final TestWallet w = wallet.withPayloadClaim("nbf", "yesterday");

        assertRejected(presentAll(w, pid(w)), WalletErrorCode.INVALID_RESPONSE);
    }

    // ------------------------------------------------------------------------------------------- disclosures

    @Test
    void selectivelyDisclosedExpIsRefused() {
        final Map<String, Object> claims = new LinkedHashMap<>(pidClaims());
        claims.put("exp", Instant.now().plus(Duration.ofDays(3650)).getEpochSecond());
        final SdJwtCredential cred = wallet.sdJwtPid(claims, Instant.now().minusSeconds(60), null, Optional.empty());

        assertRejected(wallet.present(cred, claims.keySet(), CLIENT_ID, NONCE), WalletErrorCode.DISCLOSURE_INVALID);
    }

    @Test
    void disclosedSdAlgNeverReachesTheOutput() {
        final Map<String, Object> claims = new LinkedHashMap<>(pidClaims());
        claims.put("_sd_alg", "sha-256");
        final SdJwtCredential cred = wallet.sdJwtPid(claims, Instant.now().minusSeconds(60),
                Instant.now().plus(Duration.ofDays(1)), Optional.empty());

        assertThat(verify(wallet.present(cred, claims.keySet(), CLIENT_ID, NONCE)).claims())
                .doesNotContainKey("_sd_alg").containsKey("given_name");
    }

    @Test
    void unreferencedDisclosureIsRefused() {
        final SdJwtCredential cred = pid(wallet);
        final SdJwtCredential other = pid(wallet);
        final Map<String, String> mixed = new LinkedHashMap<>(cred.disclosures());
        mixed.put("foreign", other.disclosures().get("given_name"));
        final SdJwtCredential bad = new SdJwtCredential(cred.issuerJwt(), mixed, cred.holderKey());

        assertRejected(wallet.present(bad, Set.of("given_name", "foreign"), CLIENT_ID, NONCE),
                WalletErrorCode.DISCLOSURE_INVALID);
    }

    // ------------------------------------------------------------------------------------------- key binding

    @Test
    void missingKbJwtIsHolderBindingMissing() {
        final SdJwtCredential cred = pid(wallet);

        assertRejected(wallet.presentWithoutKeyBinding(cred, Set.of("given_name")),
                WalletErrorCode.HOLDER_BINDING_MISSING);
    }

    @Test
    void credentialWithoutCnfIsHolderBindingMissing() {
        final TestWallet w = wallet.withoutCnf();

        assertRejected(presentAll(w, pid(w)), WalletErrorCode.HOLDER_BINDING_MISSING);
    }

    @Test
    void cnfJwkWithPrivateKeyMaterialIsHolderBindingInvalid() {
        final TestWallet w = wallet.withoutCnf()
                .withPayloadClaim("cnf", Map.of("jwk", wallet.holderKey().toJSONObject()));

        assertRejected(presentAll(w, pid(w)), WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void cnfJwkWithKtyOctIsHolderBindingInvalid() {
        final String k = TestWallet.b64url(new byte[32]);
        final TestWallet w = wallet.withoutCnf().withPayloadClaim("cnf", Map.of("jwk", Map.of("kty", "oct", "k", k)));

        assertRejected(presentAll(w, pid(w)), WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void arrayDigestInsideCnfIsDisclosureInvalid() {
        final Map<String, Object> cnf = new LinkedHashMap<>();
        cnf.put("jwk", wallet.holderKey().toPublicJWK().toJSONObject());
        cnf.put("alt", List.of(Map.of("...", TestWallet.digest(TestWallet.disclosure("x", "y"), "sha-256"))));
        final TestWallet w = wallet.withoutCnf().withPayloadClaim("cnf", cnf);

        assertRejected(presentAll(w, pid(w)), WalletErrorCode.DISCLOSURE_INVALID);
    }

    @Test
    void kbSignedByAnotherKeyIsHolderBindingInvalid() {
        final SdJwtCredential cred = pid(wallet);
        final String vp = wallet.present(cred, Set.of("given_name"),
                KeyBinding.of(CLIENT_ID, NONCE).withSigningKey(TestWallet.ecKey(Curve.P_256)));

        assertRejected(vp, WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void kbAlgThatDoesNotMatchTheCnfKeyIsHolderBindingInvalid() {
        final SdJwtCredential cred = pid(wallet);
        // Holder key is P-256; signed with a P-384 key as ES384.
        final String vp = wallet.present(cred, Set.of("given_name"),
                KeyBinding.of(CLIENT_ID, NONCE).withSigningKey(TestWallet.ecKey(Curve.P_384)));

        assertRejected(vp, WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void kbWithWrongTypIsHolderBindingInvalid() {
        final SdJwtCredential cred = pid(wallet);

        assertRejected(wallet.present(cred, Set.of("given_name"), KeyBinding.of(CLIENT_ID, NONCE).withTyp("JWT")),
                WalletErrorCode.HOLDER_BINDING_INVALID);
        assertRejected(wallet.present(cred, Set.of("given_name"), KeyBinding.of(CLIENT_ID, NONCE).withTyp(null)),
                WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void kbWithHs256IsRefused() {
        final SdJwtCredential cred = pid(wallet);
        final String sdJwt = wallet.presentWithoutKeyBinding(cred, Set.of("given_name"));
        final String kb = unsignedJws("{\"alg\":\"HS256\",\"typ\":\"kb+jwt\"}", "{\"iat\":"
                + Instant.now().getEpochSecond() + ",\"aud\":\"" + CLIENT_ID + "\",\"nonce\":\"" + NONCE
                + "\",\"sd_hash\":\"" + TestWallet.digest(sdJwt, "sha-256") + "\"}");

        assertRejected(sdJwt + kb, WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void wrongAudienceIsAudienceMismatch() {
        final SdJwtCredential cred = pid(wallet);

        assertRejected(wallet.present(cred, Set.of("given_name"), "x509_san_dns:other.example", NONCE),
                WalletErrorCode.AUDIENCE_MISMATCH);
    }

    @Test
    void audienceArrayIsAudienceMismatch() {
        final SdJwtCredential cred = pid(wallet);

        assertRejected(wallet.present(cred, Set.of("given_name"),
                KeyBinding.of(CLIENT_ID, NONCE).withAud(List.of(CLIENT_ID))), WalletErrorCode.AUDIENCE_MISMATCH);
    }

    @Test
    void wrongNonceIsNonceMismatch() {
        final SdJwtCredential cred = pid(wallet);

        assertRejected(wallet.present(cred, Set.of("given_name"), CLIENT_ID, "another-nonce"),
                WalletErrorCode.NONCE_MISMATCH);
        assertThat(evaluated.get()).as("status is checked only after holder binding").isNull();
    }

    @Test
    void staleKbIatIsHolderBindingInvalid() {
        final SdJwtCredential cred = pid(wallet);
        final Instant stale = Instant.now().minus(SdJwtVcPresentationVerifier.DEFAULT_KB_MAX_AGE).minusSeconds(61);

        assertRejected(wallet.present(cred, Set.of("given_name"), KeyBinding.of(CLIENT_ID, NONCE).withIat(stale)),
                WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void kbIatJustInsideTheMaxAgeIsAccepted() {
        final SdJwtCredential cred = pid(wallet);
        final Instant old = Instant.now().minus(SdJwtVcPresentationVerifier.DEFAULT_KB_MAX_AGE).plusSeconds(30);

        assertThat(verify(wallet.present(cred, Set.of("given_name"), KeyBinding.of(CLIENT_ID, NONCE).withIat(old)))
                .claims()).containsKey("given_name");
    }

    @Test
    void futureKbIatBeyondTheSkewIsHolderBindingInvalid() {
        final SdJwtCredential cred = pid(wallet);

        assertRejected(wallet.present(cred, Set.of("given_name"),
                KeyBinding.of(CLIENT_ID, NONCE).withIat(Instant.now().plusSeconds(120))),
                WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void missingKbIatIsHolderBindingInvalid() {
        final SdJwtCredential cred = pid(wallet);
        final String raw = "{\"aud\":\"" + CLIENT_ID + "\",\"nonce\":\"" + NONCE + "\",\"sd_hash\":\"%SD_HASH%\"}";

        assertRejected(wallet.present(cred, Set.of("given_name"), KeyBinding.of(CLIENT_ID, NONCE).withRawPayload(raw)),
                WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void wrongSdHashIsHolderBindingInvalid() {
        final SdJwtCredential cred = pid(wallet);

        assertRejected(wallet.present(cred, Set.of("given_name"),
                KeyBinding.of(CLIENT_ID, NONCE).withSdHash(TestWallet.digest("something else~", "sha-256"))),
                WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void sdHashOverFewerDisclosuresThanPresentedIsHolderBindingInvalid() {
        final SdJwtCredential cred = pid(wallet);
        final String bound = wallet.present(cred, Set.of("given_name"), CLIENT_ID, NONCE);
        // Insert another (genuine) disclosure after the KB-JWT was signed.
        final int cut = bound.lastIndexOf('~') + 1;
        final String injected = bound.substring(0, cut) + cred.disclosures().get("birthdate") + "~"
                + bound.substring(cut);

        assertRejected(injected, WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void sdHashMustUseTheSdAlgNotSha256() {
        final TestWallet w = wallet.withSdAlg("sha-384");
        final SdJwtCredential cred = pid(w);

        assertRejected(w.present(cred, Set.of("given_name"), KeyBinding.of(CLIENT_ID, NONCE).withSdHashAlg("sha-256")),
                WalletErrorCode.HOLDER_BINDING_INVALID);
    }

    @Test
    void duplicateKeyInKbPayloadIsRefused() {
        final SdJwtCredential cred = pid(wallet);
        // Signed by the holder; "nonce" twice, the last one being the expected value.
        final String raw = "{\"iat\":" + Instant.now().getEpochSecond() + ",\"aud\":\"" + CLIENT_ID
                + "\",\"nonce\":\"stolen\",\"nonce\":\"" + NONCE + "\",\"sd_hash\":\"%SD_HASH%\"}";

        assertRejected(wallet.present(cred, Set.of("given_name"), KeyBinding.of(CLIENT_ID, NONCE).withRawPayload(raw)),
                WalletErrorCode.INVALID_RESPONSE);
    }

    // ------------------------------------------------------------------------------------------- status

    @Test
    void revokedStatusIsCredentialRevoked() {
        status = (ref, a) -> {
            throw new WalletVerificationException(WalletErrorCode.CREDENTIAL_REVOKED, "revoked");
        };

        assertRejected(presentAll(wallet, pid(wallet)), WalletErrorCode.CREDENTIAL_REVOKED);
    }

    @Test
    void statusEvaluatorReceivesTheConfiguredAnchors() {
        final AtomicReference<TrustAnchors> seen = new AtomicReference<>();
        status = (ref, a) -> {
            seen.set(a);
            return StatusEvaluator.VALID;
        };

        verify(presentAll(wallet, pid(wallet)));

        assertThat(seen.get()).isSameAs(anchors);
    }

    @Test
    void anythingButValidFromTheEvaluatorIsStatusUnavailable() {
        status = (ref, a) -> "SUSPENDED";
        assertRejected(presentAll(wallet, pid(wallet)), WalletErrorCode.STATUS_UNAVAILABLE);

        status = (ref, a) -> {
            throw new IllegalStateException("boom");
        };
        assertRejected(presentAll(wallet, pid(wallet)), WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void absentStatusWhenRequiredIsStatusRequired() {
        final Instant now = Instant.now();
        final SdJwtCredential cred = wallet.sdJwtPid(pidClaims(), now.minusSeconds(60), now.plusSeconds(3600),
                Optional.empty());

        assertRejected(presentAll(wallet, cred), context(now, true, false, Set.of(TestWallet.PID_VCT)),
                WalletErrorCode.STATUS_REQUIRED);
    }

    @Test
    void absentStatusWhenNotRequiredIsAccepted() {
        final Instant now = Instant.now();
        final SdJwtCredential cred = wallet.sdJwtPid(pidClaims(), now.minusSeconds(60), now.plusSeconds(3600),
                Optional.empty());

        final VerifiedPresentation result = verify(presentAll(wallet, cred));

        assertThat(result.statusResult()).isEqualTo("ABSENT");
        assertThat(evaluated.get()).isNull();
    }

    /** A credential whose {@code status} claim is {@code statusValue}, presented with {@code extraDisclosures}. */
    private static String withStatus(final Object statusValue, final Map<String, String> extraDisclosures) {
        final TestWallet w = wallet.withPayloadClaim("status", statusValue);
        final Instant now = Instant.now();
        final SdJwtCredential cred = w.sdJwtPid(pidClaims(), now.minusSeconds(60), now.plusSeconds(3600),
                Optional.empty());
        final Map<String, String> disclosures = new LinkedHashMap<>(cred.disclosures());
        disclosures.putAll(extraDisclosures);
        final Set<String> disclose = new java.util.LinkedHashSet<>(pidClaims().keySet());
        disclose.addAll(extraDisclosures.keySet());
        return w.present(new SdJwtCredential(cred.issuerJwt(), disclosures, cred.holderKey()), disclose, CLIENT_ID,
                NONCE);
    }

    private static VerificationContext failOpenContext() {
        final VerificationContext c = context();
        return new VerificationContext(c.clientId(), c.nonce(), c.responseUri(), null, c.now(), c.clockSkew(),
                c.anchors(), new StatusPolicy(false, StatusPolicy.OnUnavailable.FAIL_OPEN_WITH_AUDIT,
                        Duration.ofSeconds(900), List.of()), c.acceptedVcts(), null, false);
    }

    @Test
    void selectivelyDisclosableStatusListOmittedByTheHolderIsDisclosureInvalid() {
        final String d = TestWallet.disclosure("status_list", Map.of("idx", 1, "uri", STATUS_REF.uri()));
        final Map<String, Object> status = Map.of("_sd", List.of(TestWallet.digest(d, "sha-256")));

        assertRejected(withStatus(status, Map.of()), WalletErrorCode.DISCLOSURE_INVALID);
        assertThat(evaluated.get()).isNull();
    }

    @Test
    void selectivelyDisclosedStatusListIsDisclosureInvalid() {
        final String d = TestWallet.disclosure("status_list", Map.of("idx", 1, "uri", STATUS_REF.uri()));
        final Map<String, Object> status = Map.of("_sd", List.of(TestWallet.digest(d, "sha-256")));

        assertRejected(withStatus(status, Map.of("status_list", d)), WalletErrorCode.DISCLOSURE_INVALID);
    }

    @Test
    void nestedSdDeepInsideStatusIsDisclosureInvalid() {
        final Map<String, Object> status = Map.of("status_list", Map.of("idx", 1, "uri", STATUS_REF.uri(),
                "ext", Map.of("_sd", List.of(TestWallet.digest(TestWallet.disclosure("a", "b"), "sha-256")))));

        assertRejected(withStatus(status, Map.of()), WalletErrorCode.DISCLOSURE_INVALID);
    }

    @Test
    void unknownStatusMechanismIsStatusUnavailableWhenFailClosed() {
        final String vp = withStatus(Map.of("other_mechanism", Map.of("id", 1)), Map.of());

        assertRejected(vp, WalletErrorCode.STATUS_UNAVAILABLE);
        assertRejected(withStatus(Map.of(), Map.of()), WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void unknownStatusMechanismIsAcceptedAndRecordedWhenFailOpen() {
        final String vp = withStatus(Map.of("other_mechanism", Map.of("id", 1)), Map.of());

        final VerifiedPresentation result = verifier().verify(vp, failOpenContext());

        assertThat(result.statusResult()).isEqualTo(SdJwtVcPresentationVerifier.STATUS_UNAVAILABLE_ACCEPTED)
                .isNotEqualTo(SdJwtVcPresentationVerifier.STATUS_ABSENT);
        assertThat(evaluated.get()).isNull();
    }

    @Test
    void unreachableEvaluatorFollowsFailOpenToo() {
        status = (ref, a) -> {
            throw new IllegalStateException("network down");
        };

        assertThat(verifier().verify(presentAll(wallet, pid(wallet)), failOpenContext()).statusResult())
                .isEqualTo(SdJwtVcPresentationVerifier.STATUS_UNAVAILABLE_ACCEPTED);
    }

    @Test
    void nonValidEvaluatorAnswerIsNeverAcceptedEvenWhenFailOpen() {
        status = (ref, a) -> "REVOKED";

        assertRejected(presentAll(wallet, pid(wallet)), failOpenContext(), WalletErrorCode.STATUS_UNAVAILABLE);
    }

    @Test
    void malformedStatusListReferenceIsRefused() {
        final TestWallet w = wallet.withPayloadClaim("status", Map.of("status_list", Map.of("idx", -1, "uri", "x")));
        final Instant now = Instant.now();
        final SdJwtCredential cred = w.sdJwtPid(pidClaims(), now.minusSeconds(60), now.plusSeconds(3600),
                Optional.empty());

        assertRejected(presentAll(w, cred), WalletErrorCode.INVALID_RESPONSE);
    }

    // ------------------------------------------------------------------------------------------- ordering

    @Test
    void untrustedIssuerIsReportedBeforeTheMissingKeyBinding() {
        final TestWallet other = TestWallet.create();

        assertRejected(other.presentWithoutKeyBinding(pid(other), Set.of("given_name")),
                WalletErrorCode.ISSUER_UNTRUSTED);
    }
}
