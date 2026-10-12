/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.service.key.RealmSigningKeys;
import io.helixiam.authorization.service.key.SigningKeyHandle;
import io.helixiam.common.startup.DeploymentProfile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Every {@link WalletConfigValidator} rule, each with a passing and a failing case. Configs are built through
 * {@link WalletProviderConfig#fromStored}, the console's path.
 */
class WalletConfigValidatorTest {

    private static final String REALM = "acme";
    private static final String KEY_REF = "software:acme/eudi-access";
    private static final String HOST = "verifier.example.eu";

    private static final TestPki PKI = TestPki.create("Access");
    private static final TestPki.Leaf ACCESS = PKI.issueLeaf(TestPki.LeafSpec.defaults()
            .withSubject("CN=Helix Verifier").withDnsNames("other.example.eu", HOST));
    private static final TestPki.Leaf OTHER = PKI.issueLeaf(TestPki.LeafSpec.defaults().withDnsNames(HOST));
    private static final TestPki ISSUERS = TestPki.create("PID Provider");

    private final RealmSigningKeys keys = new FakeKeys(ACCESS);
    private final WalletConfigValidator production = new WalletConfigValidator(keys, DeploymentProfile.production());
    private final WalletConfigValidator dev = new WalletConfigValidator(keys, DeploymentProfile.development());

    /** A valid production config: x509_hash, key ref, both formats, the PID-provider root as anchor. */
    private static Map<String, String> valid() {
        final Map<String, String> m = new HashMap<>();
        m.put("alias", "eudi-wallet");
        m.put("displayName", "EU Digital Identity Wallet");
        m.put("accessCertificateChain", pem(ACCESS.chain()));
        m.put("accessKeyRef", KEY_REF);
        m.put("trustAnchors", ISSUERS.rootPem());
        return m;
    }

    private Map<String, String> errors(final WalletConfigValidator validator, final Map<String, String> stored) {
        return validator.validate(REALM, WalletProviderConfig.fromStored(stored));
    }

    private Map<String, String> errorsWith(final String key, final String value) {
        final Map<String, String> m = valid();
        m.put(key, value);
        return errors(production, m);
    }

    @Test
    void validProductionConfig_hasNoErrors() {
        assertThat(errors(production, valid())).isEmpty();
    }

    @Test
    void requireValid_throwsWithEveryFieldMessage() {
        final Map<String, String> m = valid();
        m.put("transactionTtlSeconds", "5");
        m.put("credentialFormats", "[]");
        assertThatThrownBy(() -> production.requireValid(REALM, WalletProviderConfig.fromStored(m)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("eudi-wallet")
                .hasMessageContaining("transactionTtlSeconds")
                .hasMessageContaining("credentialFormats");
        production.requireValid(REALM, WalletProviderConfig.fromStored(valid()));
    }

    @Test
    void blankAlias_isRefused() {
        assertThat(errorsWith("alias", " ")).containsKey("alias");
    }

    // ------------------------------------------------------------------ client_id scheme / SAN

    @Test
    void sanDns_withHostInLeafSan_isAccepted() {
        final Map<String, String> m = valid();
        m.put("clientIdScheme", "x509_san_dns");
        m.put("clientIdHost", HOST.toUpperCase());
        assertThat(errors(production, m)).isEmpty();
    }

    @Test
    void sanDns_hostNotInLeafSan_isRefused() {
        final Map<String, String> m = valid();
        m.put("clientIdScheme", "X509_SAN_DNS");
        m.put("clientIdHost", "evil.example.eu");
        assertThat(errors(production, m)).containsEntry("clientIdHost",
                "clientIdHost must be a DNS subjectAltName of the access certificate (x509_san_dns)");
    }

    @Test
    void sanDns_withoutHost_isRefused() {
        final Map<String, String> m = valid();
        m.put("clientIdScheme", "x509_san_dns");
        assertThat(errors(production, m)).containsKey("clientIdHost");
    }

    @Test
    void x509Hash_ignoresTheSanRule() {
        final Map<String, String> m = valid();
        m.put("clientIdHost", "not-in-the-cert.example.eu");
        assertThat(errors(production, m)).isEmpty();
    }

    // ------------------------------------------------------------------ access certificate and key

    @Test
    void keyRef_withoutAConfiguredChain_usesTheKeysChain() {
        final Map<String, String> m = valid();
        m.remove("accessCertificateChain");
        assertThat(errors(production, m)).isEmpty();
    }

    @Test
    void devKey_withoutAConfiguredChain_isRefused() {
        final Map<String, String> m = valid();
        m.remove("accessCertificateChain");
        m.remove("accessKeyRef");
        m.put("accessCertificatePrivateKey", pkcs8Pem(ACCESS.privateKey()));
        assertThat(errors(dev, m)).containsKey("accessCertificateChain");
    }

    @Test
    void unparseableAccessCertificate_isRefused_withoutEchoingIt() {
        final Map<String, String> e = errorsWith("accessCertificateChain", "-----BEGIN CERTIFICATE-----\nAAAA\n");
        assertThat(e).containsKey("accessCertificateChain");
        assertThat(e.get("accessCertificateChain")).doesNotContain("AAAA");
    }

    @Test
    void selfSignedAccessCertificate_isRefused() {
        final TestPki.Leaf self = TestPki.selfSignedLeaf("CN=Self");
        final WalletConfigValidator v = new WalletConfigValidator(new FakeKeys(self), DeploymentProfile.production());
        final Map<String, String> m = valid();
        m.put("accessCertificateChain", pem(self.chain()));
        assertThat(v.validate(REALM, WalletProviderConfig.fromStored(m)))
                .containsEntry("accessCertificateChain", "The access certificate must not be self-signed (HAIP)");
    }

    @Test
    void expiredAccessCertificate_isRefused() {
        final Instant now = Instant.now();
        final TestPki.Leaf expired = PKI.issueLeaf(TestPki.LeafSpec.defaults()
                .withValidity(now.minus(Duration.ofDays(30)), now.minus(Duration.ofDays(1))));
        final WalletConfigValidator v = new WalletConfigValidator(new FakeKeys(expired), DeploymentProfile.production());
        final Map<String, String> m = valid();
        m.put("accessCertificateChain", pem(expired.chain()));
        assertThat(v.validate(REALM, WalletProviderConfig.fromStored(m)).get("accessCertificateChain"))
                .startsWith("The leaf certificate has expired");
    }

    @Test
    void notYetValidAccessCertificate_isRefused() {
        final Instant now = Instant.now();
        final TestPki.Leaf future = PKI.issueLeaf(TestPki.LeafSpec.defaults()
                .withValidity(now.plus(Duration.ofDays(1)), now.plus(Duration.ofDays(30))));
        final WalletConfigValidator v = new WalletConfigValidator(new FakeKeys(future), DeploymentProfile.production());
        final Map<String, String> m = valid();
        m.remove("accessCertificateChain"); // the key's own chain is checked too
        assertThat(v.validate(REALM, WalletProviderConfig.fromStored(m)).get("accessKeyRef"))
                .startsWith("The leaf certificate is not yet valid");
    }

    @Test
    void configuredChainDifferentFromTheKeysChain_isRefused() {
        final Map<String, String> m = valid();
        m.put("accessCertificateChain", pem(OTHER.chain()));
        assertThat(errors(production, m)).containsEntry("accessCertificateChain",
                "accessCertificateChain must equal the certificate chain of the key behind accessKeyRef");
        m.put("accessCertificateChain", TestPki.pem(ACCESS.certificate())); // leaf only: still not the same chain
        assertThat(errors(production, m)).containsKey("accessCertificateChain");
    }

    @Test
    void keyRefWhoseKeyDoesNotMatchItsChain_isRefused() {
        final WalletConfigValidator v = new WalletConfigValidator(new FakeKeys(ACCESS, OTHER.chain(), null),
                DeploymentProfile.production());
        final Map<String, String> m = valid();
        m.remove("accessCertificateChain");
        assertThat(v.validate(REALM, WalletProviderConfig.fromStored(m))).containsEntry("accessKeyRef",
                "The key behind accessKeyRef does not match the access certificate");
    }

    @Test
    void chainIncludingTheRoot_isRefused() {
        final List<X509Certificate> withRoot = PKI.withRoot(ACCESS.chain());
        final Map<String, String> m = valid();
        m.remove("accessKeyRef");
        m.put("accessCertificatePrivateKey", pkcs8Pem(ACCESS.privateKey()));
        m.put("accessCertificateChain", pem(withRoot));
        assertThat(errors(dev, m)).containsEntry("accessCertificateChain",
                "The certificate chain must not include the root (self-signed) certificate; x5c never carries it");

        final WalletConfigValidator v = new WalletConfigValidator(new FakeKeys(ACCESS, withRoot, null),
                DeploymentProfile.production());
        final Map<String, String> byRef = valid();
        byRef.remove("accessCertificateChain");
        assertThat(v.validate(REALM, WalletProviderConfig.fromStored(byRef))).containsKey("accessKeyRef");
    }

    @Test
    void chainNotLeafFirst_isRefused() {
        final Map<String, String> m = valid();
        m.remove("accessKeyRef");
        m.put("accessCertificatePrivateKey", pkcs8Pem(ACCESS.privateKey()));
        m.put("accessCertificateChain", TestPki.pem(ACCESS.certificate()) + ISSUERS.intermediatePem());
        assertThat(errors(dev, m).get("accessCertificateChain"))
                .startsWith("The certificate chain must be ordered leaf first");
    }

    @Test
    void corruptKeyBehindKeyRef_isAFieldError() {
        final WalletConfigValidator v = new WalletConfigValidator(new FakeKeys(ACCESS, ACCESS.chain(),
                new IllegalStateException("Stored verifier signing key algorithm does not match its curve")),
                DeploymentProfile.production());
        assertThat(v.validate(REALM, WalletProviderConfig.fromStored(valid())))
                .containsEntry("accessKeyRef", "The key behind accessKeyRef cannot be used");
    }

    @Test
    void keyStoreErrorWithoutMessage_getsAFixedMessage() {
        final WalletConfigValidator v = new WalletConfigValidator(new FakeKeys(ACCESS, ACCESS.chain(),
                new NoSuchElementException()), DeploymentProfile.production());
        assertThat(v.validate(REALM, WalletProviderConfig.fromStored(valid())))
                .containsEntry("accessKeyRef", "accessKeyRef could not be resolved");
    }

    @Test
    void specNameAccessCertificateKeyRef_isRefusedAsRenamed() {
        assertThat(errorsWith("accessCertificateKeyRef", "kms://realm/eudi-access-key"))
                .containsEntry("accessCertificateKeyRef", "accessCertificateKeyRef was renamed to accessKeyRef");
    }

    @Test
    void unknownKeyRef_isRefused() {
        assertThat(errorsWith("accessKeyRef", "software:acme/missing"))
                .containsEntry("accessKeyRef", "Signing key not found in this realm");
    }

    @Test
    void unsupportedKeyRefScheme_isRefused() {
        assertThat(errorsWith("accessKeyRef", "kms://realm/eudi-access-key")).containsKey("accessKeyRef");
    }

    @Test
    void neitherKeyRefNorDevKey_isRefused() {
        final Map<String, String> m = valid();
        m.remove("accessKeyRef");
        assertThat(errors(production, m)).containsKey("accessKeyRef");
    }

    @Test
    void rawPrivateKey_outsideDev_isRefused() {
        final Map<String, String> m = valid();
        m.remove("accessKeyRef");
        m.put("accessCertificatePrivateKey", pkcs8Pem(ACCESS.privateKey()));
        final Map<String, String> e = errors(production, m);
        assertThat(e).containsEntry("accessCertificatePrivateKey",
                "A raw private key is accepted only in the dev profile; import it and set accessKeyRef");
        assertThat(e.values()).noneMatch(v -> v.contains("PRIVATE KEY"));
    }

    @Test
    void rawPrivateKey_inDev_matchingTheCertificate_isAccepted() {
        final Map<String, String> m = valid();
        m.remove("accessKeyRef");
        m.put("accessCertificatePrivateKey", pkcs8Pem(ACCESS.privateKey()));
        assertThat(errors(dev, m)).isEmpty();
    }

    @Test
    void rawPrivateKey_inDev_notMatchingTheCertificate_isRefused() {
        final Map<String, String> m = valid();
        m.remove("accessKeyRef");
        m.put("accessCertificatePrivateKey", pkcs8Pem(OTHER.privateKey()));
        assertThat(errors(dev, m)).containsEntry("accessCertificatePrivateKey",
                "accessCertificatePrivateKey does not match the access certificate");
    }

    @Test
    void keyRefAndRawKeyTogether_isRefused() {
        final Map<String, String> m = valid();
        m.put("accessCertificatePrivateKey", pkcs8Pem(ACCESS.privateKey()));
        assertThat(errors(dev, m)).containsKey("accessCertificatePrivateKey");
    }

    @Test
    void registrationCertificate_mustParseWhenSet() {
        assertThat(errorsWith("registrationCertificate", "garbage")).containsKey("registrationCertificate");
        assertThat(errorsWith("registrationCertificate", ISSUERS.intermediatePem())).isEmpty();
    }

    // ------------------------------------------------------------------ trust anchors, formats, PID

    @Test
    void zeroTrustAnchors_isRefused() {
        final Map<String, String> m = valid();
        m.remove("trustAnchors");
        assertThat(errors(production, m)).containsKey("trustAnchors");
        assertThat(errorsWith("trustAnchors", "")).containsKey("trustAnchors");
    }

    @Test
    void trustAnchorThatIsNoCa_isRefused() {
        assertThat(errorsWith("trustAnchors", TestPki.pem(ACCESS.certificate()))).containsKey("trustAnchors");
    }

    @Test
    void zeroFormats_isRefused() {
        assertThat(errorsWith("credentialFormats", "[]"))
                .containsEntry("credentialFormats", "At least one credential format is required");
    }

    @Test
    void unknownFormat_isRefused() {
        assertThat(errorsWith("credentialFormats", "[\"jwt_vc_json\"]"))
                .containsEntry("credentialFormats", "Unknown credential format: jwt_vc_json (dc+sd-jwt or mso_mdoc)");
    }

    @Test
    void repeatedFormat_isRefused() {
        assertThat(errorsWith("credentialFormats", "[\"mso_mdoc\",\"mso_mdoc\"]")).containsKey("credentialFormats");
    }

    @Test
    void singleFormat_isAccepted() {
        assertThat(errorsWith("credentialFormats", "[\"mso_mdoc\"]")).isEmpty();
    }

    @Test
    void unknownPidClaim_isRefused() {
        assertThat(errorsWith("pid.requestedClaims", "[\"given_name\",\"age_over_18\"]"))
                .containsEntry("pid.requestedClaims", "Not a PID claim: age_over_18");
    }

    @Test
    void nestedPidClaim_isAccepted() {
        assertThat(errorsWith("pid.requestedClaims", "[\"birthdate\",\"address.locality\"]")).isEmpty();
    }

    @Test
    void noPidClaims_orARepeatedClaim_isRefused() {
        assertThat(errorsWith("pid.requestedClaims", "[]")).containsKey("pid.requestedClaims");
        assertThat(errorsWith("pid.requestedClaims", "[\"birthdate\",\"birthdate\"]"))
                .containsKey("pid.requestedClaims");
    }

    @Test
    void mdocOnly_withOnlyAnSdJwtOnlyClaim_isRefused() {
        final Map<String, String> m = valid();
        m.put("credentialFormats", "[\"mso_mdoc\"]");
        m.put("pid.requestedClaims", "[\"address.house_number\"]");
        assertThat(errors(production, m)).containsKey("pid.requestedClaims");
    }

    @Test
    void sdJwtFormat_withoutVcts_isRefused() {
        assertThat(errorsWith("pid.sdJwtVcts", "[]")).containsKey("pid.sdJwtVcts");
        assertThat(errorsWith("pid.sdJwtVcts", "[\" \"]")).containsKey("pid.sdJwtVcts");
        final Map<String, String> mdocOnly = valid();
        mdocOnly.put("credentialFormats", "[\"mso_mdoc\"]");
        mdocOnly.put("pid.sdJwtVcts", "[]");
        assertThat(errors(production, mdocOnly)).isEmpty();
    }

    @Test
    void customCredentialQueries_areNotSupportedYet() {
        assertThat(errorsWith("customCredentialQueries", "[\"{}\"]")).containsKey("customCredentialQueries");
    }

    // ------------------------------------------------------------------ response mode, invocation, limits

    @Test
    void directPost_outsideDev_isRefused() {
        assertThat(errorsWith("responseMode", "direct_post")).containsEntry("responseMode",
                "responseMode direct_post (unencrypted) is allowed only in the dev profile");
    }

    @Test
    void directPost_inDev_isAccepted() {
        final Map<String, String> m = valid();
        m.put("responseMode", "direct_post");
        assertThat(errors(dev, m)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"haip-vp", "openid4vp", "eudi-openid4vp", "my-wallet+app"})
    void invocationScheme_knownOrCustom_isAccepted(final String scheme) {
        assertThat(errorsWith("invocationScheme", scheme)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"javascript", "data", "1abc", "has space", "a:b"})
    void invocationScheme_unsafeOrMalformed_isRefused(final String scheme) {
        assertThat(errorsWith("invocationScheme", scheme)).containsKey("invocationScheme");
    }

    @ParameterizedTest
    @ValueSource(strings = {"59", "901", "0", "-1"})
    void ttlOutside60To900_isRefused(final String ttl) {
        assertThat(errorsWith("transactionTtlSeconds", ttl)).containsEntry("transactionTtlSeconds",
                "transactionTtlSeconds must be between 60 and 900");
    }

    @ParameterizedTest
    @ValueSource(strings = {"60", "300", "900"})
    void ttlWithin60To900_isAccepted(final String ttl) {
        assertThat(errorsWith("transactionTtlSeconds", ttl)).isEmpty();
    }

    @Test
    void clockSkewAbove60_orNegative_isRefused() {
        assertThat(errorsWith("clockSkewSeconds", "61")).containsKey("clockSkewSeconds");
        assertThat(errorsWith("clockSkewSeconds", "-1")).containsKey("clockSkewSeconds");
        assertThat(errorsWith("clockSkewSeconds", "0")).isEmpty();
    }

    @Test
    void nonPositiveLimits_areRefused() {
        assertThat(errorsWith("limits.maxJwtBytes", "0")).containsKey("limits.maxJwtBytes");
        assertThat(errorsWith("limits.cborMaxDepth", "0")).containsKey("limits.cborMaxDepth");
        assertThat(errorsWith("limits.cborMaxItems", "-5")).containsKey("limits.cborMaxItems");
        assertThat(errorsWith("limits.cborMaxBytes", "0")).containsKey("limits.cborMaxBytes");
    }

    // ------------------------------------------------------------------ status list

    @Test
    void statusListMaxCache_negativeOrAbove900_isRefused() {
        assertThat(errorsWith("statusList.maxCacheSeconds", "-1")).containsKey("statusList.maxCacheSeconds");
        assertThat(errorsWith("statusList.maxCacheSeconds", "901")).containsKey("statusList.maxCacheSeconds");
        assertThat(errorsWith("statusList.maxCacheSeconds", "0")).isEmpty();
    }

    @Test
    void statusListAllowedHosts_mustBeHostNames() {
        assertThat(errorsWith("statusList.allowedHosts", "[\"https://status.example.eu\"]"))
                .containsKey("statusList.allowedHosts");
        assertThat(errorsWith("statusList.allowedHosts", "[\"status.example.eu\"]")).isEmpty();
    }

    // ------------------------------------------------------------------ subject and LoA

    @Test
    void attributeTuple_withoutAcknowledgement_isRefused() {
        assertThat(errorsWith("subject.strategy", "attribute_tuple")).containsEntry("subject.strategy",
                "subject.strategy ATTRIBUTE_TUPLE requires subject.acknowledgeWeakSubject=true");
    }

    @Test
    void attributeTuple_withAcknowledgement_isAccepted() {
        final Map<String, String> m = valid();
        m.put("subject.strategy", "ATTRIBUTE_TUPLE");
        m.put("subject.acknowledgeWeakSubject", "true");
        assertThat(errors(production, m)).isEmpty();
    }

    @Test
    void subjectStrategyNone_isNotSupported() {
        assertThat(errorsWith("subject.strategy", "NONE")).containsKey("subject.strategy");
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://eidas.europa.eu/LoA/low", "http://eidas.europa.eu/LoA/substantial",
            "http://eidas.europa.eu/LoA/high"})
    void minimumLoa_onTheEidasLadder_isAccepted(final String loa) {
        assertThat(errorsWith("minimumLoa", loa)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"urn:nl-eid-gdi:1.0:LoA:High", "http://eidas.europa.eu/LoA/veryhigh", "high"})
    void minimumLoa_notAnEidasUri_isRefused(final String loa) {
        assertThat(errorsWith("minimumLoa", loa)).containsEntry("minimumLoa",
                "minimumLoa must be an eIDAS level of assurance (http://eidas.europa.eu/LoA/low|substantial|high)");
    }

    // ------------------------------------------------------------------ malformed stored input (never thrown)

    private Map<String, String> storedErrors(final Map<String, String> m) {
        return production.validateStored(REALM, m.get("alias"), m.get("displayName"), m);
    }

    @Test
    void validateStored_validMap_hasNoErrors() {
        assertThat(storedErrors(valid())).isEmpty();
    }

    @Test
    void validateStored_badJsonArray_isAFieldError() {
        final Map<String, String> m = valid();
        m.put("credentialFormats", "dc+sd-jwt");
        m.put("statusList.allowedHosts", "[1]");
        assertThat(storedErrors(m))
                .containsEntry("credentialFormats", "credentialFormats must be a JSON array of strings")
                .containsEntry("statusList.allowedHosts", "statusList.allowedHosts must be a JSON array of strings");
    }

    @Test
    void validateStored_unknownEnum_isAFieldError() {
        final Map<String, String> m = valid();
        m.put("responseMode", "fragment");
        m.put("subject.strategy", "email");
        final Map<String, String> e = storedErrors(m);
        assertThat(e.get("responseMode")).startsWith("responseMode must be one of");
        assertThat(e.get("subject.strategy")).startsWith("subject.strategy must be one of");
    }

    @Test
    void validateStored_badNumberOrBoolean_isAFieldError() {
        final Map<String, String> m = valid();
        m.put("transactionTtlSeconds", "five minutes");
        m.put("statusList.required", "yes");
        assertThat(storedErrors(m))
                .containsEntry("transactionTtlSeconds", "transactionTtlSeconds must be a whole number")
                .containsEntry("statusList.required", "statusList.required must be true or false");
    }

    @Test
    void validateStored_missingFields_areFieldErrors() {
        final Map<String, String> m = valid();
        m.remove("alias");
        m.remove("trustAnchors");
        m.remove("accessKeyRef");
        assertThat(storedErrors(m)).containsKeys("alias", "trustAnchors", "accessKeyRef");
    }

    @Test
    void validateStored_formatAndRuleErrors_areReportedTogether() {
        final Map<String, String> m = valid();
        m.put("responseMode", "fragment");
        m.put("transactionTtlSeconds", "5");
        assertThat(storedErrors(m)).containsKeys("responseMode", "transactionTtlSeconds");
    }

    @Test
    void fromStored_malformed_throwsATypedExceptionCarryingEveryField() {
        final Map<String, String> m = valid();
        m.put("responseMode", "fragment");
        m.put("credentialFormats", "{}");
        assertThatThrownBy(() -> WalletProviderConfig.fromStored(m))
                .isInstanceOfSatisfying(WalletConfigFormatException.class, ex -> assertThat(ex.fieldErrors())
                        .containsOnlyKeys("responseMode", "credentialFormats"));
    }

    // ------------------------------------------------------------------ null list elements (programmatic / YAML)

    @Test
    void nullListElements_areFieldErrors_notNpe() {
        final WalletProviderConfig base = WalletProviderConfig.fromStored(valid());
        final WalletProviderConfig c = new WalletProviderConfig(base.alias(), base.displayName(),
                base.clientIdScheme(), base.clientIdHost(), base.accessCertificateChain(), base.accessKeyRef(), null,
                base.accessCertificatePrivateKey(), base.registrationCertificate(), base.invocationScheme(),
                base.responseMode(), base.requestUriMethod(), base.transactionTtlSeconds(),
                Arrays.asList("dc+sd-jwt", null),
                new WalletProviderConfig.Pid(Arrays.asList("urn:eudi:pid:1", null), null,
                        Arrays.asList("given_name", null)),
                base.customCredentialQueries(), base.trustAnchors(), base.revocationChecking(),
                new WalletProviderConfig.StatusList(false, null, null, Arrays.asList((String) null)),
                base.subject(), base.minimumLoa(), base.clockSkewSeconds(), base.allowLegacyVcSdJwtTyp(),
                base.limits());
        assertThat(production.validate(REALM, c))
                .containsEntry("credentialFormats", "credentialFormats must not contain empty entries")
                .containsEntry("pid.requestedClaims", "pid.requestedClaims must not contain empty entries")
                .containsKey("pid.sdJwtVcts")
                .containsKey("statusList.allowedHosts");
    }

    // ------------------------------------------------------------------ helpers

    private static String pem(final List<X509Certificate> chain) {
        final StringBuilder sb = new StringBuilder();
        chain.forEach(c -> sb.append(TestPki.pem(c)));
        return sb.toString();
    }

    static String pkcs8Pem(final PrivateKey key) {
        return "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(key.getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
    }

    /**
     * One software key, {@code software:acme/eudi-access} in realm {@code acme}, backed by {@code key}'s private key and
     * carrying {@code chain}; when {@code failure} is set, resolving throws it.
     */
    private record FakeKeys(TestPki.Leaf key, List<X509Certificate> chain, RuntimeException failure)
            implements RealmSigningKeys {

        FakeKeys(final TestPki.Leaf leaf) {
            this(leaf, leaf.chain(), null);
        }

        @Override
        public SigningKeyHandle resolve(final String realmId, final String keyRef) {
            if (failure != null) {
                throw failure;
            }
            if (keyRef.startsWith("kms:")) {
                throw new UnsupportedOperationException("Key reference scheme 'kms:' (HSM / KMS) is not supported yet");
            }
            if (!REALM.equals(realmId) || !KEY_REF.equals(keyRef)) {
                throw new NoSuchElementException("Signing key not found in this realm");
            }
            final JWSSigner signer;
            try {
                signer = new ECDSASigner((ECPrivateKey) key.privateKey());
            } catch (final JOSEException e) {
                throw new IllegalStateException(e);
            }
            return new SigningKeyHandle() {
                @Override
                public String keyRef() {
                    return KEY_REF;
                }

                @Override
                public JWSAlgorithm algorithm() {
                    return JWSAlgorithm.ES256;
                }

                @Override
                public List<X509Certificate> certificateChain() {
                    return chain;
                }

                @Override
                public JWSSigner signer() {
                    return signer;
                }
            };
        }

        @Override
        public String importKey(final String realmId, final String name, final String privateKeyPem,
                                final String certificateChainPem) {
            throw new UnsupportedOperationException();
        }
    }
}
