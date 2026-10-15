/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import tools.jackson.databind.ObjectMapper;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;
import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import io.helixiam.authorization.federation.wallet.WalletIdentityProviders;
import io.helixiam.authorization.federation.wallet.WalletProviderConfig;
import io.helixiam.authorization.federation.wallet.testwallet.Oid4vpWalletClient;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import io.helixiam.authorization.service.key.RealmSigningKeys;
import org.springframework.context.ApplicationContext;

import java.awt.image.BufferedImage;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Task 18: what the wallet e2e tests (HTTP and browser) share. It installs EUDI wallet providers into the running
 * server's registry (an access key imported into the realm, a stored provider built and validated by the real
 * {@link WalletIdentityProviders}), plays the wallet ({@link TestWallet} issues a PID, {@link Oid4vpWalletClient}
 * fetches the request object and answers with a {@code direct_post.jwt} JWE) and reads the wallet page (the QR code is
 * decoded with ZXing, so the test proves what a phone would scan).
 */
public final class WalletE2eFixture {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final TestPki ACCESS_PKI = TestPki.create("E2E Wallet Access");
    private static final Pattern DATA_SVG = Pattern.compile("src=\"data:image/svg\\+xml;base64,([A-Za-z0-9+/=]+)\"");
    private static final Pattern VIEW_BOX = Pattern.compile("viewBox=\"0 0 (\\d+) (\\d+)\"");
    private static final Pattern RUN = Pattern.compile("M(\\d+),(\\d+)h(\\d+)v1h-\\d+z");
    private static final Pattern OPEN_LINK = Pattern.compile("id=\"walletOpen\"[^>]*href=\"([^\"]+)\"|href=\"([^\"]+)\"[^>]*id=\"walletOpen\"");

    private final ApplicationContext context;
    /** The PID issuer every provider of this fixture trusts. */
    private final TestWallet wallet = TestWallet.create();

    public WalletE2eFixture(final ApplicationContext context) {
        this.context = context;
    }

    public TestWallet wallet() {
        return wallet;
    }

    /** The stored-provider settings: the realm's imported access key, the fixture's PID issuer, SD-JWT only. */
    public Map<String, String> storedConfig(final String keyRef) {
        final Map<String, String> config = new LinkedHashMap<>();
        config.put("accessKeyRef", keyRef);
        config.put("trustAnchors", wallet.pki().rootPem());
        config.put("revocationChecking", "OFF");
        config.put("credentialFormats", "[\"dc+sd-jwt\"]");
        return config;
    }

    /** Imports a fresh access key into {@code realm} and returns its reference. */
    public String importAccessKey(final String realm) {
        final TestPki.Leaf access = ACCESS_PKI.issueLeaf(TestPki.LeafSpec.defaults());
        return context.getBean(RealmSigningKeys.class).importKey(realm, E2eSeed.unique("eudi-access"),
                pkcs8Pem(access), TestPki.pem(access.certificate()) + ACCESS_PKI.intermediatePem());
    }

    /** A validated STORED provider of {@code realm} (its key imported there), with {@code extra} settings on top. */
    public WalletIdentityProvider storedProvider(final String realm, final String alias, final Map<String, String> extra) {
        final Map<String, String> config = storedConfig(importAccessKey(realm));
        config.putAll(extra);
        return context.getBean(WalletIdentityProviders.class).build(realm,
                WalletProviderConfig.fromStored(alias, "EU Digital Identity Wallet", config));
    }

    /** A validated YAML provider (key in master): it serves every realm. */
    public WalletIdentityProvider yamlProvider(final String alias) {
        final Map<String, String> config = storedConfig(importAccessKey(WalletIdentityProviders.YAML_REALM));
        return context.getBean(WalletIdentityProviders.class).buildFromYaml(
                WalletProviderConfig.fromStored(alias, "EU Digital Identity Wallet", config));
    }

    /** Task 22 fix round 1: the stored-provider settings for {@code mso_mdoc} only (the same PID issuer/trust). */
    public Map<String, String> storedConfigMdoc(final String keyRef) {
        final Map<String, String> config = new LinkedHashMap<>();
        config.put("accessKeyRef", keyRef);
        config.put("trustAnchors", wallet.pki().rootPem());
        config.put("revocationChecking", "OFF");
        config.put("credentialFormats", "[\"mso_mdoc\"]");
        return config;
    }

    /** Task 22 fix round 1: a validated STORED provider that only accepts {@code mso_mdoc} presentations. */
    public WalletIdentityProvider storedProviderMdoc(final String realm, final String alias,
                                                     final Map<String, String> extra) {
        final Map<String, String> config = storedConfigMdoc(importAccessKey(realm));
        config.putAll(extra);
        return context.getBean(WalletIdentityProviders.class).build(realm,
                WalletProviderConfig.fromStored(alias, "EU Digital Identity Wallet", config));
    }

    /** Task 23: the stored-provider settings accepting BOTH {@code dc+sd-jwt} and {@code mso_mdoc}. */
    public Map<String, String> storedConfigBothFormats(final String keyRef) {
        final Map<String, String> config = new LinkedHashMap<>();
        config.put("accessKeyRef", keyRef);
        config.put("trustAnchors", wallet.pki().rootPem());
        config.put("revocationChecking", "OFF");
        config.put("credentialFormats", "[\"dc+sd-jwt\",\"mso_mdoc\"]");
        return config;
    }

    /**
     * Task 23: a validated STORED provider accepting either format — the default DCQL {@code credential_sets}
     * (§15: "either satisfies the default DCQL credential_sets") lets a wallet answer with just one of them.
     */
    public WalletIdentityProvider storedProviderBothFormats(final String realm, final String alias,
                                                            final Map<String, String> extra) {
        final Map<String, String> config = storedConfigBothFormats(importAccessKey(realm));
        config.putAll(extra);
        return context.getBean(WalletIdentityProviders.class).build(realm,
                WalletProviderConfig.fromStored(alias, "EU Digital Identity Wallet", config));
    }

    /**
     * Makes {@code providers} {@code realm}'s store-backed providers (replacing that realm's earlier set). A stored
     * wallet provider of another realm goes into its own realm's set instead, as the store would put it.
     */
    public void install(final String realm, final IdentityProvider... providers) {
        final Map<String, List<IdentityProvider>> byRealm = new LinkedHashMap<>();
        byRealm.put(realm, new java.util.ArrayList<>());
        for (final IdentityProvider provider : providers) {
            final String own = WalletIdentityProvider.from(provider).map(WalletIdentityProvider::keyRealm).orElse(null);
            byRealm.computeIfAbsent(own == null ? realm : own, r -> new java.util.ArrayList<>()).add(provider);
        }
        final IdentityProviderRegistry registry = context.getBean(IdentityProviderRegistry.class);
        byRealm.forEach(registry::reload);
    }

    /** A PID with an administrative number (so the wallet may create an account) and the default requested claims. */
    public static Map<String, Object> pidWithNumber(final String number) {
        final Map<String, Object> claims = new LinkedHashMap<>(pidWithoutNumber());
        claims.put("personal_administrative_number", number);
        return claims;
    }

    /** A PID without an administrative number: the tuple subject only. */
    public static Map<String, Object> pidWithoutNumber() {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Erika");
        claims.put("family_name", "Mustermann");
        claims.put("birthdate", "1984-01-26");
        claims.put("issuing_country", "DE");
        return claims;
    }

    /** What the wallet does with a scanned or opened invocation URL: fetch and verify the request object. */
    public static Oid4vpWalletClient.VerifiedRequest fetchRequest(final E2eHttp http, final String invocationUrl) {
        return Oid4vpWalletClient.fetchAndVerifyRequest(invocationUrl, requestUri -> {
            final E2eHttp.Response response = http.get(requestUri, "Accept", "application/oauth-authz-req+jwt");
            if (response.status() != 200) {
                throw new AssertionError("request object fetch failed: " + response);
            }
            return response.body();
        }, Instant.now());
    }

    /** The {@code vp_token} for {@code request}: the PID {@code claims}, all disclosed, bound to its nonce and client. */
    public Map<String, Object> vpToken(final Oid4vpWalletClient.VerifiedRequest request,
                                       final Map<String, Object> claims) {
        final Instant now = Instant.now();
        final TestWallet.SdJwtCredential pid = wallet.sdJwtPid(claims, now.minusSeconds(3600),
                now.plusSeconds(3600), Optional.empty());
        final String presentation = wallet.present(pid, claims.keySet(), request.clientId(), request.nonce());
        return Map.of("pid_sd_jwt", List.of(presentation));
    }

    /** POSTs the encrypted Authorization Response ({@code direct_post.jwt}) to the request's {@code response_uri}. */
    public E2eHttp.Response respond(final E2eHttp wallet, final Oid4vpWalletClient.VerifiedRequest request,
                                    final Map<String, Object> claims) {
        return respondWith(wallet, request, vpToken(request, claims));
    }

    /**
     * Task 22 fix round 1: as {@link #respond}, but with an already-built {@code vp_token} — so a caller that needs
     * the exact submitted presentation (e.g. to assert a fragment of it is never logged) builds it once with
     * {@link #vpToken} / {@link #mdocVpToken} and submits that very same value, rather than letting this method build
     * a second, different one internally (SD-JWT disclosures are salted; a second build never matches the first).
     */
    public E2eHttp.Response respondWith(final E2eHttp wallet, final Oid4vpWalletClient.VerifiedRequest request,
                                        final Map<String, Object> vpToken) {
        return wallet.postForm(request.responseUri(), Map.of("response", Oid4vpWalletClient.respond(request, vpToken)),
                "Accept", "application/json");
    }

    /**
     * Task 22 fix round 1: the {@code mso_mdoc} {@code vp_token} for {@code request}: the PID {@code claims} as one
     * Document, device-signed over the OpenID4VP redirect SessionTranscript (built independently of production code,
     * like {@code MdocPresentationVerifierTest}'s own transcript helper).
     */
    public Map<String, Object> mdocVpToken(final Oid4vpWalletClient.VerifiedRequest request,
                                           final Map<String, Object> claims) {
        final Instant now = Instant.now();
        final TestWallet.MdocCredential credential = wallet.mdocPid(claims, now.minusSeconds(3600),
                now.minusSeconds(3600), now.plusSeconds(3600), Optional.empty());
        final byte[] thumbprint = request.encryptionKey() == null ? null : thumbprint(request.encryptionKey());
        final byte[] transcript = sessionTranscript(request.clientId(), request.nonce(), thumbprint,
                request.responseUri());
        final byte[] deviceResponse = TestWallet.mdocDeviceResponse(credential, claims.keySet(), transcript);
        return Map.of("pid_mdoc", List.of(TestWallet.b64url(deviceResponse)));
    }

    /**
     * Task 23: the OpenID4VP redirect SessionTranscript {@code request} expects, exposed so a test can build its own
     * (tampered) mdoc {@code DeviceResponse} structure by hand instead of going through {@link #mdocVpToken}.
     */
    public static byte[] mdocSessionTranscript(final Oid4vpWalletClient.VerifiedRequest request) {
        final byte[] thumbprint = request.encryptionKey() == null ? null : thumbprint(request.encryptionKey());
        return sessionTranscript(request.clientId(), request.nonce(), thumbprint, request.responseUri());
    }

    /** RFC 7638 SHA-256 thumbprint of the response-encryption public key (the mdoc handover input). */
    private static byte[] thumbprint(final com.nimbusds.jose.jwk.ECKey key) {
        try {
            return key.toPublicJWK().computeThumbprint("SHA-256").decode();
        } catch (final com.nimbusds.jose.JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The OpenID4VP redirect SessionTranscript (Annex B), written independently of production code. */
    private static byte[] sessionTranscript(final String clientId, final String nonce, final byte[] thumbprint,
                                             final String responseUri) {
        final byte[] info = TestWallet.cbor(java.util.Arrays.asList(clientId, nonce, thumbprint, responseUri));
        return TestWallet.cbor(java.util.Arrays.asList(null, null,
                List.of("OpenID4VPHandover", TestWallet.sha("SHA-256", info))));
    }

    /** The cross-device invocation URL the wallet page's QR code encodes (decoded with ZXing). */
    public static String scanQr(final String walletPageHtml) {
        final Matcher m = DATA_SVG.matcher(walletPageHtml);
        if (!m.find()) {
            throw new AssertionError("no SVG QR code on the wallet page:\n" + walletPageHtml);
        }
        return decodeQrSvg(new String(Base64.getDecoder().decode(m.group(1)), StandardCharsets.UTF_8));
    }

    /** The same-device invocation URL behind the page's "Open wallet" link. */
    public static String openWalletLink(final String walletPageHtml) {
        final Matcher m = OPEN_LINK.matcher(walletPageHtml);
        if (!m.find()) {
            throw new AssertionError("no #walletOpen link on the wallet page:\n" + walletPageHtml);
        }
        return (m.group(1) != null ? m.group(1) : m.group(2)).replace("&amp;", "&");
    }

    /** Rasterises the module runs of a {@code QrCodeSvg} image and decodes it like a phone camera would. */
    public static String decodeQrSvg(final String svg) {
        final Matcher box = VIEW_BOX.matcher(svg);
        if (!box.find()) {
            throw new AssertionError("QR SVG has no viewBox: " + svg);
        }
        final int size = Integer.parseInt(box.group(1));
        final int scale = 6;
        final BufferedImage image = new BufferedImage(size * scale, size * scale, BufferedImage.TYPE_INT_RGB);
        for (int x = 0; x < size * scale; x++) {
            for (int y = 0; y < size * scale; y++) {
                image.setRGB(x, y, 0xFFFFFF);
            }
        }
        final Matcher run = RUN.matcher(svg);
        while (run.find()) {
            final int x0 = Integer.parseInt(run.group(1));
            final int y0 = Integer.parseInt(run.group(2));
            final int w = Integer.parseInt(run.group(3));
            for (int x = x0 * scale; x < (x0 + w) * scale; x++) {
                for (int y = y0 * scale; y < (y0 + 1) * scale; y++) {
                    image.setRGB(x, y, 0x000000);
                }
            }
        }
        try {
            // A synthetic, axis-aligned image: decode it as a pure barcode (module grid read directly), so the result
            // never depends on the binarizer's guesses for one particular random matrix.
            final java.util.Map<com.google.zxing.DecodeHintType, Object> hints =
                    new java.util.EnumMap<>(com.google.zxing.DecodeHintType.class);
            hints.put(com.google.zxing.DecodeHintType.PURE_BARCODE, Boolean.TRUE);
            hints.put(com.google.zxing.DecodeHintType.TRY_HARDER, Boolean.TRUE);
            return new QRCodeReader().decode(new BinaryBitmap(new HybridBinarizer(
                    new BufferedImageLuminanceSource(image))), hints).getText();
        } catch (final Exception e) {
            throw new AssertionError("the QR code does not decode", e);
        }
    }

    /** The transaction id in a {@code …/wallet?tx=<id>} location. */
    public static String txId(final String walletPageLocation) {
        return walletPageLocation.substring(walletPageLocation.indexOf("tx=") + 3);
    }

    static String json(final Object value) {
        try {
            return JSON.writeValueAsString(value);
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String pkcs8Pem(final TestPki.Leaf leaf) {
        return "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(leaf.privateKey().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
    }
}
