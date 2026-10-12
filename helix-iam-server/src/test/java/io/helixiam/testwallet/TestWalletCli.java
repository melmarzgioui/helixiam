/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.testwallet;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.ECKey;
import io.helixiam.authorization.federation.wallet.testwallet.Oid4vpWalletClient;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Task 25: a small, test-scope-only CLI around {@link TestWallet} / {@link Oid4vpWalletClient}, so the sandbox "Sign
 * in with EUDI Wallet" demo has a runnable stand-in for a real wallet app, driven from the command line instead of a
 * phone. <b>Never packaged in the server image or the main jar</b> — it lives under {@code src/test/java} and is run
 * with the test classpath:
 *
 * <pre>{@code
 * mvn -q -pl helix-iam-server exec:java -Dexec.classpathScope=test \
 *   -Dexec.mainClass=io.helixiam.testwallet.TestWalletCli -Dexec.args="ca --out ./wallet-demo-ca"
 * mvn -q -pl helix-iam-server exec:java -Dexec.classpathScope=test \
 *   -Dexec.mainClass=io.helixiam.testwallet.TestWalletCli \
 *   -Dexec.args="respond '<invocation-url>' --format sd-jwt --dir ./wallet-demo-ca"
 * }</pre>
 *
 * <h2>{@code ca}</h2>
 * Writes a throwaway PID-issuer CA (its root is the wallet provider's {@code trustAnchors}) and a separate verifier
 * access key/chain (imported into the realm via {@code POST /admin/realms/{realm}/verifier-keys}) to {@code --out}
 * (default {@code ./wallet-demo-ca}): {@code pid-issuer-ca.pem}, {@code pid-issuer-key.pem} +
 * {@code pid-issuer-chain.pem} (kept so a later {@code respond} mints PIDs the realm still trusts), and
 * {@code verifier-key.pem} + {@code verifier-chain.pem}.
 *
 * <h2>{@code respond &lt;invocation-url&gt;}</h2>
 * Fetches and verifies the request object behind an invocation URL (the wallet page's QR code or "Open wallet"
 * link), mints a PID for a fixed demo persona — Erika Mustermann, the official EU sample persona, clearly fake data
 * — in the format the caller asks for ({@code --format sd-jwt} (default) or {@code --format mdoc}), and posts the
 * {@code direct_post.jwt} response. Persona fields ({@code --given-name}, {@code --family-name}, {@code --birthdate},
 * {@code --issuing-country}, {@code --administrative-number}, {@code --no-administrative-number}) are optional
 * overrides; {@code --dir} names the directory a prior {@code ca} wrote to (default {@code ./wallet-demo-ca}).
 */
public final class TestWalletCli {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final SecureRandom RANDOM = new SecureRandom();

    private TestWalletCli() {
    }

    public static void main(final String[] args) {
        try {
            run(args);
        } catch (final CliException e) {
            System.err.println("error: " + e.getMessage());
            System.exit(1);
        } catch (final Exception e) {
            System.err.println("error: " + e);
            System.exit(1);
        }
    }

    private static void run(final String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            System.exit(2);
            return;
        }
        switch (args[0]) {
            case "ca" -> ca(options(args, 1));
            case "respond" -> {
                if (args.length < 2 || args[1].startsWith("--")) {
                    throw new CliException("`respond` needs an invocation URL, e.g. respond 'haip://...'");
                }
                respond(args[1], options(args, 2));
            }
            default -> {
                usage();
                System.exit(2);
            }
        }
    }

    private static void usage() {
        System.err.println("""
                Usage:
                  TestWalletCli ca [--out <dir>]
                      Writes the test PID-issuer CA bundle and the verifier access key/chain (PEM) to <dir>
                      (default ./wallet-demo-ca).

                  TestWalletCli respond <invocation-url> [--format sd-jwt|mdoc] [--dir <dir>]
                                        [--given-name N] [--family-name N] [--birthdate YYYY-MM-DD]
                                        [--issuing-country XX] [--administrative-number N] [--no-administrative-number]
                      Fetches the request object, mints a PID for a demo persona, and posts the response.
                """);
    }

    // ------------------------------------------------------------------------------------------------------- ca

    private static void ca(final Map<String, String> opts) throws Exception {
        final Path dir = Path.of(opts.getOrDefault("out", "./wallet-demo-ca"));
        Files.createDirectories(dir);

        final TestPki pidPki = TestPki.create("Demo PID Issuer");
        final TestPki.Leaf pidLeaf = pidPki.issueLeaf(TestPki.LeafSpec.defaults());
        writeString(dir.resolve("pid-issuer-ca.pem"), pidPki.rootPem());
        writeString(dir.resolve("pid-issuer-key.pem"), pkcs8Pem(pidLeaf.privateKey()));
        writeString(dir.resolve("pid-issuer-chain.pem"), chainPem(pidLeaf.chain()));

        final TestPki accessPki = TestPki.create("Demo Wallet Access");
        final TestPki.Leaf accessLeaf = accessPki.issueLeaf(TestPki.LeafSpec.defaults());
        writeString(dir.resolve("verifier-key.pem"), pkcs8Pem(accessLeaf.privateKey()));
        writeString(dir.resolve("verifier-chain.pem"), chainPem(accessLeaf.chain()));

        System.out.println("Wrote test CA material to " + dir.toAbsolutePath());
        System.out.println("  pid-issuer-ca.pem                         -> the wallet provider's trustAnchors");
        System.out.println("  verifier-key.pem + verifier-chain.pem     -> POST /admin/realms/{realm}/verifier-keys");
        System.out.println("  pid-issuer-key.pem + pid-issuer-chain.pem -> kept here; `respond --dir " + dir
                + "` mints PIDs this trust anchor still recognises");
        System.out.println();
        System.out.println("DEV/TEST ONLY: this CA and its keys must never be trusted outside a sandbox.");
    }

    private static String pkcs8Pem(final PrivateKey key) {
        final String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(key.getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";
    }

    private static String chainPem(final List<X509Certificate> chain) {
        final StringBuilder sb = new StringBuilder();
        for (final X509Certificate cert : chain) {
            sb.append(TestPki.pem(cert));
        }
        return sb.toString();
    }

    // -------------------------------------------------------------------------------------------------- respond

    private static void respond(final String invocationUrl, final Map<String, String> opts) throws Exception {
        final Path dir = Path.of(opts.getOrDefault("dir", "./wallet-demo-ca"));
        final String format = opts.getOrDefault("format", "sd-jwt");
        if (!"sd-jwt".equals(format) && !"mdoc".equals(format)) {
            throw new CliException("--format must be sd-jwt or mdoc, not " + format);
        }
        final boolean mdoc = "mdoc".equals(format);

        final TestPki.Leaf issuerLeaf = loadLeaf(dir.resolve("pid-issuer-key.pem"), dir.resolve("pid-issuer-chain.pem"));
        final TestWallet wallet = TestWallet.create().withIssuer(issuerLeaf, JWSAlgorithm.ES256);

        final HttpClient http = HttpClient.newHttpClient();
        final Oid4vpWalletClient.VerifiedRequest request =
                wallet.fetchAndVerifyRequest(invocationUrl, requestUri -> fetch(http, requestUri), Instant.now());
        System.out.println("Fetched and verified the request object: client_id=" + request.clientId()
                + " response_mode=" + request.responseMode());

        final String wireFormat = mdoc ? "mso_mdoc" : "dc+sd-jwt";
        final String queryId = findCredentialQueryId(request, wireFormat);
        final Map<String, Object> claims = persona(opts, mdoc);
        final Map<String, Object> vpToken = mdoc ? mdocVpToken(wallet, request, queryId, claims)
                : sdJwtVpToken(wallet, request, queryId, claims);

        final String responseJwe = wallet.respond(request, vpToken);
        final HttpResponse<String> posted = postForm(http, request.responseUri(), Map.of("response", responseJwe));
        if (posted.statusCode() != 200) {
            throw new CliException("the verifier refused the presentation: HTTP " + posted.statusCode() + " "
                    + posted.body());
        }
        System.out.println("Posted the " + format + " presentation for " + claims.get("given_name") + " "
                + claims.get("family_name") + " — HTTP 200.");
        explainNextStep(posted.body());
    }

    private static void explainNextStep(final String body) throws IOException {
        final JsonNode json = body.isBlank() ? JSON.createObjectNode() : JSON.readTree(body);
        if (json.has("redirect_uri")) {
            System.out.println();
            System.out.println("Same-device: open this URL in the SAME browser that showed the wallet page:");
            System.out.println("  " + json.get("redirect_uri").asText());
        } else {
            System.out.println();
            System.out.println("Cross-device: switch back to the browser tab showing the QR code — it polls "
                    + "automatically and signs in within a couple of seconds.");
        }
    }

    @SuppressWarnings("unchecked")
    private static String findCredentialQueryId(final Oid4vpWalletClient.VerifiedRequest request,
            final String wireFormat) {
        final Object dcql = request.claims().get("dcql_query");
        if (dcql instanceof Map<?, ?> dcqlMap && dcqlMap.get("credentials") instanceof List<?> credentials) {
            for (final Object credential : credentials) {
                if (credential instanceof Map<?, ?> c && wireFormat.equals(c.get("format"))) {
                    return String.valueOf(c.get("id"));
                }
            }
        }
        throw new CliException("the request's dcql_query does not ask for format " + wireFormat
                + " — try the other --format?");
    }

    private static Map<String, Object> persona(final Map<String, String> opts, final boolean mdoc) {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", opts.getOrDefault("given-name", "Erika"));
        claims.put("family_name", opts.getOrDefault("family-name", "Mustermann"));
        claims.put(mdoc ? "birth_date" : "birthdate", opts.getOrDefault("birthdate", "1984-01-26"));
        claims.put("issuing_country", opts.getOrDefault("issuing-country", "DE"));
        if (!"true".equals(opts.get("no-administrative-number"))) {
            claims.put("personal_administrative_number",
                    opts.getOrDefault("administrative-number", "DEMO-" + randomSuffix()));
        }
        return claims;
    }

    private static Map<String, Object> sdJwtVpToken(final TestWallet wallet,
            final Oid4vpWalletClient.VerifiedRequest request, final String queryId, final Map<String, Object> claims) {
        final Instant now = Instant.now();
        final TestWallet.SdJwtCredential pid = wallet.sdJwtPid(claims, now.minusSeconds(3600), now.plusSeconds(3600),
                Optional.empty());
        final String presentation = wallet.present(pid, claims.keySet(), request.clientId(), request.nonce());
        return Map.of(queryId, List.of(presentation));
    }

    private static Map<String, Object> mdocVpToken(final TestWallet wallet,
            final Oid4vpWalletClient.VerifiedRequest request, final String queryId, final Map<String, Object> claims)
            throws JOSEException {
        final Instant now = Instant.now();
        final TestWallet.MdocCredential credential = wallet.mdocPid(claims, now.minusSeconds(3600),
                now.minusSeconds(3600), now.plusSeconds(3600), Optional.empty());
        final byte[] thumbprint = request.encryptionKey() == null ? null : thumbprint(request.encryptionKey());
        final byte[] transcript = sessionTranscript(request.clientId(), request.nonce(), thumbprint,
                request.responseUri());
        final byte[] deviceResponse = TestWallet.mdocDeviceResponse(credential, claims.keySet(), transcript);
        return Map.of(queryId, List.of(TestWallet.b64url(deviceResponse)));
    }

    private static byte[] thumbprint(final ECKey key) throws JOSEException {
        return key.toPublicJWK().computeThumbprint("SHA-256").decode();
    }

    /** The OpenID4VP redirect SessionTranscript (Annex B), written independently of production code. */
    private static byte[] sessionTranscript(final String clientId, final String nonce, final byte[] thumbprint,
            final String responseUri) {
        final byte[] info = TestWallet.cbor(Arrays.asList(clientId, nonce, thumbprint, responseUri));
        return TestWallet.cbor(Arrays.asList(null, null,
                List.of("OpenID4VPHandover", TestWallet.sha("SHA-256", info))));
    }

    // -------------------------------------------------------------------------------------------------- HTTP / IO

    private static String fetch(final HttpClient http, final String requestUri) {
        try {
            final HttpRequest req = HttpRequest.newBuilder(URI.create(requestUri))
                    .header("Accept", "application/oauth-authz-req+jwt").GET().build();
            final HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new CliException("fetching the request object failed: HTTP " + resp.statusCode() + " "
                        + resp.body());
            }
            return resp.body();
        } catch (final IOException | InterruptedException e) {
            throw new CliException("could not fetch the request object: " + e.getMessage());
        }
    }

    private static HttpResponse<String> postForm(final HttpClient http, final String url,
            final Map<String, String> form) throws IOException, InterruptedException {
        final String body = form.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        final HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }

    private static TestPki.Leaf loadLeaf(final Path keyPath, final Path chainPath) throws Exception {
        if (!Files.exists(keyPath) || !Files.exists(chainPath)) {
            throw new CliException("no PID-issuer key/chain at " + keyPath.getParent().toAbsolutePath()
                    + " — run `ca` first (with the same --dir) before `respond`.");
        }
        final PrivateKey key = readPkcs8PrivateKey(keyPath);
        final List<X509Certificate> chain = readCertificateChain(chainPath);
        return new TestPki.Leaf(chain.get(0), key, chain);
    }

    private static PrivateKey readPkcs8PrivateKey(final Path path) throws Exception {
        final String pem = Files.readString(path);
        final String b64 = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        final byte[] der = Base64.getDecoder().decode(b64);
        final KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private static List<X509Certificate> readCertificateChain(final Path path) throws Exception {
        final CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream in = Files.newInputStream(path)) {
            final Collection<? extends Certificate> certs = cf.generateCertificates(in);
            final List<X509Certificate> out = new ArrayList<>();
            for (final Certificate c : certs) {
                out.add((X509Certificate) c);
            }
            return out;
        }
    }

    private static void writeString(final Path path, final String content) throws IOException {
        Files.writeString(path, content);
    }

    private static String randomSuffix() {
        final byte[] b = new byte[4];
        RANDOM.nextBytes(b);
        return HexFormat.of().formatHex(b);
    }

    /** {@code --key value} and bare {@code --flag} (read back as {@code "true"}), from {@code args[from..]}. */
    private static Map<String, String> options(final String[] args, final int from) {
        final Map<String, String> m = new LinkedHashMap<>();
        for (int i = from; i < args.length; i++) {
            final String a = args[i];
            if (!a.startsWith("--")) {
                throw new CliException("unexpected argument: " + a);
            }
            final String key = a.substring(2);
            final boolean hasValue = i + 1 < args.length && !args[i + 1].startsWith("--");
            m.put(key, hasValue ? args[++i] : "true");
        }
        return m;
    }

    /** A CLI usage error: {@link #main} prints only its message (no stack trace) and exits 1. */
    private static final class CliException extends RuntimeException {
        CliException(final String message) {
            super(message);
        }
    }
}
