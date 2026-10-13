/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.mdoc;

import io.helixiam.authorization.federation.wallet.PresentationVerifier;
import io.helixiam.authorization.federation.wallet.VerificationContext;
import io.helixiam.authorization.federation.wallet.VerifiedPresentation;
import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.status.CredentialIssuer;
import io.helixiam.authorization.federation.wallet.status.StatusEvaluator;
import io.helixiam.authorization.federation.wallet.status.StatusCheck;
import io.helixiam.authorization.federation.wallet.trust.IssuerTrustValidator;
import io.helixiam.authorization.federation.wallet.trust.ValidatedChain;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Verifies an ISO 18013-5 mdoc presentation ({@code mso_mdoc}: base64url of one DeviceResponse, OpenID4VP Appendix
 * B.2, docs/eudi-wallet-spec-notes.md §1.9, §6) and returns only the disclosed data elements plus the issuer
 * certificate's identity. It is the mdoc counterpart of the SD-JWT VC verifier and behaves the same way: every failure
 * is a {@link WalletVerificationException}, no partial result is ever returned, nothing is logged here, and no
 * exception detail carries presentation content. All untrusted CBOR is read by {@link StrictCbor}.
 *
 * <p>Checks, in this order (fail closed):
 * <ol>
 *   <li>size: the base64url input is at most {@code maxPresentationBytes} characters ({@code LIMIT_EXCEEDED}), then
 *       strict base64url (no padding) and {@link StrictCbor} with {@code cborLimits} (a depth / item / size bomb is
 *       {@code LIMIT_EXCEEDED}). The same {@code cborLimits} bound every nested decode: the MSO, the COSE protected
 *       headers, each IssuerSignedItem and DeviceNameSpaces;</li>
 *   <li>DeviceResponse: {@code version} matching {@code 1\.\d+}, {@code status} {@code 0}, exactly one Document
 *       (HAIP §5.3.1: one mdoc per DeviceResponse), no {@code zkDocuments} / {@code encryptedDocuments}; else
 *       {@code INVALID_RESPONSE}. {@code documentErrors} is tolerated (not read);</li>
 *   <li>Document {@code docType} equals {@code acceptedDoctype} ({@code DOCTYPE_NOT_ACCEPTED});</li>
 *   <li>IssuerAuth: a COSE_Sign1 with an <em>attached</em> payload (the MSO; detached is {@code INVALID_RESPONSE}),
 *       its x5chain validated by {@link IssuerTrustValidator} at {@code context.now}, then its signature with the leaf
 *       key ({@code ISSUER_SIGNATURE_INVALID}; an alg outside ES256/384/512 or not fitting the key:
 *       {@code ALGORITHM_NOT_ALLOWED});</li>
 *   <li>MSO ({@link MobileSecurityObject}): its {@code docType} equals the Document's ({@code DOCTYPE_NOT_ACCEPTED});
 *       validity with {@code context.clockSkew}: {@code signed} after {@code now + skew} is {@code INVALID_RESPONSE},
 *       {@code validFrom} after {@code now + skew} is {@code CREDENTIAL_NOT_YET_VALID}, {@code validUntil} before
 *       {@code now - skew} is {@code CREDENTIAL_EXPIRED}; and {@code [validFrom, validUntil]} must lie within the
 *       IssuerAuth leaf certificate's {@code [notBefore, notAfter]} ({@code INVALID_RESPONSE}: the notes, §6.2, record
 *       {@code validUntil <= notAfter}; the {@code validFrom >= notBefore} half is the ISO reader rule as ruled for
 *       this task);</li>
 *   <li>every IssuerSignedItemBytes: tag 24 wrapping an IssuerSignedItem {@code {digestID, random (>= 16 bytes),
 *       elementIdentifier, elementValue}} ({@code INVALID_RESPONSE} otherwise; a namespace list must be non-empty; a
 *       repeated {@code digestID} or {@code elementIdentifier} within a namespace is {@code INVALID_RESPONSE}). Its
 *       digest, over the <em>exact tag-24 bytes as received</em> (never re-encoded) with the MSO
 *       {@code digestAlgorithm}, must equal {@code valueDigests[namespace][digestID]}; a missing entry or a different
 *       digest is {@code DIGEST_MISMATCH};</li>
 *   <li>DeviceAuth: no {@code deviceSigned}, no {@code deviceAuth} or no {@code deviceSignature} is
 *       {@code HOLDER_BINDING_MISSING}. A {@code deviceMac} is {@code HOLDER_BINDING_INVALID} (notes §6.4: no reader
 *       key exists in the OpenID4VP redirect flow). DeviceNameSpaces must be an empty map ({@code INVALID_RESPONSE}
 *       otherwise, notes §6.3). The {@code deviceSignature} must be detached and verify with the MSO
 *       {@code deviceKey} over DeviceAuthenticationBytes built from this verifier's own SessionTranscript
 *       ({@link SessionTranscripts#openId4VpRedirect} of {@code clientId}, {@code nonce},
 *       {@code encryptionJwkThumbprint}, {@code responseUri}) and the received DeviceNameSpacesBytes. Any failure is
 *       {@code HOLDER_BINDING_INVALID}, including a {@code deviceSignature} {@code alg} that is missing, outside
 *       ES256/384/512 or does not fit the device key (as on the SD-JWT KB-JWT path; IssuerAuth keeps
 *       {@code ALGORITHM_NOT_ALLOWED}). The transcript is only hashed inside the signature, so a wrong nonce cannot be
 *       told apart from a wrong client_id (no {@code NONCE_MISMATCH} / {@code AUDIENCE_MISMATCH} here);</li>
 *   <li>status, only after holder binding passed: no MSO {@code status} is {@code STATUS_REQUIRED} when
 *       {@code statusPolicy.required}, else {@link #STATUS_ABSENT}. A {@code status_list} goes to the
 *       {@link StatusEvaluator} (in production the status-list client's CWT evaluator), which must answer
 *       {@code VALID} or throw; its wallet exceptions pass through and any other answer is {@code STATUS_UNAVAILABLE}.
 *       A present status with no {@code status_list} (e.g. only {@code identifier_list}), or an evaluator failing with
 *       a non-wallet exception, is <em>unavailable</em>: {@code STATUS_UNAVAILABLE} under {@code FAIL_CLOSED} (and a
 *       null policy), {@link #STATUS_UNAVAILABLE_ACCEPTED} under {@code FAIL_OPEN_WITH_AUDIT};</li>
 *   <li>output.</li>
 * </ol>
 *
 * <p><b>Output claims.</b> {@code namespace -> {elementIdentifier -> value}} for the disclosed items only. Values are
 * normalised to JSON-ish Java: text as {@link String}, integers as {@link Long}, floats as {@link Double}, booleans,
 * null, byte strings as base64url (no padding), {@code full-date} (tag 1004, exactly {@code YYYY-MM-DD}) as is,
 * {@code tdate} (tag 0, UTC "Z" only, per the PID rulebook) as an ISO-8601 instant, arrays as lists and maps as maps
 * (integer keys as their decimal text; an integer and a text key that collide are refused). An invalid date, a
 * non-UTC tdate or any other tag in a value is {@code INVALID_RESPONSE}.
 *
 * <p>The result's {@code credentialType} is the Document's {@code docType}.
 *
 * <p><b>No disclosure.</b> A Document without {@code issuerSigned.nameSpaces} is valid ISO and verifies with empty
 * claims; DCQL matching (Task 14) must reject a presentation that does not satisfy the query. The issuer identity is the IssuerAuth
 * leaf's subject DN (RFC 2253) and serial (lower-case hex).
 */
public final class MdocPresentationVerifier implements PresentationVerifier {

    public static final String FORMAT = "mso_mdoc";
    /** Caps the whole presentation (the base64url DeviceResponse), as ruled for "JWT 64 KB". */
    public static final int DEFAULT_MAX_PRESENTATION_BYTES = 64 * 1024;
    /** {@link VerifiedPresentation#statusResult()} when the MSO carries no {@code status}. */
    public static final String STATUS_ABSENT = StatusCheck.ABSENT;
    /**
     * {@link VerifiedPresentation#statusResult()} when the status could not be evaluated and
     * {@code statusPolicy.onUnavailable} is {@code FAIL_OPEN_WITH_AUDIT}: accepted, and the caller must audit it.
     */
    public static final String STATUS_UNAVAILABLE_ACCEPTED = StatusCheck.UNAVAILABLE_ACCEPTED;

    private static final Pattern BASE64URL = Pattern.compile("[A-Za-z0-9_-]+");
    /** DeviceResponse {@code version}: major 1, any minor. */
    private static final Pattern VERSION = Pattern.compile("1\\.\\d+");
    /** full-date (RFC 8943): exactly a four-digit year, month and day. */
    private static final Pattern FULL_DATE = Pattern.compile("\\d{4}-\\d{2}-\\d{2}");
    /** tdate as the PID rulebook requires it: UTC ("Z"), optional fractional seconds. */
    private static final Pattern TDATE = Pattern.compile("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?Z");
    private static final int MIN_RANDOM_BYTES = 16;
    private static final long TAG_TDATE = 0;
    private static final long TAG_FULL_DATE = 1004;

    private final IssuerTrustValidator trust;
    private final StatusEvaluator status;
    private final int maxPresentationBytes;
    private final CborLimits cborLimits;

    public MdocPresentationVerifier(final IssuerTrustValidator trust, final StatusEvaluator status) {
        this(trust, status, DEFAULT_MAX_PRESENTATION_BYTES, CborLimits.DEFAULTS);
    }

    public MdocPresentationVerifier(final IssuerTrustValidator trust, final StatusEvaluator status,
            final int maxPresentationBytes, final CborLimits cborLimits) {
        this.trust = Objects.requireNonNull(trust, "trust");
        this.status = Objects.requireNonNull(status, "status");
        this.cborLimits = Objects.requireNonNull(cborLimits, "cborLimits");
        if (maxPresentationBytes <= 0) {
            throw new IllegalArgumentException("limits must be positive");
        }
        this.maxPresentationBytes = maxPresentationBytes;
    }

    @Override
    public String format() {
        return FORMAT;
    }

    @Override
    public VerifiedPresentation verify(final String rawPresentation, final VerificationContext context) {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(context.clientId(), "clientId");
        Objects.requireNonNull(context.nonce(), "nonce");
        Objects.requireNonNull(context.responseUri(), "responseUri");
        Objects.requireNonNull(context.now(), "now");
        Objects.requireNonNull(context.anchors(), "anchors");
        Objects.requireNonNull(context.acceptedDoctype(), "acceptedDoctype");
        if (Objects.requireNonNull(context.clockSkew(), "clockSkew").isNegative()) {
            throw new IllegalArgumentException("clockSkew must not be negative");
        }
        try {
            return doVerify(rawPresentation, context);
        } catch (final WalletVerificationException e) {
            throw e;
        } catch (final RuntimeException e) {
            // Fail closed with a safe detail: library exception text may echo presentation content.
            throw fail(WalletErrorCode.INVALID_RESPONSE, "mdoc could not be verified");
        }
    }

    private VerifiedPresentation doVerify(final String raw, final VerificationContext ctx) {
        final CborValue.Dict document = document(deviceResponse(raw));

        if (!(document.get("docType").orElse(null) instanceof CborValue.Text docTypeText)) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "Document docType is missing");
        }
        final String docType = docTypeText.value();
        if (!docType.equals(ctx.acceptedDoctype())) {
            throw fail(WalletErrorCode.DOCTYPE_NOT_ACCEPTED, "Document docType is not accepted");
        }
        if (!(document.get("issuerSigned").orElse(null) instanceof CborValue.Dict issuerSigned)) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "Document has no issuerSigned");
        }

        // ---- IssuerAuth
        final CborValue issuerAuthValue = issuerSigned.get("issuerAuth")
                .orElseThrow(() -> fail(WalletErrorCode.INVALID_RESPONSE, "issuerSigned has no issuerAuth"));
        final CoseSign1 issuerAuth = CoseSign1.decode(issuerAuthValue, cborLimits);
        final byte[] msoBytes = issuerAuth.payload();
        if (msoBytes == null) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "IssuerAuth payload is detached");
        }
        final ValidatedChain issuerChain = trust.validateChain(issuerAuth.x5chain(), ctx.anchors(), ctx.now());
        final X509Certificate leaf = issuerChain.leaf();
        if (!issuerAuth.verify(leaf.getPublicKey(), null)) {
            throw fail(WalletErrorCode.ISSUER_SIGNATURE_INVALID, "IssuerAuth signature is invalid");
        }

        // ---- MSO
        final MobileSecurityObject mso = MobileSecurityObject.decode(msoBytes, cborLimits);
        if (!mso.docType().equals(docType)) {
            throw fail(WalletErrorCode.DOCTYPE_NOT_ACCEPTED, "MSO docType does not match the Document");
        }
        checkValidity(mso, leaf, ctx);

        // ---- IssuerSignedItems
        final Map<String, Object> claims = issuerSignedItems(issuerSigned, mso);

        // ---- DeviceAuth
        verifyDeviceAuth(document, docType, mso.deviceKey(), ctx);

        // ---- Status (only after holder binding)
        final String statusResult = checkStatus(mso.status(), issuerChain, ctx);

        return new VerifiedPresentation(FORMAT, docType, Collections.unmodifiableMap(claims),
                leaf.getSubjectX500Principal().getName(), leaf.getSerialNumber().toString(16), statusResult);
    }

    // ------------------------------------------------------------------------------------------- DeviceResponse

    private CborValue.Dict deviceResponse(final String raw) {
        if (raw == null || raw.isEmpty()) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "mdoc presentation is empty");
        }
        if (raw.length() > maxPresentationBytes) {
            throw fail(WalletErrorCode.LIMIT_EXCEEDED, "mdoc presentation exceeds " + maxPresentationBytes + " bytes");
        }
        if (!BASE64URL.matcher(raw).matches()) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "mdoc presentation is not base64url");
        }
        final byte[] bytes;
        try {
            bytes = Base64.getUrlDecoder().decode(raw);
        } catch (final IllegalArgumentException e) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "mdoc presentation is not base64url");
        }
        if (!(StrictCbor.decode(bytes, cborLimits) instanceof CborValue.Dict response)) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "DeviceResponse is not a map");
        }
        return response;
    }

    /** The single Document of a DeviceResponse whose version and status are acceptable. */
    private static CborValue.Dict document(final CborValue.Dict response) {
        if (!(response.get("version").orElse(null) instanceof CborValue.Text version)
                || !VERSION.matcher(version.value()).matches()) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "DeviceResponse version is not supported");
        }
        if (!(response.get("status").orElse(null) instanceof CborValue.Int st) || st.value() != 0) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "DeviceResponse status is not OK");
        }
        if (response.get("zkDocuments").isPresent() || response.get("encryptedDocuments").isPresent()) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "zkDocuments and encryptedDocuments are not supported");
        }
        if (!(response.get("documents").orElse(null) instanceof CborValue.Array documents)
                || documents.items().size() != 1
                || !(documents.items().get(0) instanceof CborValue.Dict document)) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "DeviceResponse must hold exactly one Document");
        }
        return document;
    }

    // ------------------------------------------------------------------------------------------- MSO validity

    private static void checkValidity(final MobileSecurityObject mso, final X509Certificate leaf,
            final VerificationContext ctx) {
        final Instant latest = ctx.now().plus(ctx.clockSkew());
        if (mso.signed().isAfter(latest)) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "MSO signed is in the future");
        }
        if (mso.validFrom().isAfter(latest)) {
            throw fail(WalletErrorCode.CREDENTIAL_NOT_YET_VALID, "MSO validFrom is in the future");
        }
        if (mso.validUntil().isBefore(ctx.now().minus(ctx.clockSkew()))) {
            throw fail(WalletErrorCode.CREDENTIAL_EXPIRED, "MSO validUntil has passed");
        }
        if (mso.validFrom().isBefore(leaf.getNotBefore().toInstant())
                || mso.validUntil().isAfter(leaf.getNotAfter().toInstant())) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "MSO validity is outside the IssuerAuth certificate validity");
        }
    }

    // ------------------------------------------------------------------------------------------- issuer-signed items

    /** One decoded IssuerSignedItem and the exact tag-24 bytes it arrived in. */
    private record Item(String namespace, int digestId, byte[] encoded, String elementIdentifier,
            CborValue elementValue) {

        /** Redacted: the value is personal data. */
        @Override
        public String toString() {
            return "Item[" + namespace + "#" + digestId + "]";
        }
    }

    private Map<String, Object> issuerSignedItems(final CborValue.Dict issuerSigned, final MobileSecurityObject mso) {
        final CborValue nameSpacesValue = issuerSigned.get("nameSpaces").orElse(null);
        if (nameSpacesValue == null) {
            return new LinkedHashMap<>();
        }
        if (!(nameSpacesValue instanceof CborValue.Dict nameSpaces)) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "issuerSigned nameSpaces is not a map");
        }
        // Pass 1: structure (and duplicates) before any digest, so a duplicate is never reported as a digest mismatch.
        final List<Item> items = new ArrayList<>();
        for (final Map.Entry<CborValue, CborValue> ns : nameSpaces.entries().entrySet()) {
            if (!(ns.getKey() instanceof CborValue.Text name) || !(ns.getValue() instanceof CborValue.Array list)
                    || list.items().isEmpty()) {
                throw fail(WalletErrorCode.INVALID_RESPONSE, "issuerSigned nameSpaces entry is malformed");
            }
            final Set<Integer> digestIds = new HashSet<>();
            final Set<String> identifiers = new HashSet<>();
            for (final CborValue value : list.items()) {
                final Item item = item(name.value(), value);
                if (!digestIds.add(item.digestId())) {
                    throw fail(WalletErrorCode.INVALID_RESPONSE, "digestID repeated within a namespace");
                }
                if (!identifiers.add(item.elementIdentifier())) {
                    throw fail(WalletErrorCode.INVALID_RESPONSE, "elementIdentifier repeated within a namespace");
                }
                items.add(item);
            }
        }
        // Pass 2: digests over the bytes as received.
        for (final Item item : items) {
            final Map<Integer, byte[]> digests = mso.valueDigests().get(item.namespace());
            final byte[] expected = digests == null ? null : digests.get(item.digestId());
            if (expected == null) {
                throw fail(WalletErrorCode.DIGEST_MISMATCH, "IssuerSignedItem digestID is not in the MSO");
            }
            if (!MessageDigest.isEqual(expected, digest(mso.digestAlgorithm(), item.encoded()))) {
                throw fail(WalletErrorCode.DIGEST_MISMATCH, "IssuerSignedItem digest does not match the MSO");
            }
        }
        // Pass 3: output.
        final Map<String, Object> claims = new LinkedHashMap<>();
        for (final Item item : items) {
            @SuppressWarnings("unchecked")
            final Map<String, Object> ns = (Map<String, Object>) claims.computeIfAbsent(item.namespace(),
                    k -> new LinkedHashMap<String, Object>());
            ns.put(item.elementIdentifier(), json(item.elementValue()));
        }
        claims.replaceAll((ns, elements) -> Collections.unmodifiableMap((Map<?, ?>) elements));
        return claims;
    }

    private Item item(final String namespace, final CborValue value) {
        if (!(value instanceof CborValue.Embedded embedded)) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "IssuerSignedItemBytes is not tag 24");
        }
        if (!(StrictCbor.decode(embedded.content(), cborLimits) instanceof CborValue.Dict item)
                || !(item.get("digestID").orElse(null) instanceof CborValue.Int digestId)
                || digestId.value() < 0 || digestId.value() > Integer.MAX_VALUE
                || !(item.get("random").orElse(null) instanceof CborValue.Bytes random)
                || random.value().length < MIN_RANDOM_BYTES
                || !(item.get("elementIdentifier").orElse(null) instanceof CborValue.Text identifier)
                || identifier.value().isEmpty()
                || item.get("elementValue").isEmpty()) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "IssuerSignedItem is malformed");
        }
        return new Item(namespace, (int) digestId.value(), embedded.encoded(), identifier.value(),
                item.get("elementValue").get());
    }

    private static byte[] digest(final String digestAlgorithm, final byte[] data) {
        try {
            // MobileSecurityObject admits only SHA-256 / SHA-384 / SHA-512, which are also the JCA names
            return MessageDigest.getInstance(digestAlgorithm).digest(data);
        } catch (final NoSuchAlgorithmException e) {
            throw fail(WalletErrorCode.ALGORITHM_NOT_ALLOWED, "MSO digestAlgorithm is not available");
        }
    }

    /** A CBOR element value as JSON-ish Java; see the class description. */
    private static Object json(final CborValue value) {
        return switch (value) {
            case CborValue.Text t -> t.value();
            case CborValue.Int i -> i.value();
            case CborValue.Real r when Double.isFinite(r.value()) -> r.value();
            case CborValue.Bool b -> b.value();
            case CborValue.Null n -> null;
            case CborValue.Bytes b -> Base64.getUrlEncoder().withoutPadding().encodeToString(b.value());
            case CborValue.Tagged t when t.tag() == TAG_FULL_DATE -> fullDate(t.content());
            case CborValue.Tagged t when t.tag() == TAG_TDATE -> tdate(t.content());
            case CborValue.Array a -> {
                final List<Object> list = new ArrayList<>(a.items().size());
                for (final CborValue item : a.items()) {
                    list.add(json(item));
                }
                yield Collections.unmodifiableList(list);
            }
            case CborValue.Dict d -> {
                final Map<String, Object> map = new LinkedHashMap<>();
                for (final Map.Entry<CborValue, CborValue> e : d.entries().entrySet()) {
                    final String key = e.getKey() instanceof CborValue.Text t ? t.value()
                            : Long.toString(((CborValue.Int) e.getKey()).value());
                    if (map.containsKey(key)) {
                        throw fail(WalletErrorCode.INVALID_RESPONSE, "element map keys collide as text");
                    }
                    map.put(key, json(e.getValue()));
                }
                yield Collections.unmodifiableMap(map);
            }
            default -> throw fail(WalletErrorCode.INVALID_RESPONSE, "element value type is not supported");
        };
    }

    private static String fullDate(final CborValue content) {
        final String text = ((CborValue.Text) content).value();
        if (!FULL_DATE.matcher(text).matches()) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "element value is not a valid full-date");
        }
        try {
            return LocalDate.parse(text, DateTimeFormatter.ISO_LOCAL_DATE).toString();
        } catch (final DateTimeParseException e) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "element value is not a valid full-date");
        }
    }

    private static String tdate(final CborValue content) {
        final String text = ((CborValue.Text) content).value();
        if (!TDATE.matcher(text).matches()) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "element value is not a UTC tdate");
        }
        try {
            return OffsetDateTime.parse(text, DateTimeFormatter.ISO_OFFSET_DATE_TIME).toInstant().toString();
        } catch (final DateTimeParseException e) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "element value is not a valid tdate");
        }
    }

    // ------------------------------------------------------------------------------------------- device auth

    /**
     * DeviceAuth over this verifier's own SessionTranscript. Every signature failure is
     * {@code HOLDER_BINDING_INVALID}: the transcript is hashed inside a detached signature, so the verifier cannot tell
     * whether the nonce, the client_id, the response_uri or the thumbprint differed.
     */
    private void verifyDeviceAuth(final CborValue.Dict document, final String docType, final PublicKey deviceKey,
            final VerificationContext ctx) {
        final CborValue deviceSignedValue = document.get("deviceSigned").orElse(null);
        if (deviceSignedValue == null) {
            throw fail(WalletErrorCode.HOLDER_BINDING_MISSING, "Document has no deviceSigned");
        }
        if (!(deviceSignedValue instanceof CborValue.Dict deviceSigned)
                || !(deviceSigned.get("nameSpaces").orElse(null) instanceof CborValue.Embedded deviceNameSpaces)) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "deviceSigned is malformed");
        }
        if (!(StrictCbor.decode(deviceNameSpaces.content(), cborLimits) instanceof CborValue.Dict deviceElements)) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "DeviceNameSpaces is not a map");
        }
        if (!deviceElements.entries().isEmpty()) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "device-signed data elements are not supported");
        }
        final CborValue deviceAuthValue = deviceSigned.get("deviceAuth").orElse(null);
        if (deviceAuthValue == null) {
            throw fail(WalletErrorCode.HOLDER_BINDING_MISSING, "deviceSigned has no deviceAuth");
        }
        if (!(deviceAuthValue instanceof CborValue.Dict deviceAuth)) {
            throw fail(WalletErrorCode.HOLDER_BINDING_INVALID, "deviceAuth is not a map");
        }
        if (deviceAuth.get("deviceMac").isPresent()) {
            throw fail(WalletErrorCode.HOLDER_BINDING_INVALID, "deviceMac is not supported");
        }
        final CborValue signatureValue = deviceAuth.get("deviceSignature")
                .orElseThrow(() -> fail(WalletErrorCode.HOLDER_BINDING_MISSING, "deviceAuth has no deviceSignature"));
        final CoseSign1 deviceSignature;
        try {
            deviceSignature = CoseSign1.decode(signatureValue, cborLimits);
        } catch (final WalletVerificationException e) {
            if (e.code() != WalletErrorCode.INVALID_RESPONSE) {
                throw e; // e.g. LIMIT_EXCEEDED from its protected header
            }
            throw fail(WalletErrorCode.HOLDER_BINDING_INVALID, "deviceSignature is not a COSE_Sign1");
        }
        if (deviceSignature.payload() != null) {
            throw fail(WalletErrorCode.HOLDER_BINDING_INVALID, "deviceSignature payload is not detached");
        }
        final byte[] transcript = SessionTranscripts.openId4VpRedirect(ctx.clientId(), ctx.nonce(),
                ctx.encryptionJwkThumbprint(), ctx.responseUri());
        final byte[] deviceAuthentication = SessionTranscripts.deviceAuthenticationBytes(transcript, docType,
                deviceNameSpaces.encoded());
        final boolean valid;
        try {
            valid = deviceSignature.verify(deviceKey, deviceAuthentication);
        } catch (final WalletVerificationException e) {
            if (e.code() != WalletErrorCode.ALGORITHM_NOT_ALLOWED) {
                throw e;
            }
            // alg missing, outside the allow-list, or not fitting the device key: like the SD-JWT KB-JWT path
            throw fail(WalletErrorCode.HOLDER_BINDING_INVALID, "deviceSignature alg is not usable with the device key");
        }
        if (!valid) {
            throw fail(WalletErrorCode.HOLDER_BINDING_INVALID,
                    "deviceSignature does not verify over the expected SessionTranscript");
        }
    }

    // ------------------------------------------------------------------------------------------- status

    /** Status policy via the shared {@link StatusCheck} (identical to the SD-JWT VC verifier). */
    private String checkStatus(final MobileSecurityObject.Status msoStatus, final ValidatedChain issuerChain,
            final VerificationContext ctx) {
        if (msoStatus == null) {
            return StatusCheck.absent(ctx.statusPolicy(), "MSO has no status");
        }
        if (!(msoStatus instanceof MobileSecurityObject.StatusList list)) {
            return StatusCheck.notEvaluable(ctx.statusPolicy(), "MSO status mechanism cannot be evaluated");
        }
        // ISO §12.3.6: the evaluator binds the list signer to the MSO signer, or to status_list.certificate
        return StatusCheck.evaluate(status, list.reference(), ctx.anchors(),
                new CredentialIssuer(issuerChain, list.certificate()), ctx.statusPolicy());
    }

    private static WalletVerificationException fail(final WalletErrorCode code, final String safeDetail) {
        return new WalletVerificationException(code, safeDetail);
    }
}
