/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.mdoc;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * The ISO 18013-5 SessionTranscript for OpenID4VP and the DeviceAuthentication bytes signed over it
 * (docs/eudi-wallet-spec-notes.md §1.9, §6.3; OpenID4VP 1.0 Appendix B.2.6.1):
 *
 * <pre>
 * OpenID4VPHandoverInfo = [clientId: tstr, nonce: tstr, jwkThumbprint: bstr / null, responseUri: tstr]
 * OpenID4VPHandover     = ["OpenID4VPHandover", bstr SHA-256(CBOR(OpenID4VPHandoverInfo))]
 * SessionTranscript     = [null, null, OpenID4VPHandover]
 * </pre>
 *
 * <p>Encoded with definite lengths and the shortest length heads (RFC 8949 preferred serialisation), as the spec
 * example is; the output matches the Appendix B.2.6.1 vector byte for byte. The verifier builds the transcript from its
 * own transaction values, never from the presentation.
 */
public final class SessionTranscripts {

    private static final int MAJOR_BYTES = 2;
    private static final int MAJOR_TEXT = 3;
    private static final int MAJOR_ARRAY = 4;
    private static final int CBOR_NULL = 0xf6;
    private static final byte[] TAG_24 = {(byte) 0xd8, 0x18};

    private SessionTranscripts() {
    }

    /**
     * The SessionTranscript of an OpenID4VP redirect / {@code direct_post} flow.
     *
     * @param clientId            the full {@code client_id}, with its Client Identifier Prefix
     * @param nonce               the request {@code nonce}
     * @param jwkThumbprintOrNull the raw RFC 7638 SHA-256 thumbprint of the response encryption key, or null when the
     *                            response is not encrypted
     * @param responseUri         the {@code response_uri} (or {@code redirect_uri}) of the request
     * @return the encoded SessionTranscript
     */
    public static byte[] openId4VpRedirect(final String clientId, final String nonce, final byte[] jwkThumbprintOrNull,
            final String responseUri) {
        final byte[] handover = handover(clientId, nonce, jwkThumbprintOrNull, responseUri);
        final ByteArrayOutputStream out = new ByteArrayOutputStream(handover.length + 3);
        writeHead(out, MAJOR_ARRAY, 3);
        out.write(CBOR_NULL); // DeviceEngagementBytes
        out.write(CBOR_NULL); // EReaderKeyBytes
        out.writeBytes(handover);
        return out.toByteArray();
    }

    /** The encoded OpenID4VPHandover. */
    static byte[] handover(final String clientId, final String nonce, final byte[] jwkThumbprintOrNull,
            final String responseUri) {
        final byte[] infoHash = sha256(handoverInfo(clientId, nonce, jwkThumbprintOrNull, responseUri));
        final ByteArrayOutputStream out = new ByteArrayOutputStream(64);
        writeHead(out, MAJOR_ARRAY, 2);
        writeText(out, "OpenID4VPHandover");
        writeBytes(out, infoHash);
        return out.toByteArray();
    }

    /** The encoded OpenID4VPHandoverInfo. */
    static byte[] handoverInfo(final String clientId, final String nonce, final byte[] jwkThumbprintOrNull,
            final String responseUri) {
        Objects.requireNonNull(clientId, "clientId");
        Objects.requireNonNull(nonce, "nonce");
        Objects.requireNonNull(responseUri, "responseUri");
        final ByteArrayOutputStream out = new ByteArrayOutputStream(256);
        writeHead(out, MAJOR_ARRAY, 4);
        writeText(out, clientId);
        writeText(out, nonce);
        if (jwkThumbprintOrNull == null) {
            out.write(CBOR_NULL);
        } else {
            writeBytes(out, jwkThumbprintOrNull);
        }
        writeText(out, responseUri);
        return out.toByteArray();
    }

    /**
     * The SessionTranscript of an OpenID4VP request over the W3C Digital Credentials API (OpenID4VP 1.0 Appendix
     * B.2.6.2): {@code [null, null, ["OpenID4VPDCAPIHandover", bstr SHA-256(CBOR([origin, nonce, jwkThumbprint /
     * null]))]]}. Matches the Appendix B.2.6.2 example byte for byte.
     *
     * @param origin              the web Origin the response is bound to, <em>without</em> the {@code origin:} prefix
     *                            (the verifier's own expected origin, never a value taken from the response)
     * @param nonce               the request {@code nonce}
     * @param jwkThumbprintOrNull the raw RFC 7638 SHA-256 thumbprint of the response encryption key for
     *                            {@code dc_api.jwt}, or null for {@code dc_api}
     * @throws IllegalArgumentException when {@code origin} carries the {@code origin:} prefix
     */
    public static byte[] openId4VpDcApi(final String origin, final String nonce, final byte[] jwkThumbprintOrNull) {
        final byte[] handover = dcApiHandover(origin, nonce, jwkThumbprintOrNull);
        final ByteArrayOutputStream out = new ByteArrayOutputStream(handover.length + 3);
        writeHead(out, MAJOR_ARRAY, 3);
        out.write(CBOR_NULL); // DeviceEngagementBytes
        out.write(CBOR_NULL); // EReaderKeyBytes
        out.writeBytes(handover);
        return out.toByteArray();
    }

    /** The encoded OpenID4VPDCAPIHandover. */
    static byte[] dcApiHandover(final String origin, final String nonce, final byte[] jwkThumbprintOrNull) {
        final byte[] infoHash = sha256(dcApiHandoverInfo(origin, nonce, jwkThumbprintOrNull));
        final ByteArrayOutputStream out = new ByteArrayOutputStream(64);
        writeHead(out, MAJOR_ARRAY, 2);
        writeText(out, "OpenID4VPDCAPIHandover");
        writeBytes(out, infoHash);
        return out.toByteArray();
    }

    /** The encoded OpenID4VPDCAPIHandoverInfo {@code [origin, nonce, jwkThumbprint / null]}. */
    static byte[] dcApiHandoverInfo(final String origin, final String nonce, final byte[] jwkThumbprintOrNull) {
        Objects.requireNonNull(origin, "origin");
        Objects.requireNonNull(nonce, "nonce");
        if (origin.startsWith("origin:")) {
            throw new IllegalArgumentException("The DC API handover takes the bare Origin, not the origin: audience");
        }
        final ByteArrayOutputStream out = new ByteArrayOutputStream(160);
        writeHead(out, MAJOR_ARRAY, 3);
        writeText(out, origin);
        writeText(out, nonce);
        if (jwkThumbprintOrNull == null) {
            out.write(CBOR_NULL);
        } else {
            writeBytes(out, jwkThumbprintOrNull);
        }
        return out.toByteArray();
    }

    /**
     * DeviceAuthenticationBytes {@code #6.24(bstr .cbor ["DeviceAuthentication", SessionTranscript, DocType,
     * DeviceNameSpacesBytes])}, the detached content of the device signature (draft §12.4.4).
     *
     * @param sessionTranscript     the encoded SessionTranscript, embedded byte-exact
     * @param docType               the Document's docType
     * @param deviceNameSpacesBytes the Document's DeviceNameSpacesBytes (the whole tag-24 item) exactly as received
     */
    static byte[] deviceAuthenticationBytes(final byte[] sessionTranscript, final String docType,
            final byte[] deviceNameSpacesBytes) {
        final ByteArrayOutputStream inner = new ByteArrayOutputStream(
                sessionTranscript.length + deviceNameSpacesBytes.length + docType.length() + 32);
        writeHead(inner, MAJOR_ARRAY, 4);
        writeText(inner, "DeviceAuthentication");
        inner.writeBytes(sessionTranscript);
        writeText(inner, docType);
        inner.writeBytes(deviceNameSpacesBytes);
        final byte[] content = inner.toByteArray();
        final ByteArrayOutputStream out = new ByteArrayOutputStream(content.length + 8);
        out.writeBytes(TAG_24);
        writeBytes(out, content);
        return out.toByteArray();
    }

    private static void writeText(final ByteArrayOutputStream out, final String text) {
        final byte[] utf8 = text.getBytes(StandardCharsets.UTF_8);
        writeHead(out, MAJOR_TEXT, utf8.length);
        out.writeBytes(utf8);
    }

    private static void writeBytes(final ByteArrayOutputStream out, final byte[] bytes) {
        writeHead(out, MAJOR_BYTES, bytes.length);
        out.writeBytes(bytes);
    }

    /** A definite-length head with the shortest argument encoding (RFC 8949 §4.2.1); lengths fit in 32 bits. */
    private static void writeHead(final ByteArrayOutputStream out, final int major, final long length) {
        final int m = major << 5;
        if (length < 24) {
            out.write(m | (int) length);
        } else if (length < 0x100) {
            out.write(m | 24);
            out.write((int) length);
        } else if (length < 0x10000) {
            out.write(m | 25);
            out.write((int) (length >> 8) & 0xff);
            out.write((int) length & 0xff);
        } else {
            out.write(m | 26);
            for (int shift = 24; shift >= 0; shift -= 8) {
                out.write((int) (length >> shift) & 0xff);
            }
        }
    }

    private static byte[] sha256(final byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
