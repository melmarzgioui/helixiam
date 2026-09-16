package group.mfnr.authorization.flow.wysiwys;

import java.util.Map;
import java.util.TreeMap;

/**
 * Helix IAM E4.4: builds the canonical, length-prefixed representation of a transaction for WYSIWYS
 * "dynamic linking" (PSD2-SCA). The server and the phone derive byte-identical challenges from the
 * same fields, and the phone displays exactly these fields — so what the user sees is what the
 * device key signs. Length-prefixing every segment makes the encoding unambiguous: no two distinct
 * field sets can serialize to the same bytes (no boundary-collision / signature-reuse).
 */
public final class WysiwysCanonicalizer {

    private static final String VERSION = "WYSIWYS-v1";

    private WysiwysCanonicalizer() {
    }

    /**
     * @param action the operation being authorized (e.g. "payment")
     * @param params the transaction fields shown to the user (rendered in sorted-key order)
     * @param nonce  the single-use server nonce binding this signature to this request
     * @param expiry the absolute expiry (epoch millis) past which the signature is invalid
     * @return a deterministic, length-prefixed canonical string; sign its UTF-8 bytes
     */
    public static String canonicalize(final String action, final Map<String, String> params,
                                      final String nonce, final long expiry) {
        final StringBuilder sb = new StringBuilder();
        sb.append(VERSION).append('\n');
        segment(sb, "action", action);
        // Sort by key so insertion order can't change the bytes the user signs.
        for (final Map.Entry<String, String> entry : new TreeMap<>(params).entrySet()) {
            segment(sb, entry.getKey(), entry.getValue());
        }
        segment(sb, "nonce", nonce);
        segment(sb, "expiry", Long.toString(expiry));
        return sb.toString();
    }

    /** A length-prefixed {@code key=len:value} line; lengths are over UTF-8 bytes. */
    private static void segment(final StringBuilder sb, final String key, final String value) {
        final String safeKey = key == null ? "" : key;
        final String safeValue = value == null ? "" : value;
        final int keyLen = safeKey.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        final int valueLen = safeValue.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        sb.append(keyLen).append(':').append(safeKey).append('=')
          .append(valueLen).append(':').append(safeValue).append('\n');
    }
}
