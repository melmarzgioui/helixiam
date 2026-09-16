package group.mfnr.authorization.flow.push;

import group.mfnr.authorization.flow.authenticators.CredentialVerifier;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.IntSupplier;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * Helix IAM E4.3: orchestrates "approve on your phone" with number matching. {@link #start} mints an
 * approval (random id + nonce + a 2-digit number among decoys), stores it and sends it via the
 * {@link PushSender}. The phone {@link #approve}s by signing the nonce with its device key (verified
 * through the generic device {@link CredentialVerifier}, reusing E4.1) AND tapping the matching
 * number — both are required, so a stolen push can't be blindly approved (MFA-fatigue resistant).
 * The browser then {@link #consume}s the APPROVED request once. Poll-based, no held connections.
 */
public class PushApprovalService {

    private static final int CANDIDATE_COUNT = 3;

    private final PushApprovalStore store;
    private final CredentialVerifier credentialVerifier;
    private final PushSender pushSender;
    private final Supplier<String> tokenGenerator;
    private final IntSupplier numberGenerator;
    private final LongSupplier clock;
    private final long ttlMillis;

    public PushApprovalService(final PushApprovalStore store, final CredentialVerifier credentialVerifier,
                               final PushSender pushSender, final Supplier<String> tokenGenerator,
                               final IntSupplier numberGenerator, final LongSupplier clock, final long ttlMillis) {
        this.store = store;
        this.credentialVerifier = credentialVerifier;
        this.pushSender = pushSender;
        this.tokenGenerator = tokenGenerator;
        this.numberGenerator = numberGenerator;
        this.clock = clock;
        this.ttlMillis = ttlMillis;
    }

    /** Mints + stores + pushes a number-matching approval; returns it so the browser shows the number. */
    public PushApproval start(final String userId) {
        final String id = tokenGenerator.get();
        final String challenge = tokenGenerator.get();
        final int expected = numberGenerator.getAsInt();

        final Set<Integer> candidates = new LinkedHashSet<>();
        candidates.add(expected);
        while (candidates.size() < CANDIDATE_COUNT) {
            candidates.add(numberGenerator.getAsInt());
        }

        final PushApproval approval = new PushApproval(id, userId, expected, challenge, clock.getAsLong(), ttlMillis);
        store.save(approval);
        pushSender.send(new PushMessage(id, userId, challenge, expected, new ArrayList<>(candidates)));
        return approval;
    }

    /**
     * Phone response: verify the device signature over the nonce (ES256, via the device Credential
     * SPI) <b>against the user the approval is bound to</b>, then accept only if the tapped number
     * matches. The user is taken from the stored approval — never from the request — so a different
     * user's enrolled device cannot approve this approval (IDOR/auth-bypass). A bad signature is
     * rejected without changing state; a wrong number is recorded as a DENY.
     */
    public boolean approve(final String id, final int selectedNumber,
                           final String deviceId, final String signatureB64Url) {
        final PushApproval approval = store.find(id).orElse(null);
        if (approval == null || !verifyDevice(approval, deviceId, signatureB64Url)) {
            return false;
        }
        final boolean approved = approval.approve(selectedNumber, clock.getAsLong());
        store.save(approval);
        return approved;
    }

    /** Explicit deny from the phone ("It wasn't me"), gated on the bound user's device signature. */
    public boolean deny(final String id, final String deviceId, final String signatureB64Url) {
        final PushApproval approval = store.find(id).orElse(null);
        if (approval == null || !verifyDevice(approval, deviceId, signatureB64Url)) {
            return false;
        }
        approval.deny();
        store.save(approval);
        return true;
    }

    /** Single-use consume by the initiating browser; returns the bound user id or null. */
    public String consume(final String id) {
        final PushApproval approval = store.find(id).orElse(null);
        if (approval == null) {
            return null;
        }
        final String userId = approval.consume();
        if (userId != null) {
            store.save(approval);
        }
        return userId;
    }

    /** Current status for the poll stream; UNKNOWN if the id is not (or no longer) present. */
    public String status(final String id) {
        return store.find(id).map(a -> a.status().name()).orElse("UNKNOWN");
    }

    private boolean verifyDevice(final PushApproval approval, final String deviceId, final String signatureB64Url) {
        // Always verify against the user the approval is bound to — never a client-supplied id — so a
        // different user's enrolled device cannot resolve this approval (auth bypass / IDOR).
        final String challenge = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(approval.challenge().getBytes(StandardCharsets.UTF_8));
        final String input = json("deviceId", deviceId, "challenge", challenge, "signature", signatureB64Url);
        return credentialVerifier.verify("device", approval.userId(), input);
    }

    private static String json(final String... kv) {
        final StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < kv.length; i += 2) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append('"').append(kv[i]).append("\":\"").append(escape(kv[i + 1])).append('"');
        }
        return sb.append('}').toString();
    }

    private static String escape(final String value) {
        return value == null ? "" : value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
