package group.mfnr.authorization.idp.ciba;

import group.mfnr.authorization.flow.push.PushApproval;
import group.mfnr.authorization.flow.push.PushApprovalService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Supplier;

/**
 * Helix IAM E7.5: OIDC CIBA (Client-Initiated Backchannel Authentication) — decoupled login for
 * call-centre / POS / smart-device flows where the consumption device isn't where the user
 * authenticates. It reuses the E4.3 device push: a backchannel request pushes an approval to the
 * user's phone, and the client polls until the user approves on the device.
 *
 * <p>{@link #requestAuthentication} starts a push and returns an {@code auth_req_id}; the client polls
 * {@link #poll} (at the token endpoint, grant {@code urn:openid:params:grant-type:ciba}) which maps
 * the push approval state to {@code authorization_pending} / denied / expired / approved(user).
 */
@Service
public class CibaBackchannelService {

    private static final long EXPIRES_IN_SECONDS = 120;
    private static final long POLL_INTERVAL_SECONDS = 5;

    private final PushApprovalService pushApprovalService;
    private final Supplier<String> authReqIdGenerator;
    private final ConcurrentMap<String, Pending> requests = new ConcurrentHashMap<>();

    @Autowired
    public CibaBackchannelService(final PushApprovalService pushApprovalService) {
        this(pushApprovalService, CibaBackchannelService::randomId);
    }

    CibaBackchannelService(final PushApprovalService pushApprovalService, final Supplier<String> authReqIdGenerator) {
        this.pushApprovalService = pushApprovalService;
        this.authReqIdGenerator = authReqIdGenerator;
    }

    private record Pending(String clientId, String userId, String scope, String pushApprovalId) {
    }

    /** A backchannel authentication request: the client polls with {@code authReqId}. */
    public record AuthResponse(String authReqId, long expiresInSeconds, long intervalSeconds) {
    }

    public enum PollStatus { PENDING, DENIED, EXPIRED, APPROVED }

    /** Poll result: {@code userId} is populated only when {@link PollStatus#APPROVED}. */
    public record PollResult(PollStatus status, String userId) {
    }

    /** Start a backchannel authentication for the resolved user (login_hint already resolved). */
    public AuthResponse requestAuthentication(final String clientId, final String userId, final String scope,
                                              final String bindingMessage) {
        final PushApproval approval = pushApprovalService.start(userId);
        final String authReqId = authReqIdGenerator.get();
        requests.put(authReqId, new Pending(clientId, userId, scope, approval.id()));
        return new AuthResponse(authReqId, EXPIRES_IN_SECONDS, POLL_INTERVAL_SECONDS);
    }

    /** Poll the backchannel request; the client must own the {@code authReqId}. */
    public PollResult poll(final String authReqId, final String clientId) {
        final Pending pending = requests.get(authReqId);
        if (pending == null) {
            throw new IllegalArgumentException("Unknown or expired auth_req_id");
        }
        if (!pending.clientId().equals(clientId)) {
            throw new IllegalStateException("auth_req_id does not belong to the requesting client");
        }
        return switch (pushApprovalService.status(pending.pushApprovalId())) {
            case "APPROVED", "CONSUMED" -> {
                requests.remove(authReqId); // single-use once approved
                yield new PollResult(PollStatus.APPROVED, pending.userId());
            }
            case "DENIED" -> new PollResult(PollStatus.DENIED, null);
            case "EXPIRED", "UNKNOWN" -> new PollResult(PollStatus.EXPIRED, null);
            default -> new PollResult(PollStatus.PENDING, null);
        };
    }

    private static String randomId() {
        final byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
