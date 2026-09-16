package group.mfnr.authorization.security.flow;

import group.mfnr.authorization.flow.qr.QrLoginService;
import group.mfnr.authorization.flow.qr.QrSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Helix IAM E4.2: the cross-device QR-login endpoints, deliberately <b>poll-based</b> (not SSE).
 * The browser short-polls {@code GET /qr/{id}} for status; the enrolled phone {@code POST}s
 * {@code /qr/{id}/confirm} with a device-signed token. Both are stateless reads/writes against the
 * shared {@link QrSessionStore}, so any publisher instance serves any request — this scales
 * horizontally with no held connections and no cross-node push/pub-sub (the trap SSE would create).
 * Secured by the device signature + single-use rotating token (permitted + CSRF-exempt in SecurityConfig).
 */
@RestController
public class QrLoginController {

    private final QrLoginService qrLoginService;

    public QrLoginController(final QrLoginService qrLoginService) {
        this.qrLoginService = qrLoginService;
    }

    /** Browser poll: current status (+ the freshly rotated token so the QR can refresh). */
    @GetMapping("/qr/{id}")
    public Map<String, String> status(@PathVariable final String id) {
        return qrLoginService.refresh(id)
                .map(s -> Map.of("status", s.status().name(), "token", s.currentToken()))
                .orElse(Map.of("status", QrSession.Status.EXPIRED.name()));
    }

    /** Phone confirmation: verify the device signature over the token, then flip to CONFIRMED. */
    @PostMapping("/qr/{id}/confirm")
    public Map<String, Boolean> confirm(@PathVariable final String id, @RequestBody final ConfirmRequest request) {
        final boolean confirmed = qrLoginService.confirm(
                id, request.token(), request.userId(), request.deviceId(), request.signature());
        return Map.of("confirmed", confirmed);
    }

    /** Phone confirmation payload: the scanned token + the enrolled device's ES256 signature over it. */
    public record ConfirmRequest(String token, String userId, String deviceId, String signature) {
    }
}
