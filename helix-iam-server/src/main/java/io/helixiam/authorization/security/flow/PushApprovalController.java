package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.flow.push.PushApprovalService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Helix IAM E4.3: push-approval endpoints, poll-based (not SSE) for the same horizontal-scale reasons
 * as QR login. The browser short-polls {@code GET /push/{id}} for status; the enrolled phone resolves
 * it with {@code POST /push/{id}/approve} (number tapped + device-signed) or {@code /deny}. Stateless
 * against the shared store, so any instance serves any request. Permitted + CSRF-exempt in SecurityConfig
 * (secured by the device signature + number matching).
 */
@RestController
public class PushApprovalController {

    private final PushApprovalService pushApprovalService;

    public PushApprovalController(final PushApprovalService pushApprovalService) {
        this.pushApprovalService = pushApprovalService;
    }

    @GetMapping("/push/{id}")
    public Map<String, String> status(@PathVariable final String id) {
        return Map.of("status", pushApprovalService.status(id));
    }

    @PostMapping("/push/{id}/approve")
    public Map<String, Boolean> approve(@PathVariable final String id, @RequestBody final ApproveRequest request) {
        return Map.of("approved", pushApprovalService.approve(
                id, request.selectedNumber(), request.deviceId(), request.signature()));
    }

    @PostMapping("/push/{id}/deny")
    public Map<String, Boolean> deny(@PathVariable final String id, @RequestBody final DenyRequest request) {
        return Map.of("denied", pushApprovalService.deny(id, request.deviceId(), request.signature()));
    }

    // The approved user is taken from the stored approval (the device must belong to it), never from
    // the request body — so the client cannot supply the user it's approving for (auth bypass / IDOR).

    /** Phone approval payload: the tapped number + the device's ES256 signature over the nonce. */
    public record ApproveRequest(int selectedNumber, String deviceId, String signature) {
    }

    /** Phone deny payload ("It wasn't me"), still device-signed. */
    public record DenyRequest(String deviceId, String signature) {
    }
}
