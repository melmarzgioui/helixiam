package group.mfnr.authorization.security.flow;

import group.mfnr.authorization.amqp.mfa.MfaWebAuthnPublisher;
import group.mfnr.authorization.amqp.mfa.WebAuthnRegistration;
import group.mfnr.authorization.domain.UserCredentials;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Helix IAM E3.3: passkey enrollment for the logged-in user. GET issues a creation challenge and
 * renders the page that runs {@code navigator.credentials.create()}; POST forwards the attestation
 * to the subscriber (which verifies + stores the credential). Active only when the flow engine is
 * enabled.
 */
@Controller
public class WebAuthnRegistrationController {

    private static final String CHALLENGE_SESSION_ATTR = "WEBAUTHN_REG_CHALLENGE";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final MfaWebAuthnPublisher publisher;
    private final String rpId;
    private final String origin;

    public WebAuthnRegistrationController(final MfaWebAuthnPublisher publisher,
                                          @Value("${helix.webauthn.rp-id:localhost}") final String rpId,
                                          @Value("${helix.webauthn.origin:http://localhost:8083}") final String origin) {
        this.publisher = publisher;
        this.rpId = rpId;
        this.origin = origin;
    }

    @GetMapping("/webauthn/register")
    public String page(@AuthenticationPrincipal final UserCredentials user, final HttpSession session, final Model model) {
        final byte[] challenge = new byte[32];
        RANDOM.nextBytes(challenge);
        final String challengeB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(challenge);
        session.setAttribute(CHALLENGE_SESSION_ATTR, challengeB64);

        model.addAttribute("challenge", challengeB64);
        model.addAttribute("rpId", rpId);
        model.addAttribute("userId", user.getUserId());
        model.addAttribute("username", user.getEmail() != null ? user.getEmail() : user.getUserId());
        return "mfa/webauthn-register";
    }

    @PostMapping("/webauthn/register")
    public String register(@RequestParam final String attestationObject, @RequestParam final String clientDataJSON,
                           @AuthenticationPrincipal final UserCredentials user, final HttpSession session,
                           final Model model) {
        final String challenge = (String) session.getAttribute(CHALLENGE_SESSION_ATTR);
        if (challenge == null) {
            model.addAttribute("error", "true");
            return page(user, session, model);
        }
        final boolean ok = Boolean.TRUE.equals(publisher.register(new WebAuthnRegistration(
                user.getUserId(), attestationObject, clientDataJSON, challenge, origin, rpId)));
        session.removeAttribute(CHALLENGE_SESSION_ATTR);
        model.addAttribute(ok ? "registered" : "error", "true");
        return "mfa/webauthn-register";
    }
}
