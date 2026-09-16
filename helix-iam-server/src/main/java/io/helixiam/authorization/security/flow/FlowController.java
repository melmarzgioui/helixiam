package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.flow.AuthFlow;
import io.helixiam.authorization.flow.FlowExecutionState;
import io.helixiam.authorization.flow.FlowExecutor;
import io.helixiam.authorization.flow.FlowProgress;
import io.helixiam.authorization.flow.persistence.AuthFlowDefinition;
import io.helixiam.authorization.flow.persistence.AuthFlowMapper;
import io.helixiam.authorization.service.MfaService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.HashMap;
import java.util.Map;

/**
 * Helix IAM E2.4/E3: the generic engine-driven challenge endpoint. It renders whatever view the
 * current authenticator asked for via {@code challenge("<view>")} (template {@code flow/<view>}),
 * and feeds every submitted field back into the {@link FlowExecutor} at whichever execution the
 * engine is challenging. Fully generic over flow shape and authenticator — a new factor's screen
 * works with no controller change, just a {@code templates/flow/<view>.html}. Active only when
 * {@code helix.flow-engine.enabled=true}.
 */
@Controller
public class FlowController {

    private static final String REDIRECT_PREFIX = "redirect:";
    private static final String VIEW_PREFIX = "flow/";

    private final FlowExecutor flowExecutor;
    private final AuthFlowMapper authFlowMapper;
    private final MfaService mfaService;
    private final String spBaseUrl;
    private final String rpId;
    private final io.helixiam.authorization.security.realm.SessionPolicyApplier sessionPolicyApplier;
    // SSO P1: resume the originating /oauth2/authorize once the post-password flow completes.
    private final ResolveSavedRequestRedirect savedRequestRedirect = new ResolveSavedRequestRedirect();
    private final io.helixiam.authorization.security.session.AuthTimeStamper authTimeStamper =
            new io.helixiam.authorization.security.session.AuthTimeStamper();

    public FlowController(final FlowExecutor flowExecutor, final AuthFlowMapper authFlowMapper,
                          final MfaService mfaService, @Value("${sp.base.url}") final String spBaseUrl,
                          @Value("${helix.webauthn.rp-id:localhost}") final String rpId,
                          final io.helixiam.authorization.security.realm.SessionPolicyApplier sessionPolicyApplier) {
        this.flowExecutor = flowExecutor;
        this.authFlowMapper = authFlowMapper;
        this.mfaService = mfaService;
        this.spBaseUrl = spBaseUrl;
        this.rpId = rpId;
        this.sessionPolicyApplier = sessionPolicyApplier;
    }

    @GetMapping("/flow")
    public String renderChallenge(final HttpSession session, final Model model) {
        final FlowExecutionState state = state(session);
        if (state == null || state.currentChallengeView() == null) {
            return REDIRECT_PREFIX + flowPath("/login");
        }
        // The challenge form must post back to the realm-prefixed /flow, not the flat path the
        // controller maps at — otherwise the realm-routing guard 404s the submission.
        model.addAttribute("flowAction", flowPath("/flow"));
        // Expose data a challenge screen needs. WebAuthn renders the server challenge + rpId so
        // the browser can run navigator.credentials.get(); other views simply ignore these.
        final Map<String, Object> execAttributes = state.attributesFor(state.currentChallengeExecutionId());
        model.addAttribute("webauthnChallenge", execAttributes.get("webauthn.challenge"));
        // (10) passwordless usernameless passkey login challenge (resident-key / conditional UI).
        model.addAttribute("passkeyLoginChallenge", execAttributes.get("passkey-login.challenge"));
        model.addAttribute("rpId", rpId);
        // QR login (E4.2): the view renders helix://qr-login/{id}?t={token} and watches /qr/{id}.
        model.addAttribute("qrSessionId", execAttributes.get("qr.session"));
        model.addAttribute("qrToken", execAttributes.get("qr.token"));
        // Push approval (E4.3): the view shows the number to match and watches /push/{id}.
        model.addAttribute("pushId", execAttributes.get("push.id"));
        model.addAttribute("pushNumber", execAttributes.get("push.number"));
        return VIEW_PREFIX + state.currentChallengeView();
    }

    @PostMapping("/flow")
    public String submitChallenge(@RequestParam final Map<String, String> params,
                                  final HttpSession session, final Model model,
                                  final HttpServletRequest request, final HttpServletResponse response) {
        final FlowExecutionState state = state(session);
        final AuthFlowDefinition definition =
                (AuthFlowDefinition) session.getAttribute(FlowLoginSuccessHandler.FLOW_DEFINITION_ATTRIBUTE);
        if (state == null || definition == null || state.currentChallengeExecutionId() == null) {
            return REDIRECT_PREFIX + flowPath("/login");
        }
        model.addAttribute("flowAction", flowPath("/flow"));

        final Map<String, String> formData = new HashMap<>(params);
        formData.remove("_csrf");

        final AuthFlow flow = authFlowMapper.toAuthFlow(definition);
        final FlowProgress progress =
                flowExecutor.submit(flow, state, state.currentChallengeExecutionId(), formData);
        session.setAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE, state);

        return switch (progress.type()) {
            case COMPLETED -> {
                mfaService.unlockUser(); // restore the fully authenticated token
                authTimeStamper.stamp(request); // SSO P2
                sessionPolicyApplier.applyOnLogin(request, io.helixiam.authorization.security.realm.RealmContextHolder.get()); // SSO P3
                yield savedRequestRedirect.redirectView(request, response, spBaseUrl);
            }
            case CHALLENGE -> REDIRECT_PREFIX + flowPath("/flow"); // advanced to the next factor's screen
            case FAILED -> {
                model.addAttribute("error", "true"); // wrong response — re-prompt with an error
                yield VIEW_PREFIX + state.currentChallengeView();
            }
        };
    }

    private FlowExecutionState state(final HttpSession session) {
        return (FlowExecutionState) session.getAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE);
    }

    /** Realm-prefix a controller path so browser redirects/form posts survive the realm-routing guard. */
    private String flowPath(final String path) {
        return io.helixiam.authorization.security.realm.RealmPaths.prefixed(
                io.helixiam.authorization.security.realm.RealmContextHolder.get(), path);
    }
}
