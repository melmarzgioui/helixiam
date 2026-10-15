/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

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

    private static final org.apache.logging.log4j.Logger LOG =
            org.apache.logging.log4j.LogManager.getLogger(FlowController.class);

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
    /** Task 18: make a federated login's pending commit when its step-up completes. */
    private java.util.List<io.helixiam.authorization.federation.FederatedLoginCommit> loginCommits = java.util.List.of();
    /** Final review F2: report how a federated login that stepped up ended (its connector's audit). */
    private java.util.List<io.helixiam.authorization.federation.FederatedLoginOutcome> loginOutcomes = java.util.List.of();

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

    /** Task 18: the committers of a federated login's pending commit (none → such a login is refused). */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setLoginCommits(
            final java.util.List<io.helixiam.authorization.federation.FederatedLoginCommit> loginCommits) {
        this.loginCommits = loginCommits == null ? java.util.List.of() : java.util.List.copyOf(loginCommits);
    }

    /** Realm requires MFA, user not enrolled: the completed flow sends the user to enrolment (null: not checked). */
    private io.helixiam.authorization.security.mfa.MfaEnrolmentRequirement mfaEnrolment;

    /** The same enrolment rule as {@link FlowLoginSuccessHandler} and the federated completion. */
    @org.springframework.beans.factory.annotation.Autowired
    public void setMfaEnrolment(final io.helixiam.authorization.security.mfa.MfaEnrolmentRequirement mfaEnrolment) {
        this.mfaEnrolment = mfaEnrolment;
    }

    /** Final review F2: the receivers of a federated login's outcome marker. */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setLoginOutcomes(
            final java.util.List<io.helixiam.authorization.federation.FederatedLoginOutcome> loginOutcomes) {
        this.loginOutcomes = loginOutcomes == null ? java.util.List.of() : java.util.List.copyOf(loginOutcomes);
    }

    @GetMapping("/flow")
    public String renderChallenge(final HttpSession session, final Model model) {
        final FlowExecutionState state = state(session);
        if (state == null || state.currentChallengeView() == null) {
            return REDIRECT_PREFIX + "/login";
        }
        // The challenge form must post back to the realm-prefixed /flow, not the flat path the
        // controller maps at — otherwise the realm-routing guard 404s the submission.
        model.addAttribute("flowAction", flowPath("/flow"));
        // Expose data a challenge screen needs. WebAuthn renders the server challenge + rpId so
        // the browser can run navigator.credentials.get(); other views simply ignore these.
        final Map<String, Object> execAttributes = state.attributesFor(state.currentChallengeExecutionId());
        // A step that challenges on another page (the EUDI wallet verification: the wallet page) sends the browser
        // there ONCE; coming back to /flow renders its view.
        if (execAttributes.remove(io.helixiam.authorization.flow.spi.AuthenticationContext.REDIRECT_ATTRIBUTE)
                instanceof String target && target.startsWith("/") && !target.startsWith("//")
                && target.indexOf('\\') < 0) { // never "/\\host" (browsers read it as "//host")
            session.setAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE, state);
            return REDIRECT_PREFIX + target; // context-relative: resolved under the realm like the broker's
        }
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
            return REDIRECT_PREFIX + "/login";
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
                // Restore the fully authenticated token — only if it is the user the flow completed for, pending in
                // this session (the merge of the wallet and security branches: user check, one rotation, commit or
                // undo, stamp, acr).
                final String flowUser = progress.userId() != null ? progress.userId() : state.userId();
                if (mfaEnrolment != null && flowUser != null && flowUser.equals(state.userId())
                        && mfaService.isPendingSignInOf(flowUser)
                        && mfaEnrolment.mustEnrol(io.helixiam.authorization.security.realm.RealmContextHolder.get(), flowUser)) {
                    // The realm requires MFA and this user has not enrolled TOTP, yet the flow (an admin-built one
                    // whose challenge was email OTP, push or QR) completed: no full session, enrol first — the rule of
                    // FlowLoginSuccessHandler and the federated completion. The pending sign-in and the flow state
                    // (a federated login's commit, acr and outcome) stay; MfaAuthController ends them after enrolment.
                    request.changeSessionId();
                    LOG.info("Login flow completed for a user who must enrol a second factor first");
                    yield REDIRECT_PREFIX + "/mfa/enable";
                }
                if (flowUser == null || !flowUser.equals(state.userId()) || !mfaService.unlockUser(flowUser)) {
                    LOG.warn("Login flow completed for another user than the pending sign-in; refusing it");
                    org.springframework.security.core.context.SecurityContextHolder.clearContext();
                    io.helixiam.authorization.federation.PendingFederatedLogin.clear(session);
                    session.invalidate();
                    reportFailed(state);
                    yield REDIRECT_PREFIX + "/login?error";
                }
                request.changeSessionId(); // a completed sign-in gets a new session id (no fixation)
                if (!io.helixiam.authorization.federation.PendingFederatedLogin.finish(request, state, loginCommits,
                        loginOutcomes, authTimeStamper)) {
                    yield REDIRECT_PREFIX + "/login?error=federation";
                }
                sessionPolicyApplier.applyOnLogin(request, io.helixiam.authorization.security.realm.RealmContextHolder.get()); // SSO P3
                yield savedRequestRedirect.redirectView(request, response, spBaseUrl);
            }
            case CHALLENGE -> REDIRECT_PREFIX + "/flow"; // advanced to the next factor's screen
            case FAILED -> {
                model.addAttribute("error", "true"); // wrong response — re-prompt with an error
                model.addAttribute("flowFailure", state.attributesFor(state.currentChallengeExecutionId())
                        .get(io.helixiam.authorization.flow.spi.AuthenticationContext.FAILURE_ATTRIBUTE));
                yield VIEW_PREFIX + state.currentChallengeView();
            }
        };
    }

    /**
     * Verify-only EUDI wallet step: the wallet's same-device {@code redirect_uri} and the wallet page's cross-device
     * {@code next} come back here with the response code; it is fed to the step that is challenging, exactly like a
     * submitted form (the step redeems it against this session's state and browser binding, single use). Only while a
     * wallet verification is the current challenge.
     */
    @GetMapping("/flow/wallet/callback")
    public String walletCallback(@RequestParam(name = "response_code", required = false) final String responseCode,
                                 final HttpSession session, final Model model,
                                 final HttpServletRequest request, final HttpServletResponse response) {
        final FlowExecutionState state = state(session);
        if (state == null || responseCode == null || responseCode.isBlank()
                || !io.helixiam.authorization.federation.wallet.WalletVerifyAuthenticator.VIEW
                        .equals(state.currentChallengeView())) {
            return REDIRECT_PREFIX + "/login";
        }
        return submitChallenge(Map.of("response_code", responseCode), session, model, request, response);
    }

    /** Final review F2: the federated login of this flow ended without a session; reported once. */
    private void reportFailed(final FlowExecutionState state) {
        final java.io.Serializable marker = state.pendingOutcome();
        state.setPendingOutcome(null);
        io.helixiam.authorization.federation.FederatedLoginOutcome.failed(loginOutcomes, marker);
    }

    private FlowExecutionState state(final HttpSession session) {
        return (FlowExecutionState) session.getAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE);
    }

    /**
     * Realm-prefix a controller path for a form's {@code action} (raw HTML). Redirects stay context-relative
     * ({@code redirect:/flow}): Spring resolves them under the realm's virtual context path, so prefixing them too
     * produced {@code /realms/<r>/realms/<r>/...} (403) — found by the wallet verification e2e.
     */
    private String flowPath(final String path) {
        return io.helixiam.authorization.security.realm.RealmPaths.prefixed(
                io.helixiam.authorization.security.realm.RealmContextHolder.get(), path);
    }
}
