package io.helixiam.authorization.controller;

import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.amqp.user.UserPasswordDto;
import io.helixiam.authorization.amqp.user.UserRequiredActionsDto;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.flow.FlowLoginSuccessHandler;
import io.helixiam.authorization.security.requiredactions.RequiredActionsGate;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * Helix IAM B1: serves the required-actions completion flow. After {@link RequiredActionsGate} holds a
 * user post-password, this lists their pending actions and completes them one at a time. UPDATE_PASSWORD
 * is fully wired (set a new password); other actions are shown and acknowledged. When the list empties,
 * the original Authentication is handed back to the normal post-password routing
 * ({@link FlowLoginSuccessHandler}) so MFA / the login flow still runs.
 */
@Controller
public class RequiredActionsController {

    public static final String UPDATE_PASSWORD = "UPDATE_PASSWORD";

    private static final Logger LOG = LogManager.getLogger(RequiredActionsController.class);

    private final UserAdminPublisher userPublisher;
    private final FlowLoginSuccessHandler flowSuccessHandler;
    private final String spBaseUrl;

    public RequiredActionsController(final UserAdminPublisher userPublisher,
                                     final io.helixiam.authorization.flow.FlowExecutor flowExecutor,
                                     final io.helixiam.authorization.amqp.AuthFlowPublisher authFlowPublisher,
                                     final io.helixiam.authorization.flow.persistence.AuthFlowMapper authFlowMapper,
                                     final io.helixiam.authorization.security.realm.SessionPolicyApplier sessionPolicyApplier,
                                     final io.helixiam.authorization.security.realm.ConcurrentSessionLimiter concurrentSessionLimiter,
                                     @Value("${sp.base.url:/}") final String spBaseUrl) {
        this.userPublisher = userPublisher;
        this.spBaseUrl = spBaseUrl;
        // Same wiring as SecurityConfig so completing the actions resumes the exact post-password routing.
        this.flowSuccessHandler = new FlowLoginSuccessHandler(flowExecutor, authFlowPublisher, authFlowMapper,
                spBaseUrl, sessionPolicyApplier, concurrentSessionLimiter);
    }

    @GetMapping("/required-actions")
    public String page(final HttpServletRequest request, final HttpServletResponse response, final Model model)
            throws IOException {
        final List<String> pending = pending(request);
        if (pending.isEmpty()) {
            response.sendRedirect(request.getContextPath() + "/login");
            return null;
        }
        final String action = pending.get(0);
        model.addAttribute("action", action);
        model.addAttribute("remaining", pending.size());
        return UPDATE_PASSWORD.equalsIgnoreCase(action)
                ? "required-actions/update-password"
                : "required-actions/acknowledge";
    }

    @PostMapping("/required-actions/update-password")
    public String updatePassword(@RequestParam("newPassword") final String newPassword,
                                 @RequestParam("repeatPassword") final String repeatPassword,
                                 final HttpServletRequest request, final HttpServletResponse response,
                                 final Model model) throws IOException {
        if (newPassword == null || newPassword.isBlank() || !newPassword.equals(repeatPassword)) {
            model.addAttribute("action", UPDATE_PASSWORD);
            model.addAttribute("error", true);
            return "required-actions/update-password";
        }
        final String userId = userId(request);
        final String realm = realm(request);
        if (userId == null) {
            response.sendRedirect(request.getContextPath() + "/login");
            return null;
        }
        final boolean set = Boolean.TRUE.equals(userPublisher.resetPassword(new UserPasswordDto(realm, userId, newPassword)));
        if (!set) {
            model.addAttribute("action", UPDATE_PASSWORD);
            model.addAttribute("error", true);
            return "required-actions/update-password";
        }
        return completeOne(UPDATE_PASSWORD, request, response);
    }

    @PostMapping("/required-actions/acknowledge")
    public String acknowledge(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        final List<String> pending = pending(request);
        if (pending.isEmpty()) {
            return finish(request, response);
        }
        return completeOne(pending.get(0), request, response);
    }

    /** Clear one completed action server-side, advance the session, and finish when none remain. */
    private String completeOne(final String action, final HttpServletRequest request, final HttpServletResponse response)
            throws IOException {
        final String userId = userId(request);
        final String realm = realm(request);
        final String remaining = userPublisher.clearRequiredAction(new UserRequiredActionsDto(realm, userId, action));
        request.getSession().setAttribute(RequiredActionsGate.PENDING_ACTIONS_ATTR, remaining);
        LOG.info("User {} completed required action {} (remaining: [{}])", userId, action, remaining);
        if (remaining == null || remaining.isBlank()) {
            return finish(request, response);
        }
        response.sendRedirect(request.getContextPath() + "/required-actions");
        return null;
    }

    /** All actions done — hand the original Authentication back to the normal post-password routing. */
    private String finish(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        final HttpSession session = request.getSession(false);
        final Authentication original = session == null ? null
                : (Authentication) session.getAttribute(RequiredActionsGate.PENDING_AUTH_ATTR);
        if (session != null) {
            session.removeAttribute(RequiredActionsGate.PENDING_AUTH_ATTR);
            session.removeAttribute(RequiredActionsGate.PENDING_ACTIONS_ATTR);
            session.removeAttribute(RequiredActionsGate.PENDING_REALM_ATTR);
        }
        if (original == null) {
            response.sendRedirect(request.getContextPath() + "/login");
            return null;
        }
        // Resumes the flow engine (→ /flow for MFA step-up) or completes to a full session — MFA preserved.
        flowSuccessHandler.onAuthenticationSuccess(request, response, original);
        return null;
    }

    private static List<String> pending(final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);
        final Object raw = session == null ? null : session.getAttribute(RequiredActionsGate.PENDING_ACTIONS_ATTR);
        if (raw == null || raw.toString().isBlank()) {
            return List.of();
        }
        return Arrays.stream(raw.toString().split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }

    private static String userId(final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);
        final Object auth = session == null ? null : session.getAttribute(RequiredActionsGate.PENDING_AUTH_ATTR);
        if (auth instanceof Authentication a && a.getPrincipal() instanceof UserCredentials u) {
            return u.getUserId();
        }
        return null;
    }

    private static String realm(final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);
        final Object realm = session == null ? null : session.getAttribute(RequiredActionsGate.PENDING_REALM_ATTR);
        return realm == null ? null : realm.toString();
    }
}
