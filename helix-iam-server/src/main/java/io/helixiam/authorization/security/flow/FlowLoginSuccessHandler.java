package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.amqp.AuthFlowPublisher;
import io.helixiam.authorization.support.RealmScopedKey;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.flow.AuthFlow;
import io.helixiam.authorization.flow.BrowserFlows;
import io.helixiam.authorization.flow.FlowExecutionState;
import io.helixiam.authorization.flow.FlowExecutor;
import io.helixiam.authorization.flow.FlowProgress;
import io.helixiam.authorization.flow.persistence.AuthFlowDefinition;
import io.helixiam.authorization.flow.persistence.AuthFlowMapper;
import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

/**
 * Helix IAM E2.4/E2.5: engine-driven replacement for {@code MfaAuthenticationSuccessHandler}.
 * Once the password factor succeeds, the realm's persisted post-password flow (loaded from the
 * subscriber over AMQP, E2.5) runs through the {@link FlowExecutor}: it completes immediately
 * when no further factor is required, or gates the session (a non-authenticated
 * {@link MfaAuthentication}) and redirects to the engine's challenge page. Falls back to the
 * in-code flow when the store has none. Used only when {@code helix.flow-engine.enabled=true}.
 */
public class FlowLoginSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger LOG = LogManager.getLogger(FlowLoginSuccessHandler.class);

    public static final String FLOW_STATE_ATTRIBUTE = "HELIX_FLOW_STATE";
    public static final String FLOW_DEFINITION_ATTRIBUTE = "HELIX_FLOW_DEFINITION";

    private final FlowExecutor flowExecutor;
    private final AuthFlowPublisher authFlowPublisher;
    private final AuthFlowMapper authFlowMapper;
    private final String spBaseUrl;
    private final ResolveSavedRequestRedirect savedRequestRedirect;
    private final io.helixiam.authorization.security.realm.SessionPolicyApplier sessionPolicyApplier;
    // Auth-hardening (feature 6): optional per-realm concurrent-session cap, applied on completion.
    private final io.helixiam.authorization.security.realm.ConcurrentSessionLimiter concurrentSessionLimiter;
    private final io.helixiam.authorization.security.session.AuthTimeStamper authTimeStamper =
            new io.helixiam.authorization.security.session.AuthTimeStamper();

    public FlowLoginSuccessHandler(final FlowExecutor flowExecutor, final AuthFlowPublisher authFlowPublisher,
                                   final AuthFlowMapper authFlowMapper, final String spBaseUrl,
                                   final io.helixiam.authorization.security.realm.SessionPolicyApplier sessionPolicyApplier) {
        this(flowExecutor, authFlowPublisher, authFlowMapper, spBaseUrl, new ResolveSavedRequestRedirect(), sessionPolicyApplier, null);
    }

    /** Auth-hardening: variant that also enforces the per-realm concurrent-session cap. */
    public FlowLoginSuccessHandler(final FlowExecutor flowExecutor, final AuthFlowPublisher authFlowPublisher,
                                   final AuthFlowMapper authFlowMapper, final String spBaseUrl,
                                   final io.helixiam.authorization.security.realm.SessionPolicyApplier sessionPolicyApplier,
                                   final io.helixiam.authorization.security.realm.ConcurrentSessionLimiter concurrentSessionLimiter) {
        this(flowExecutor, authFlowPublisher, authFlowMapper, spBaseUrl, new ResolveSavedRequestRedirect(), sessionPolicyApplier, concurrentSessionLimiter);
    }

    /** Test seam: inject the saved-request resolver. */
    FlowLoginSuccessHandler(final FlowExecutor flowExecutor, final AuthFlowPublisher authFlowPublisher,
                            final AuthFlowMapper authFlowMapper, final String spBaseUrl,
                            final ResolveSavedRequestRedirect savedRequestRedirect,
                            final io.helixiam.authorization.security.realm.SessionPolicyApplier sessionPolicyApplier) {
        this(flowExecutor, authFlowPublisher, authFlowMapper, spBaseUrl, savedRequestRedirect, sessionPolicyApplier, null);
    }

    /** Test seam: inject the saved-request resolver + the concurrent-session limiter. */
    FlowLoginSuccessHandler(final FlowExecutor flowExecutor, final AuthFlowPublisher authFlowPublisher,
                            final AuthFlowMapper authFlowMapper, final String spBaseUrl,
                            final ResolveSavedRequestRedirect savedRequestRedirect,
                            final io.helixiam.authorization.security.realm.SessionPolicyApplier sessionPolicyApplier,
                            final io.helixiam.authorization.security.realm.ConcurrentSessionLimiter concurrentSessionLimiter) {
        this.flowExecutor = flowExecutor;
        this.authFlowPublisher = authFlowPublisher;
        this.authFlowMapper = authFlowMapper;
        this.spBaseUrl = spBaseUrl;
        this.savedRequestRedirect = savedRequestRedirect;
        this.sessionPolicyApplier = sessionPolicyApplier;
        this.concurrentSessionLimiter = concurrentSessionLimiter;
    }

    @Override
    public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response,
                                        final Authentication authentication) throws IOException {
        if (!(authentication.getPrincipal() instanceof UserCredentials userCredentials)) {
            savedRequestRedirect.sendRedirect(request, response, spBaseUrl);
            return;
        }

        // Hold the user pending the post-password flow (mirrors the legacy MFA gate).
        SecurityContextHolder.getContext().setAuthentication(new MfaAuthentication(authentication));

        final String clientId = InFlightClientResolver.clientId(request, response);
        final AuthFlowDefinition definition = resolveFlow(userCredentials, clientId);
        final AuthFlow flow = authFlowMapper.toAuthFlow(definition);

        final FlowExecutionState state = new FlowExecutionState(RealmContextHolder.get());
        state.setUserId(userCredentials.getUserId());
        final FlowProgress progress = flowExecutor.begin(flow, state);

        request.getSession().setAttribute(FLOW_STATE_ATTRIBUTE, state);
        request.getSession().setAttribute(FLOW_DEFINITION_ATTRIBUTE, definition);

        switch (progress.type()) {
            case COMPLETED -> {
                // Promote to the full authentication FIRST, then resume the saved /oauth2/authorize so the
                // SAS chain sees an authenticated session and issues a code for the originating client.
                SecurityContextHolder.getContext().setAuthentication(authentication);
                authTimeStamper.stamp(request); // SSO P2
                sessionPolicyApplier.applyOnLogin(request, RealmContextHolder.get()); // SSO P3
                // Auth-hardening (feature 6): enforce the per-realm concurrent-session cap.
                if (concurrentSessionLimiter != null) {
                    final String sessionId = request.getSession(false) != null ? request.getSession(false).getId() : null;
                    final io.helixiam.authorization.security.realm.ConcurrentSessionLimiter.Outcome outcome =
                            concurrentSessionLimiter.enforceOnLogin(RealmContextHolder.get(), authentication.getName(), sessionId);
                    if (outcome == io.helixiam.authorization.security.realm.ConcurrentSessionLimiter.Outcome.DENIED) {
                        SecurityContextHolder.clearContext();
                        request.getSession().invalidate();
                        response.sendRedirect(request.getContextPath() + "/login?error=tooManySessions");
                        return;
                    }
                }
                savedRequestRedirect.sendRedirect(request, response, spBaseUrl);
            }
            case CHALLENGE -> response.sendRedirect(request.getContextPath() + "/flow");
            case FAILED -> response.sendRedirect(request.getContextPath() + "/login?error=error");
        }
    }

    /**
     * The flow this login runs: the in-flight client's bound flow (named-flow override) when a client is in
     * play, otherwise the realm's browser flow; the in-code fallback when the store has none.
     */
    private AuthFlowDefinition resolveFlow(final UserCredentials userCredentials, final String clientId) {
        final String realm = RealmContextHolder.get();
        try {
            final AuthFlowDefinition stored = clientId != null && !clientId.isBlank()
                    ? authFlowPublisher.retrieveFlowForClient(RealmScopedKey.pack(realm, clientId))
                    : authFlowPublisher.retrieveBrowserFlow(realm);
            if (stored != null && stored.getExecutions() != null && !stored.getExecutions().isEmpty()) {
                return stored;
            }
        } catch (final RuntimeException e) {
            LOG.warn("Could not load the persisted login flow, using the in-code fallback: {}", e.getMessage());
        }
        return BrowserFlows.fallbackDefinition(userCredentials.isMfaEnabled());
    }
}
