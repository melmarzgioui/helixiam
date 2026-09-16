package io.helixiam.authorization.federation;

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
import io.helixiam.authorization.security.flow.FlowLoginSuccessHandler;
import io.helixiam.authorization.security.flow.InFlightClientResolver;
import io.helixiam.authorization.security.flow.ResolveSavedRequestRedirect;
import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * Helix IAM E5.4: post-broker login completion with optional step-up. The external IdP is the
 * federated user's <em>primary</em> authentication; this then runs the realm's post-(primary-auth)
 * flow — the SAME MFA flow the password path runs via {@link FlowLoginSuccessHandler} — so a
 * federated login can still be forced through a second factor.
 *
 * <ul>
 *   <li>flow COMPLETES immediately (no MFA / no stored step-up) → establish a full session, redirect
 *       to the SP;</li>
 *   <li>flow CHALLENGES → hold a non-authenticated {@link MfaAuthentication} gate (promoted to full
 *       by the {@code /flow} controller once the factor passes), stash the flow state, redirect to
 *       {@code /flow};</li>
 *   <li>flow FAILS → reject to {@code /login?error}, no session.</li>
 * </ul>
 */
@Component
public class FederatedLoginCompleter {

    private static final Logger LOG = LogManager.getLogger(FederatedLoginCompleter.class);

    private static final String LOGIN_ERROR = "redirect:/login?error=federation";

    private final FlowExecutor flowExecutor;
    private final AuthFlowPublisher authFlowPublisher;
    private final AuthFlowMapper authFlowMapper;
    private final FederatedSessionEstablisher sessionEstablisher;
    private final String spBaseUrl;
    private final io.helixiam.authorization.security.realm.SessionPolicyApplier sessionPolicyApplier;
    private final ResolveSavedRequestRedirect savedRequestRedirect = new ResolveSavedRequestRedirect();
    private final io.helixiam.authorization.security.session.AuthTimeStamper authTimeStamper =
            new io.helixiam.authorization.security.session.AuthTimeStamper();

    public FederatedLoginCompleter(final FlowExecutor flowExecutor, final AuthFlowPublisher authFlowPublisher,
                                   final AuthFlowMapper authFlowMapper,
                                   final FederatedSessionEstablisher sessionEstablisher,
                                   @Value("${sp.base.url}") final String spBaseUrl,
                                   final io.helixiam.authorization.security.realm.SessionPolicyApplier sessionPolicyApplier) {
        this.flowExecutor = flowExecutor;
        this.authFlowPublisher = authFlowPublisher;
        this.authFlowMapper = authFlowMapper;
        this.sessionEstablisher = sessionEstablisher;
        this.spBaseUrl = spBaseUrl;
        this.sessionPolicyApplier = sessionPolicyApplier;
    }

    /** Complete a federated login for the broker-resolved {@code userId}; returns the redirect view. */
    public String complete(final String userId, final HttpServletRequest request, final HttpServletResponse response) {
        final UserCredentials user = sessionEstablisher.loadUser(userId);
        final Authentication fullAuthentication =
                UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities());

        final String clientId = InFlightClientResolver.clientId(request, response);
        final AuthFlowDefinition definition = resolveFlow(user, clientId);
        final AuthFlow flow = authFlowMapper.toAuthFlow(definition);

        final FlowExecutionState state = new FlowExecutionState(RealmContextHolder.get());
        state.setUserId(user.getUserId());
        final FlowProgress progress = flowExecutor.begin(flow, state);

        final HttpSession session = request.getSession();
        session.setAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE, state);
        session.setAttribute(FlowLoginSuccessHandler.FLOW_DEFINITION_ATTRIBUTE, definition);

        return switch (progress.type()) {
            case COMPLETED -> {
                sessionEstablisher.persist(fullAuthentication, request, response);
                authTimeStamper.stamp(request); // SSO P2
                sessionPolicyApplier.applyOnLogin(request, RealmContextHolder.get()); // SSO P3
                LOG.info("Federated login completed for user {} (no step-up required)", userId);
                // SSO P1: resume the originating /oauth2/authorize (if any), else the SP base URL.
                yield savedRequestRedirect.redirectView(request, response, spBaseUrl);
            }
            case CHALLENGE -> {
                // Hold the user pending the post-broker factor; /flow promotes this to a full session.
                sessionEstablisher.persist(new MfaAuthentication(fullAuthentication), request, response);
                LOG.info("Federated login for user {} requires step-up — routing to the flow engine", userId);
                yield "redirect:/flow";
            }
            case FAILED -> {
                LOG.warn("Federated login post-broker flow failed for user {}", userId);
                yield LOGIN_ERROR;
            }
        };
    }

    /**
     * The post-primary-auth flow to run: the in-flight client's bound flow (named-flow override) when a
     * client is in play, otherwise the realm's browser flow; the in-code fallback when the store has none.
     */
    private AuthFlowDefinition resolveFlow(final UserCredentials user, final String clientId) {
        final String realm = RealmContextHolder.get();
        try {
            final AuthFlowDefinition stored = clientId != null && !clientId.isBlank()
                    ? authFlowPublisher.retrieveFlowForClient(RealmScopedKey.pack(realm, clientId))
                    : authFlowPublisher.retrieveBrowserFlow(realm);
            if (stored != null && stored.getExecutions() != null && !stored.getExecutions().isEmpty()) {
                return stored;
            }
        } catch (final RuntimeException e) {
            LOG.warn("Could not load the persisted login flow for federation, using the in-code fallback: {}",
                    e.getMessage());
        }
        return BrowserFlows.fallbackDefinition(user.isMfaEnabled());
    }
}
