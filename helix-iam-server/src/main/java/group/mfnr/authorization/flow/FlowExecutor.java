package group.mfnr.authorization.flow;

import group.mfnr.authorization.flow.spi.AuthenticationContext;
import group.mfnr.authorization.flow.spi.Authenticator;
import group.mfnr.authorization.flow.spi.AuthenticatorRegistry;

import java.util.Map;

/**
 * Helix IAM E2.4: drives a flow to completion. It asks the {@link FlowEvaluator} for the next
 * decision, resolves and runs the named authenticator, and either issues a challenge (and
 * pauses) or records the outcome and continues. Conditions and other non-interactive steps
 * resolve in the same loop without a user round-trip.
 */
public class FlowExecutor {

    private final AuthenticatorRegistry registry;
    private final FlowEvaluator evaluator;

    public FlowExecutor(final AuthenticatorRegistry registry, final FlowEvaluator evaluator) {
        this.registry = registry;
        this.evaluator = evaluator;
    }

    /** Advances the flow from its current state, issuing the next challenge or finishing. */
    public FlowProgress begin(final AuthFlow flow, final FlowExecutionState state) {
        return drive(flow, state);
    }

    /** Processes the user's response to the current challenge, then advances. */
    public FlowProgress submit(final AuthFlow flow, final FlowExecutionState state,
                               final String executionId, final Map<String, String> formData) {
        final AuthExecution execution = flow.findExecution(executionId)
                .orElseThrow(() -> new IllegalArgumentException("No such execution: " + executionId));
        final Authenticator authenticator = registry.get(execution.authenticatorId());

        final AuthenticationContext context =
                new AuthenticationContext(executionId, state.realmId(), state.userId(), execution.config());
        context.attributes().putAll(state.attributesFor(executionId));
        context.submit(formData);
        authenticator.action(context);
        state.attributesFor(executionId).putAll(context.attributes());
        record(state, executionId, context);

        return drive(flow, state);
    }

    private FlowProgress drive(final AuthFlow flow, final FlowExecutionState state) {
        while (true) {
            final Decision decision = evaluator.evaluate(flow, state.outcomes());
            switch (decision.kind()) {
                case SUCCESS:
                    return FlowProgress.completed(state.userId());
                case FAILURE:
                    return FlowProgress.failed();
                case RUN:
                default:
                    final AuthExecution execution = flow.findExecution(decision.executionId())
                            .orElseThrow(() -> new IllegalStateException(
                                    "Flow references unknown execution: " + decision.executionId()));
                    final Authenticator authenticator = registry.get(execution.authenticatorId());

                    final AuthenticationContext context = new AuthenticationContext(
                            execution.id(), state.realmId(), state.userId(), execution.config());
                    context.attributes().putAll(state.attributesFor(execution.id()));
                    authenticator.authenticate(context);
                    state.attributesFor(execution.id()).putAll(context.attributes());

                    if (context.status() == AuthenticationContext.Status.CHALLENGE) {
                        state.setCurrentChallengeExecutionId(execution.id());
                        state.setCurrentChallengeView(context.challengeView());
                        return FlowProgress.challenge(context.challengeView(), execution.id());
                    }
                    // Non-interactive step (e.g. a condition) resolved immediately — record and loop.
                    record(state, execution.id(), context);
            }
        }
    }

    private void record(final FlowExecutionState state, final String executionId,
                        final AuthenticationContext context) {
        context.outcome().ifPresent(outcome -> state.outcomes().put(executionId, outcome));
        if (context.userId() != null) {
            state.setUserId(context.userId());
        }
    }
}
