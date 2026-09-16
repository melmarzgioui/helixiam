package io.helixiam.authorization.flow.authenticators;

import io.helixiam.authorization.amqp.risk.RiskLoginRecord;
import io.helixiam.authorization.amqp.risk.RiskPublisher;
import io.helixiam.authorization.amqp.risk.RiskSignalRequest;
import io.helixiam.authorization.amqp.risk.RiskSignals;
import io.helixiam.authorization.flow.risk.RiskAction;
import io.helixiam.authorization.flow.risk.RiskEvaluator;
import io.helixiam.authorization.flow.risk.RiskPolicy;
import io.helixiam.authorization.flow.risk.RiskPolicyResolver;
import io.helixiam.authorization.flow.risk.RiskSignalGatherer;
import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.AuthenticatorCategory;
import io.helixiam.authorization.flow.spi.FactorClass;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM (adaptive auth): the RiskAuthenticator's decision. Passes straight through when the
 * policy is OFF (default — login unchanged) or LOW; forces the OTP step-up when the policy maps
 * the band to STEP_UP; denies on DENY; records the login on a pass / completed step-up.
 */
class RiskAuthenticatorTest {

    private final RiskEvaluator evaluator = new RiskEvaluator();

    // --- Fakes (no Mockito; same lambda/subclass style as the other authenticator tests) ---

    /** Resolver stub returning a fixed policy. */
    private static RiskPolicyResolver resolver(final RiskPolicy policy) {
        return new RiskPolicyResolver(null) {
            @Override
            public RiskPolicy resolve(final String realmId) {
                return policy;
            }
        };
    }

    /** Gatherer stub returning fixed raw signals (no servlet request needed). */
    private static RiskSignalGatherer gatherer(final RiskSignalGatherer.RawSignals raw) {
        return new RiskSignalGatherer() {
            @Override
            public RawSignals gather(final jakarta.servlet.http.HttpServletRequest request) {
                return raw;
            }
        };
    }

    private static RiskSignalGatherer.RawSignals raw() {
        return new RiskSignalGatherer.RawSignals("1.2.3.4", "agent", "fp-known", "token");
    }

    /** Publisher stub returning fixed signals + capturing the recorded login. */
    private static class FakePublisher implements RiskPublisher {
        private final RiskSignals signals;
        final AtomicReference<RiskLoginRecord> recorded = new AtomicReference<>();

        FakePublisher(final RiskSignals signals) {
            this.signals = signals;
        }

        @Override
        public RiskSignals evaluateSignals(final RiskSignalRequest request) {
            return signals;
        }

        @Override
        public Boolean recordLogin(final RiskLoginRecord record) {
            recorded.set(record);
            return Boolean.TRUE;
        }
    }

    private static RiskSignals signals(final boolean hasDevices, final boolean knownDevice,
                                       final boolean hasHistory, final boolean knownIp, final int failures) {
        final RiskSignals s = new RiskSignals();
        s.setHasEnrolledDevices(hasDevices);
        s.setKnownDevice(knownDevice);
        s.setHasLoginHistory(hasHistory);
        s.setKnownIp(knownIp);
        s.setRecentFailureCount(failures);
        return s;
    }

    private AuthenticationContext context() {
        return new AuthenticationContext("e-risk", "master", "user-1");
    }

    @Test
    void metadata_isConditionClass_idRisk() {
        RiskAuthenticator a = new RiskAuthenticator(resolver(RiskPolicy.disabled()), evaluator,
                new FakePublisher(new RiskSignals()), gatherer(raw()), (u, c) -> true);

        assertThat(a.metadata().id()).isEqualTo("risk");
        assertThat(a.metadata().factorClass()).isEqualTo(FactorClass.NONE);
        // A genuine flow condition — the console shows it under "Add a condition", not "Add a method".
        assertThat(a.metadata().category()).isEqualTo(AuthenticatorCategory.CONDITION);
    }

    @Test
    void policyOff_passesThroughUnchanged_noRecording() {
        FakePublisher publisher = new FakePublisher(signals(true, false, true, false, 9));
        RiskAuthenticator a = new RiskAuthenticator(resolver(RiskPolicy.disabled()), evaluator,
                publisher, gatherer(raw()), (u, c) -> true);
        AuthenticationContext ctx = context();

        a.authenticate(ctx);

        // DEFAULT: even with maximally-risky signals, a disabled policy just succeeds and records nothing.
        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
        assertThat(publisher.recorded.get()).isNull();
    }

    @Test
    void lowRisk_succeedsAndRecordsLogin() {
        FakePublisher publisher = new FakePublisher(signals(true, true, true, true, 0)); // known device + IP
        RiskPolicy policy = new RiskPolicy(true, 40, 70, RiskAction.ALLOW, RiskAction.STEP_UP, RiskAction.DENY);
        RiskAuthenticator a = new RiskAuthenticator(resolver(policy), evaluator,
                publisher, gatherer(raw()), (u, c) -> true);
        AuthenticationContext ctx = context();

        a.authenticate(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
        assertThat(publisher.recorded.get()).isNotNull();
        assertThat(publisher.recorded.get().getIp()).isEqualTo("1.2.3.4");
    }

    @Test
    void mediumRisk_forcesStepUpChallenge() {
        FakePublisher publisher = new FakePublisher(signals(true, false, true, false, 0)); // new device+IP = 60
        RiskPolicy policy = new RiskPolicy(true, 40, 70, RiskAction.ALLOW, RiskAction.STEP_UP, RiskAction.DENY);
        RiskAuthenticator a = new RiskAuthenticator(resolver(policy), evaluator,
                publisher, gatherer(raw()), (u, c) -> true);
        AuthenticationContext ctx = context();

        a.authenticate(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.CHALLENGE);
        assertThat(ctx.challengeView()).isEqualTo("otp-form");
        assertThat(publisher.recorded.get()).isNull(); // not recorded until the step-up completes
    }

    @Test
    void highRisk_denies() {
        FakePublisher publisher = new FakePublisher(signals(true, false, true, false, 9)); // capped → high
        RiskPolicy policy = new RiskPolicy(true, 40, 70, RiskAction.ALLOW, RiskAction.STEP_UP, RiskAction.DENY);
        RiskAuthenticator a = new RiskAuthenticator(resolver(policy), evaluator,
                publisher, gatherer(raw()), (u, c) -> true);
        AuthenticationContext ctx = context();

        a.authenticate(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }

    @Test
    void stepUp_completesWhenCodeValid_andRecords() {
        FakePublisher publisher = new FakePublisher(signals(true, false, true, false, 0));
        RiskPolicy policy = new RiskPolicy(true, 40, 70, RiskAction.ALLOW, RiskAction.STEP_UP, RiskAction.DENY);
        RiskAuthenticator a = new RiskAuthenticator(resolver(policy), evaluator,
                publisher, gatherer(raw()), (u, c) -> "123456".equals(c));
        AuthenticationContext ctx = context();

        a.authenticate(ctx); // → CHALLENGE, stashes the step-up marker
        ctx.submit(Map.of("code", "123456"));
        a.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
        assertThat(publisher.recorded.get()).isNotNull();
    }

    @Test
    void stepUp_failsWhenCodeInvalid() {
        FakePublisher publisher = new FakePublisher(signals(true, false, true, false, 0));
        RiskPolicy policy = new RiskPolicy(true, 40, 70, RiskAction.ALLOW, RiskAction.STEP_UP, RiskAction.DENY);
        RiskAuthenticator a = new RiskAuthenticator(resolver(policy), evaluator,
                publisher, gatherer(raw()), (u, c) -> "123456".equals(c));
        AuthenticationContext ctx = context();

        a.authenticate(ctx);
        ctx.submit(Map.of("code", "000000"));
        a.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }

    @Test
    void signalLookupFailure_failsOpenToLowRisk() {
        RiskPublisher failing = new RiskPublisher() {
            @Override
            public RiskSignals evaluateSignals(final RiskSignalRequest request) {
                throw new RuntimeException("AMQP down");
            }

            @Override
            public Boolean recordLogin(final RiskLoginRecord record) {
                return Boolean.TRUE;
            }
        };
        RiskPolicy policy = new RiskPolicy(true, 40, 70, RiskAction.ALLOW, RiskAction.STEP_UP, RiskAction.DENY);
        RiskAuthenticator a = new RiskAuthenticator(resolver(policy), evaluator,
                failing, gatherer(raw()), (u, c) -> true);
        AuthenticationContext ctx = context();

        a.authenticate(ctx);

        // No signals → score 0 → LOW → ALLOW. A subscriber/AMQP hiccup never blocks login.
        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
    }
}
