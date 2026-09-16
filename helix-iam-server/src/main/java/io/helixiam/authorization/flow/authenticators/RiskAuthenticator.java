/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.authenticators;

import io.helixiam.authorization.amqp.risk.RiskLoginRecord;
import io.helixiam.authorization.amqp.risk.RiskPublisher;
import io.helixiam.authorization.amqp.risk.RiskSignalRequest;
import io.helixiam.authorization.amqp.risk.RiskSignals;
import io.helixiam.authorization.flow.risk.RiskAction;
import io.helixiam.authorization.flow.risk.RiskAssessment;
import io.helixiam.authorization.flow.risk.RiskEvaluator;
import io.helixiam.authorization.flow.risk.RiskPolicy;
import io.helixiam.authorization.flow.risk.RiskPolicyResolver;
import io.helixiam.authorization.flow.risk.RiskSignalGatherer;
import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.Authenticator;
import io.helixiam.authorization.flow.spi.AuthenticatorMetadata;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Helix IAM (adaptive auth): the risk-based / adaptive step-up authenticator. A discoverable
 * {@code @Component} on the {@code Authenticator} SPI — Helix auto-registers it under id
 * {@code "risk"} with no {@code FlowConfig} change. An admin places it in a realm flow (typically
 * right after password); it evaluates the attempt's risk and either passes through, forces a
 * step-up OTP, or denies, according to the per-realm {@link RiskPolicy}.
 *
 * <h2>Behaviour</h2>
 * <ul>
 *   <li><b>Policy OFF (default)</b> → {@code success()} immediately. The login behaves <i>exactly</i>
 *       as today; no AMQP call, no cookie, no recording. This is the safe default for every realm.</li>
 *   <li><b>LOW / action ALLOW</b> → {@code success()}, and the device + IP are recorded as "known".</li>
 *   <li><b>action STEP_UP</b> → issues the standard {@code otp-form} challenge; on a correct code in
 *       {@link #action} it completes and records the login.</li>
 *   <li><b>action DENY</b> → {@code failure(...)}.</li>
 * </ul>
 *
 * <p>Self-contained step-up: it reuses the existing {@code otp-form} challenge view (no new template)
 * and the existing {@link OtpVerifier} (the same TOTP verification the OTP authenticator uses), so it
 * integrates with the established challenge/response mechanism without touching the flow runtime.
 *
 * <p>Signals come from the request (IP / User-Agent / remembered-device cookie via
 * {@link RiskSignalGatherer}) and from the subscriber (known-device/known-IP history + brute-force
 * velocity via {@link RiskPublisher}); scoring is done by the pure {@link RiskEvaluator}.
 */
@Component
public class RiskAuthenticator implements Authenticator {

    public static final String ID = "risk";

    private static final Logger LOG = LogManager.getLogger(RiskAuthenticator.class);
    private static final String OTP_VIEW = "otp-form";
    private static final String CODE_PARAM = "code";
    private static final String STEPUP_ATTRIBUTE = "risk.stepup";
    private static final int DEVICE_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 180; // 180 days
    private static final SecureRandom RANDOM = new SecureRandom();

    private final RiskPolicyResolver policyResolver;
    private final RiskEvaluator evaluator;
    private final RiskPublisher publisher;
    private final RiskSignalGatherer gatherer;
    private final OtpVerifier otpVerifier;

    public RiskAuthenticator(final RiskPolicyResolver policyResolver,
                             final RiskEvaluator evaluator,
                             final RiskPublisher publisher,
                             final RiskSignalGatherer gatherer,
                             final OtpVerifier otpVerifier) {
        this.policyResolver = policyResolver;
        this.evaluator = evaluator;
        this.publisher = publisher;
        this.gatherer = gatherer;
        this.otpVerifier = otpVerifier;
    }

    @Override
    public AuthenticatorMetadata metadata() {
        return AuthenticatorMetadata.condition(ID, "Adaptive risk-based authentication");
    }

    @Override
    public void authenticate(final AuthenticationContext context) {
        final RiskPolicy policy = policyResolver.resolve(context.realmId());
        if (!policy.enabled()) {
            context.success(); // DEFAULT: feature off → login path completely unchanged.
            return;
        }

        final HttpServletRequest request = currentRequest();
        final RiskSignalGatherer.RawSignals raw = gatherer.gather(request);

        final RiskSignals signals = lookupSignals(context, raw);
        final RiskAssessment assessment = evaluator.evaluate(signals, policy);
        LOG.info("Risk assessment realm={} user={} score={} band={} action={} reasons={}",
                context.realmId(), context.userId(), assessment.score(), assessment.band(),
                assessment.action(), assessment.reasons());

        final RiskAction action = assessment.action();
        if (action == RiskAction.DENY) {
            context.failure("Sign-in blocked by the security policy (risk score " + assessment.score() + ")");
            return;
        }
        if (action == RiskAction.STEP_UP && otpVerifier != null) {
            context.putAttribute(STEPUP_ATTRIBUTE, Boolean.TRUE);
            context.challenge(OTP_VIEW);
            return;
        }
        // ALLOW (or STEP_UP with no verifier available): pass through and remember this device/IP.
        recordSuccess(context, raw);
        context.success();
    }

    @Override
    public void action(final AuthenticationContext context) {
        if (!Boolean.TRUE.equals(context.getAttribute(STEPUP_ATTRIBUTE))) {
            // No step-up was pending — nothing to verify; re-run the assessment.
            authenticate(context);
            return;
        }
        final String code = context.formParameter(CODE_PARAM);
        if (code != null && otpVerifier != null && otpVerifier.verify(context.userId(), code)) {
            recordSuccess(context, gatherer.gather(currentRequest()));
            context.success();
        } else {
            context.failure("Invalid authentication code");
        }
    }

    private RiskSignals lookupSignals(final AuthenticationContext context,
                                      final RiskSignalGatherer.RawSignals raw) {
        try {
            final RiskSignals s = publisher.evaluateSignals(new RiskSignalRequest(
                    context.realmId(), context.userId(), raw.deviceFingerprint(), raw.ip(), null));
            return s == null ? new RiskSignals() : s;
        } catch (final RuntimeException e) {
            // Fail-open on the signal lookup so a transient subscriber/AMQP hiccup never blocks login.
            // With no signals the score is 0 → LOW → policy's low action (ALLOW by default).
            LOG.warn("Risk-signal lookup failed for realm={} user={}: {} — treating as low risk",
                    context.realmId(), context.userId(), e.getMessage());
            return new RiskSignals();
        }
    }

    private void recordSuccess(final AuthenticationContext context, final RiskSignalGatherer.RawSignals raw) {
        // Ensure the device has a stable remembered-device token, minting + setting the cookie if absent.
        String fingerprint = raw.deviceFingerprint();
        final HttpServletResponse response = currentResponse();
        if (fingerprint == null && response != null) {
            final String token = newDeviceToken();
            fingerprint = RiskSignalGatherer.sha256(token);
            final Cookie cookie = new Cookie(RiskSignalGatherer.DEVICE_COOKIE, token);
            cookie.setHttpOnly(true);
            cookie.setSecure(isSecure());
            cookie.setPath("/");
            cookie.setMaxAge(DEVICE_COOKIE_MAX_AGE_SECONDS);
            response.addCookie(cookie);
        }
        try {
            publisher.recordLogin(new RiskLoginRecord(context.realmId(), context.userId(),
                    fingerprint, raw.ip(), null, raw.userAgent()));
        } catch (final RuntimeException e) {
            LOG.warn("Failed to record risk login history for realm={} user={}: {}",
                    context.realmId(), context.userId(), e.getMessage());
        }
    }

    private static String newDeviceToken() {
        final byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static HttpServletRequest currentRequest() {
        final ServletRequestAttributes attrs = currentAttributes();
        return attrs == null ? null : attrs.getRequest();
    }

    private static HttpServletResponse currentResponse() {
        final ServletRequestAttributes attrs = currentAttributes();
        return attrs == null ? null : attrs.getResponse();
    }

    private static boolean isSecure() {
        final HttpServletRequest request = currentRequest();
        return request != null && request.isSecure();
    }

    private static ServletRequestAttributes currentAttributes() {
        final var attrs = RequestContextHolder.getRequestAttributes();
        return attrs instanceof ServletRequestAttributes sra ? sra : null;
    }
}
