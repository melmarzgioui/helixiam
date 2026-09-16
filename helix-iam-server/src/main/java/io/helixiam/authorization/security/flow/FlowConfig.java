package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.flow.FlowEvaluator;
import io.helixiam.authorization.flow.FlowExecutor;
import io.helixiam.authorization.flow.authenticators.CredentialVerifier;
import io.helixiam.authorization.flow.authenticators.DeviceAuthenticator;
import io.helixiam.authorization.flow.authenticators.HotpAuthenticator;
import io.helixiam.authorization.flow.authenticators.OtpAuthenticator;
import io.helixiam.authorization.flow.authenticators.OtpVerifier;
import io.helixiam.authorization.flow.authenticators.PasswordlessLoginAuthenticator;
import io.helixiam.authorization.flow.authenticators.ResidentKeyResolver;
import io.helixiam.authorization.flow.authenticators.WebAuthnAuthenticator;
import org.springframework.beans.factory.annotation.Value;
import io.helixiam.authorization.flow.authenticators.otp.EmailOtpAuthenticator;
import io.helixiam.authorization.flow.authenticators.otp.OtpSender;
import io.helixiam.authorization.flow.authenticators.otp.SmsOtpAuthenticator;
import io.helixiam.authorization.flow.authenticators.recovery.RecoveryCodeAuthenticator;
import io.helixiam.authorization.flow.authenticators.recovery.RecoveryCodeVerifier;
import io.helixiam.authorization.amqp.device.DeviceEnrollmentPublisher;
import io.helixiam.authorization.flow.authenticators.PushApprovalAuthenticator;
import io.helixiam.authorization.flow.device.DeviceEnrollmentService;
import io.helixiam.authorization.flow.device.DeviceEnrollmentTicketStore;
import io.helixiam.authorization.flow.device.InMemoryDeviceEnrollmentTicketStore;
import io.helixiam.authorization.flow.magiclink.InMemoryMagicLinkTokenStore;
import io.helixiam.authorization.flow.magiclink.MagicLinkSender;
import io.helixiam.authorization.flow.magiclink.MagicLinkService;
import io.helixiam.authorization.flow.magiclink.MagicLinkTokenStore;
import io.helixiam.authorization.flow.authenticators.QrLoginAuthenticator;
import io.helixiam.authorization.flow.persistence.AuthFlowMapper;
import io.helixiam.authorization.flow.push.InMemoryPushApprovalStore;
import io.helixiam.authorization.flow.push.PushApprovalService;
import io.helixiam.authorization.flow.push.PushApprovalStore;
import io.helixiam.authorization.flow.push.PushSender;
import io.helixiam.authorization.flow.qr.InMemoryQrSessionStore;
import io.helixiam.authorization.flow.qr.QrLoginService;
import io.helixiam.authorization.flow.qr.QrSessionStore;
import io.helixiam.authorization.flow.wysiwys.InMemoryTransactionSigningStore;
import io.helixiam.authorization.flow.wysiwys.TransactionSigningService;
import io.helixiam.authorization.flow.wysiwys.TransactionSigningStore;
import io.helixiam.authorization.flow.spi.Authenticator;
import io.helixiam.authorization.flow.spi.AuthenticatorRegistry;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.function.IntSupplier;
import java.util.function.Supplier;

/**
 * Helix IAM E2.4: wires the flow engine into Spring.
 *
 * <p><b>Pluggable SPI discovery:</b> the {@link AuthenticatorRegistry} is built from <i>every</i>
 * {@link Authenticator} bean in the context (injected as {@code List<Authenticator>}). A new
 * factor is therefore added by simply dropping a bean that implements {@code Authenticator} — a
 * {@code @Component} on the classpath, or a {@code @Bean} here — with no change to the engine,
 * the registry, or this config. Helix auto-detects it at startup, registers it under its
 * {@code metadata().id()}, and any realm flow can reference and execute it. The built-ins below
 * are just the bundled beans; third-party plugins join the same way. (Out-of-process signed
 * plugin JARs via ServiceLoader are Epic 9.)
 */
@Configuration
public class FlowConfig {

    private static final Logger LOG = LogManager.getLogger(FlowConfig.class);

    @Bean
    public FlowEvaluator flowEvaluator() {
        return new FlowEvaluator();
    }

    // --- Built-in authenticators, each a discoverable Authenticator bean. ---

    @Bean
    public Authenticator totpAuthenticator(final OtpVerifier otpVerifier) {
        return new OtpAuthenticator(otpVerifier);                                 // TOTP (E2.3)
    }

    // Notifications (N3): SMS-OTP routes through the realm's configured SMS provider; Email-OTP through the
    // realm's email provider. Each falls back to logging the code when no provider is configured (dev parity).
    @Bean
    public Authenticator smsOtpAuthenticator(final io.helixiam.authorization.messaging.MessagingService messaging,
                                             final io.helixiam.authorization.service.UserInfoService userInfo) {
        return new SmsOtpAuthenticator(
                new io.helixiam.authorization.messaging.sender.RealmSmsOtpSender(messaging, userInfo),
                System::currentTimeMillis);
    }

    @Bean
    public Authenticator emailOtpAuthenticator(final io.helixiam.authorization.messaging.MessagingService messaging,
                                               final io.helixiam.authorization.service.UserInfoService userInfo) {
        return new EmailOtpAuthenticator(
                new io.helixiam.authorization.messaging.sender.RealmEmailOtpSender(messaging, userInfo),
                System::currentTimeMillis);
    }

    @Bean
    public Authenticator recoveryCodeAuthenticator(final RecoveryCodeVerifier recoveryCodeVerifier) {
        return new RecoveryCodeAuthenticator(recoveryCodeVerifier);               // E3.2
    }

    @Bean
    public Authenticator hotpAuthenticator(final CredentialVerifier credentialVerifier) {
        return new HotpAuthenticator(credentialVerifier);                         // E3.4 (via Credential SPI)
    }

    @Bean
    public Authenticator webauthnAuthenticator(final CredentialVerifier credentialVerifier,
                                               @Value("${helix.webauthn.rp-id:localhost}") final String rpId,
                                               @Value("${helix.webauthn.origin:http://localhost:8083}") final String origin) {
        return new WebAuthnAuthenticator(credentialVerifier, rpId, origin);       // E3.3 (passkeys, via Credential SPI)
    }

    @Bean
    public Authenticator passwordlessLoginAuthenticator(final ResidentKeyResolver residentKeyResolver,
                                                        @Value("${helix.webauthn.rp-id:localhost}") final String rpId,
                                                        @Value("${helix.webauthn.origin:http://localhost:8083}") final String origin) {
        // (10) passwordless usernameless passkey login — a phishing-resistant, identity-establishing FIRST step.
        return new PasswordlessLoginAuthenticator(residentKeyResolver, rpId, origin);
    }

    @Bean
    public Authenticator deviceAuthenticator(final CredentialVerifier credentialVerifier) {
        return new DeviceAuthenticator(credentialVerifier);                       // E4.1 (device factor, via Credential SPI)
    }

    @Bean
    @ConditionalOnMissingBean(QrSessionStore.class)
    public QrSessionStore qrSessionStore() {
        return new InMemoryQrSessionStore();                                      // E4.2 (Redis impl can override)
    }

    @Bean
    public QrLoginService qrLoginService(final QrSessionStore qrSessionStore,
                                         final CredentialVerifier credentialVerifier,
                                         @Value("${helix.qr.ttl-millis:300000}") final long ttlMillis,
                                         @Value("${helix.qr.rotation-millis:30000}") final long rotationMillis) {
        final SecureRandom random = new SecureRandom();
        final Supplier<String> tokenGenerator = () -> {
            final byte[] bytes = new byte[32];
            random.nextBytes(bytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        };
        return new QrLoginService(qrSessionStore, credentialVerifier, tokenGenerator,
                System::currentTimeMillis, ttlMillis, rotationMillis);
    }

    @Bean
    public Authenticator qrLoginAuthenticator(final QrLoginService qrLoginService) {
        return new QrLoginAuthenticator(qrLoginService);                          // E4.2 (cross-device QR login)
    }

    @Bean
    @ConditionalOnMissingBean(PushApprovalStore.class)
    public PushApprovalStore pushApprovalStore() {
        return new InMemoryPushApprovalStore();                                   // E4.3 (Redis impl can override)
    }

    @Bean
    public PushApprovalService pushApprovalService(final PushApprovalStore pushApprovalStore,
                                                   final CredentialVerifier credentialVerifier,
                                                   final PushSender pushSender,
                                                   @Value("${helix.push.ttl-millis:120000}") final long ttlMillis) {
        final SecureRandom random = new SecureRandom();
        final Supplier<String> tokenGenerator = () -> {
            final byte[] bytes = new byte[32];
            random.nextBytes(bytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        };
        final IntSupplier numberGenerator = () -> 10 + random.nextInt(90); // 2-digit (10..99)
        return new PushApprovalService(pushApprovalStore, credentialVerifier, pushSender,
                tokenGenerator, numberGenerator, System::currentTimeMillis, ttlMillis);
    }

    @Bean
    public Authenticator pushApprovalAuthenticator(final PushApprovalService pushApprovalService) {
        return new PushApprovalAuthenticator(pushApprovalService);                // E4.3 (push approval, number matching)
    }

    // Dev-default senders. Declared as @Bean @ConditionalOnMissingBean here (NOT @ConditionalOnMissingBean
    // on the @Component classes, where the condition is evaluated unreliably during component scanning)
    // so a real FCM/APNs / email adapter replaces them by defining its own bean.
    @Bean
    @ConditionalOnMissingBean(PushSender.class)
    public PushSender pushSender(final io.helixiam.authorization.messaging.MessagingService messaging,
                                 final io.helixiam.authorization.amqp.messaging.MessagingAdminPublisher publisher,
                                 final io.helixiam.authorization.service.UserInfoService userInfo) {
        // N6c: resolve the user's device tokens + render the push-approval template + dispatch via FCM/APNs
        // (falls back to logging when no provider/device is available).
        return new io.helixiam.authorization.messaging.sender.RealmPushSender(messaging, publisher, userInfo);
    }

    @Bean
    @ConditionalOnMissingBean(MagicLinkSender.class)
    public MagicLinkSender magicLinkSender(final io.helixiam.authorization.messaging.MessagingService messaging,
                                           final io.helixiam.authorization.service.UserInfoService userInfo,
                                           @Value("${helix.magic-link.ttl-millis:600000}") final long ttlMillis) {
        // N6b: render the realm's magic-link-email template + dispatch via the configured email provider
        // (falls back to logging the link when no provider is configured).
        return new io.helixiam.authorization.messaging.sender.RealmMagicLinkSender(messaging, userInfo, ttlMillis);
    }

    @Bean
    @ConditionalOnMissingBean(TransactionSigningStore.class)
    public TransactionSigningStore transactionSigningStore() {
        return new InMemoryTransactionSigningStore();                             // E4.4 (Redis impl can override)
    }

    @Bean
    public TransactionSigningService transactionSigningService(final TransactionSigningStore transactionSigningStore,
                                                               final CredentialVerifier credentialVerifier,
                                                               @Value("${helix.wysiwys.ttl-millis:120000}") final long ttlMillis) {
        final SecureRandom random = new SecureRandom();
        final Supplier<String> tokenGenerator = () -> {
            final byte[] bytes = new byte[32];
            random.nextBytes(bytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        };
        return new TransactionSigningService(transactionSigningStore, credentialVerifier,
                tokenGenerator, System::currentTimeMillis, ttlMillis);            // E4.4 (WYSIWYS transaction signing)
    }

    @Bean
    @ConditionalOnMissingBean(DeviceEnrollmentTicketStore.class)
    public DeviceEnrollmentTicketStore deviceEnrollmentTicketStore() {
        return new InMemoryDeviceEnrollmentTicketStore();                         // E4.1 enrollment (Redis can override)
    }

    @Bean
    public DeviceEnrollmentService deviceEnrollmentService(final DeviceEnrollmentTicketStore deviceEnrollmentTicketStore,
                                                           final DeviceEnrollmentPublisher deviceEnrollmentPublisher,
                                                           @Value("${helix.device.enroll-ttl-millis:300000}") final long ttlMillis) {
        final SecureRandom random = new SecureRandom();
        final Supplier<String> tokenGenerator = () -> {
            final byte[] bytes = new byte[32];
            random.nextBytes(bytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        };
        return new DeviceEnrollmentService(deviceEnrollmentTicketStore, deviceEnrollmentPublisher,
                tokenGenerator, System::currentTimeMillis, ttlMillis);            // E4.1 mobile enrollment endpoint
    }

    @Bean
    @ConditionalOnMissingBean(MagicLinkTokenStore.class)
    public MagicLinkTokenStore magicLinkTokenStore() {
        return new InMemoryMagicLinkTokenStore();                                 // magic-link (Redis can override)
    }

    @Bean
    public MagicLinkService magicLinkService(final MagicLinkTokenStore magicLinkTokenStore,
                                             final MagicLinkSender magicLinkSender,
                                             @Value("${helix.magic-link.ttl-millis:600000}") final long ttlMillis,
                                             @Value("${helix.magic-link.base-url:http://localhost:8083/login/magic}") final String linkBaseUrl) {
        final SecureRandom random = new SecureRandom();
        final Supplier<String> tokenGenerator = () -> {
            final byte[] bytes = new byte[32];
            random.nextBytes(bytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        };
        return new MagicLinkService(magicLinkTokenStore, magicLinkSender,
                tokenGenerator, System::currentTimeMillis, ttlMillis, linkBaseUrl); // passwordless magic-link
    }
    // MfaEnabledCondition (E2.5) is a @Component, so it is discovered automatically too.

    /**
     * Discovers every {@link Authenticator} bean (built-in or third-party plugin) and registers
     * it. Duplicate ids are rejected, so a plugin cannot silently shadow a built-in.
     */
    @Bean
    public AuthenticatorRegistry authenticatorRegistry(final List<Authenticator> authenticators) {
        final AuthenticatorRegistry registry = new AuthenticatorRegistry(authenticators);
        LOG.info("Helix authenticator SPI: discovered {} authenticator(s): {}",
                registry.all().size(),
                registry.all().stream().map(a -> a.metadata().id()).sorted().toList());
        return registry;
    }

    @Bean
    public FlowExecutor flowExecutor(final AuthenticatorRegistry registry, final FlowEvaluator evaluator) {
        return new FlowExecutor(registry, evaluator);
    }

    @Bean
    public AuthFlowMapper authFlowMapper() {
        return new AuthFlowMapper();
    }
}
