package group.mfnr.authorization.service.realm;

import group.mfnr.authorization.domain.realm.RealmConfig;
import group.mfnr.authorization.domain.realm.admin.RealmSettingsDto;
import group.mfnr.authorization.service.RealmService;
import group.mfnr.authorization.service.client.ConsoleClientBootstrapService;
import group.mfnr.authorization.service.flow.AuthFlowService;
import group.mfnr.authorization.service.role.DefaultRolesBootstrapService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E8.5-S4: realm settings administration.
 */
class RealmAdminServiceTest {

    private RealmService realmService;
    private ConsoleClientBootstrapService consoleClientBootstrapService;
    private RealmAdminService service;

    @BeforeEach
    void setUp() {
        realmService = mock(RealmService.class);
        consoleClientBootstrapService = mock(ConsoleClientBootstrapService.class);
        service = new RealmAdminService(realmService, mock(RealmAdminBootstrapService.class),
                mock(AuthFlowService.class), mock(DefaultRolesBootstrapService.class),
                consoleClientBootstrapService);
    }

    @Test
    void save_seedsConsoleClient_forNewRealm() {
        when(realmService.getOrDefault("acme")).thenReturn(RealmConfig.defaults("acme"));
        when(realmService.exists("acme")).thenReturn(false);
        when(realmService.save(any(RealmConfig.class))).thenAnswer(inv -> inv.getArgument(0));

        service.save(new RealmSettingsDto("acme", "Acme", null,
                900, 1_209_600, false, false, 8, true, 1_800, 36_000, true, 2_592_000,
                true, 5, 900, 600, false,
                false, false, false, false, false, 0,
                false, "none", null, null, 2, false, false, 30, 80, "allow", "step_up", "deny",
                null, null, null, null, null,
                true));

        verify(consoleClientBootstrapService).ensureConsoleClient("acme");
    }

    @Test
    void get_returnsPlatformDefaults_whenNoRowExists() {
        when(realmService.getOrDefault("gov")).thenReturn(RealmConfig.defaults("gov"));

        final RealmSettingsDto dto = service.get("gov");

        assertEquals("gov", dto.realmId());
        assertEquals(RealmConfig.DEFAULT_ACCESS_TOKEN_TTL_SECONDS, dto.accessTokenTtlSeconds());
        assertEquals(RealmConfig.DEFAULT_PASSWORD_MIN_LENGTH, dto.passwordMinLength());
        assertTrue(dto.enabled());
        assertFalse(dto.requireMfa());
    }

    @Test
    void save_appliesEveryField_andUpserts() {
        when(realmService.getOrDefault("gov")).thenReturn(RealmConfig.defaults("gov"));
        when(realmService.save(any(RealmConfig.class))).thenAnswer(inv -> inv.getArgument(0));

        final RealmSettingsDto dto = service.save(new RealmSettingsDto("gov", "Government NL", "https://idp.gov.nl",
                900, 1_209_600, true, true, 16, false, 600, 7_200, true, 1_209_600,
                true, 4, 1_200, 600, false,
                true, true, true, true, true, 3,
                true, "turnstile", "site-key", "secret-key", 2, false, true, 30, 80, "allow", "deny", "deny",
                "https://cdn/logo.svg", "#0a7d52", "#f5f8f6", "Welcome to Gov NL", ".hx{color:red}",
                true));

        // Auth-hardening fields round-trip onto the entity.
        // (assertions appended below via the captor)

        final ArgumentCaptor<RealmConfig> captor = ArgumentCaptor.forClass(RealmConfig.class);
        verify(realmService).save(captor.capture());
        final RealmConfig saved = captor.getValue();
        assertEquals("Government NL", saved.getDisplayName());
        assertEquals("https://idp.gov.nl", saved.getIssuer());
        assertEquals(900, saved.getAccessTokenTtlSeconds());
        assertEquals(1_209_600, saved.getRefreshTokenTtlSeconds());
        assertTrue(saved.isReuseRefreshTokens());
        assertTrue(saved.isRequireMfa());
        assertEquals(16, saved.getPasswordMinLength());
        assertFalse(saved.isEnabled());
        // SSO P3 session policies round-trip onto the entity.
        assertEquals(600, saved.getSsoSessionIdleTimeoutSeconds());
        assertEquals(7_200, saved.getSsoSessionMaxLifetimeSeconds());
        assertTrue(saved.isRememberMe());
        assertEquals(1_209_600, saved.getRememberMeLifetimeSeconds());

        assertEquals("Government NL", dto.displayName());
        assertEquals(16, dto.passwordMinLength());
        assertEquals(600, dto.ssoSessionIdleTimeoutSeconds());
        assertEquals(7_200, dto.ssoSessionMaxLifetimeSeconds());
        assertTrue(dto.rememberMe());
        assertEquals(1_209_600, dto.rememberMeLifetimeSeconds());

        // Auth-hardening: account lockout + password policy + breached + captcha + concurrency round-trip.
        assertTrue(saved.isLockoutEnabled());
        assertEquals(4, saved.getMaxLoginFailures());
        assertEquals(1_200, saved.getLockoutDurationSeconds());
        assertEquals(600, saved.getFailureResetSeconds());
        assertTrue(saved.isPasswordRequireUppercase());
        assertTrue(saved.isPasswordNotUsername());
        assertEquals(3, saved.getPasswordHistoryCount());
        assertTrue(saved.isBreachedPasswordCheck());
        assertEquals("turnstile", saved.getCaptchaProvider());
        assertEquals("site-key", saved.getCaptchaSiteKey());
        assertEquals("secret-key", saved.getCaptchaSecretKey());
        assertEquals(2, saved.getMaxConcurrentSessions());
        assertFalse(saved.isConcurrentSessionEvictOldest());
        // The subscriber DTO carries the secret over the internal AMQP seam (the publisher controller
        // strips it before the browser); so the persisted entity holds it.
        assertEquals("secret-key", saved.getCaptchaSecretKey());

        // B2: per-realm login theming round-trips onto the entity + back into the returned DTO.
        assertEquals("https://cdn/logo.svg", saved.getLogoUrl());
        assertEquals("#0a7d52", saved.getPrimaryColor());
        assertEquals("#f5f8f6", saved.getBackgroundColor());
        assertEquals("Welcome to Gov NL", saved.getWelcomeText());
        assertEquals(".hx{color:red}", saved.getCustomCss());
        assertEquals("https://cdn/logo.svg", dto.logoUrl());
        assertEquals("#0a7d52", dto.primaryColor());
    }

    @Test
    void registrationEnabled_roundTripsThroughSaveAndGet_defaultsTrue() {
        when(realmService.getOrDefault("acme2")).thenReturn(RealmConfig.defaults("acme2"));
        when(realmService.save(any(RealmConfig.class))).thenAnswer(inv -> inv.getArgument(0));

        // A DTO with registration explicitly disabled must persist as-is.
        final RealmSettingsDto disabled = new RealmSettingsDto("acme2", "Acme2", null,
                900, 1_209_600, false, false, 8, true, 1_800, 36_000, true, 2_592_000,
                true, 5, 900, 600, false,
                false, false, false, false, false, 0,
                false, "none", null, null, 2, false, false, 30, 80, "allow", "step_up", "deny",
                null, null, null, null, null,
                false);
        service.save(disabled);

        final ArgumentCaptor<RealmConfig> captor = ArgumentCaptor.forClass(RealmConfig.class);
        verify(realmService).save(captor.capture());
        assertFalse(captor.getValue().isRegistrationEnabled());

        // A freshly-defaulted realm config reports registration enabled.
        when(realmService.getOrDefault("beta")).thenReturn(RealmConfig.defaults("beta"));
        assertTrue(service.get("beta").registrationEnabled());
    }
}
