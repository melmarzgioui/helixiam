package group.mfnr.authorization.service;

import group.mfnr.authorization.domain.user.UserCredentials;
import group.mfnr.authorization.repository.ChangePasswordRepository;
import group.mfnr.authorization.repository.MfaUserRepository;
import group.mfnr.authorization.repository.UserCredentialsRepository;
import group.mfnr.authorization.repository.VerifyEmailRepository;
import io.helixiam.notification.Notifier;
import io.helixiam.notification.repository.NotificationCodeRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Helix IAM: user-claim assembly for OIDC tokens. The {@code email} column and {@code username}
 * are surfaced as claims (mapped downstream to {@code email}/{@code preferred_username}) alongside
 * the free-form profile attributes.
 */
class UserServiceTest {

    private UserCredentialsRepository userCredentialsRepository;
    private UserService service;

    @BeforeEach
    void setUp() {
        userCredentialsRepository = mock(UserCredentialsRepository.class);
        service = new UserService(userCredentialsRepository, mock(ChangePasswordRepository.class),
                mock(NotificationCodeRepository.class), mock(VerifyEmailRepository.class),
                mock(MfaUserRepository.class), mock(Notifier.class), new PasswordEncoderService());
    }

    @Test
    void userClaims_includesEmailAndUsername_alongsideAttributes() {
        final UserCredentials user = new UserCredentials();
        user.setUserId("u-1");
        user.setUsername("alice");
        user.setEmail("alice@example.com");
        user.getUserAttributes().put("department", "Tax");
        when(userCredentialsRepository.findByUserId("u-1")).thenReturn(Optional.of(user));

        final Map<String, String> claims = service.userClaims("u-1");

        assertEquals("alice@example.com", claims.get("email"));
        assertEquals("alice", claims.get("username"));
        assertEquals("Tax", claims.get("department"));
    }

    @Test
    void userClaims_omitsEmail_whenNotSet() {
        final UserCredentials user = new UserCredentials();
        user.setUserId("u-2");
        user.setUsername("svc-account");
        when(userCredentialsRepository.findByUserId("u-2")).thenReturn(Optional.of(user));

        final Map<String, String> claims = service.userClaims("u-2");

        assertFalse(claims.containsKey("email"), "no email column → no email claim");
        assertEquals("svc-account", claims.get("username"));
    }

    @Test
    void userClaims_doesNotOverrideExplicitAttribute() {
        final UserCredentials user = new UserCredentials();
        user.setUserId("u-3");
        user.setUsername("alice");
        user.setEmail("column@example.com");
        // An explicit profile attribute wins over the column-derived default.
        user.getUserAttributes().put("email", "attr@example.com");
        when(userCredentialsRepository.findByUserId("u-3")).thenReturn(Optional.of(user));

        assertEquals("attr@example.com", service.userClaims("u-3").get("email"));
    }
}
