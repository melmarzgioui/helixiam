package group.mfnr.authorization.service.user;

import group.mfnr.authorization.domain.user.UserCredentials;
import group.mfnr.authorization.domain.user.admin.UserChangePasswordDto;
import group.mfnr.authorization.repository.UserCredentialsRepository;
import group.mfnr.authorization.repository.tenant.TenantRepository;
import group.mfnr.authorization.repository.tenant.TenantUserRepository;
import group.mfnr.authorization.service.PasswordEncoderService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM (6) Self-service Account: the user-driven password change must <em>verify the current password</em>
 * before setting a new one — unlike the admin reset. These prove the verify-current contract: a wrong current
 * password never re-hashes/saves, a correct one Argon2id-encodes the new password and clears the legacy salt,
 * and a missing/absent user is rejected.
 */
class UserAdminServiceChangePasswordTest {

    private TenantUserRepository tenantUsers;
    private TenantRepository tenants;
    private UserCredentialsRepository users;
    private PasswordEncoderService encoder;
    private UserAdminService service;

    @BeforeEach
    void setUp() {
        tenantUsers = mock(TenantUserRepository.class);
        tenants = mock(TenantRepository.class);
        users = mock(UserCredentialsRepository.class);
        encoder = mock(PasswordEncoderService.class);
        service = new UserAdminService(tenantUsers, tenants, users, encoder);
    }

    private UserCredentials stored() {
        final UserCredentials u = new UserCredentials();
        u.setPassword("$argon2id$stored");
        u.setPasswordSaltValue("legacy-salt");
        return u;
    }

    @Test
    void changePassword_correctCurrent_reEncodesNewAndClearsSalt() {
        final UserCredentials user = stored();
        when(users.findByUserId("u1")).thenReturn(Optional.of(user));
        when(encoder.matches("old", "$argon2id$stored", "legacy-salt")).thenReturn(true);
        when(encoder.encode("new")).thenReturn("$argon2id$new");

        final boolean ok = service.changePassword(new UserChangePasswordDto("master", "u1", "old", "new"));

        assertThat(ok).isTrue();
        assertThat(user.getPassword()).isEqualTo("$argon2id$new");
        assertThat(user.getPasswordSaltValue()).isNull();
        verify(users).save(user);
    }

    @Test
    void changePassword_wrongCurrent_returnsFalse_andNeverSaves() {
        final UserCredentials user = stored();
        when(users.findByUserId("u1")).thenReturn(Optional.of(user));
        when(encoder.matches(eq("wrong"), eq("$argon2id$stored"), eq("legacy-salt"))).thenReturn(false);

        final boolean ok = service.changePassword(new UserChangePasswordDto("master", "u1", "wrong", "new"));

        assertThat(ok).isFalse();
        assertThat(user.getPassword()).isEqualTo("$argon2id$stored"); // unchanged
        verify(users, never()).save(user);
    }

    @Test
    void changePassword_absentUser_returnsFalse() {
        when(users.findByUserId("ghost")).thenReturn(Optional.empty());

        final boolean ok = service.changePassword(new UserChangePasswordDto("master", "ghost", "old", "new"));

        assertThat(ok).isFalse();
        verify(users, never()).save(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void changePassword_blankNewPassword_isRejected() {
        assertThatThrownBy(() -> service.changePassword(new UserChangePasswordDto("master", "u1", "old", "  ")))
                .isInstanceOf(IllegalArgumentException.class);
        verify(users, never()).save(org.mockito.ArgumentMatchers.any());
    }
}
