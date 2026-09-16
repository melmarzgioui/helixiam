package io.helixiam.authorization.service.user;

import io.helixiam.authorization.domain.device.DeviceCredentialEntity;
import io.helixiam.authorization.domain.mfa.HotpCredentialEntity;
import io.helixiam.authorization.domain.mfa.RecoveryCodeEntity;
import io.helixiam.authorization.domain.mfa.WebAuthnCredentialEntity;
import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.domain.user.admin.CredentialSummary;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.device.DeviceCredentialRepository;
import io.helixiam.authorization.repository.mfa.HotpCredentialRepository;
import io.helixiam.authorization.repository.mfa.RecoveryCodeRepository;
import io.helixiam.authorization.repository.mfa.WebAuthnCredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E8.5: the console's Device &amp; passkeys screen reads every enrolled factor for a user as a
 * flat, secret-free {@link CredentialSummary} list and revokes one by (type,id). These tests prove the
 * aggregation across all factor stores and that each revoke type deletes from the right store only.
 */
class CredentialAdminServiceTest {

    private DeviceCredentialRepository devices;
    private WebAuthnCredentialRepository passkeys;
    private HotpCredentialRepository hotp;
    private RecoveryCodeRepository recovery;
    private UserCredentialsRepository users;
    private CredentialAdminService service;

    @BeforeEach
    void setUp() {
        devices = mock(DeviceCredentialRepository.class);
        passkeys = mock(WebAuthnCredentialRepository.class);
        hotp = mock(HotpCredentialRepository.class);
        recovery = mock(RecoveryCodeRepository.class);
        users = mock(UserCredentialsRepository.class);
        service = new CredentialAdminService(devices, passkeys, hotp, recovery, users);

        when(devices.findAllByUserId(anyString())).thenReturn(List.of());
        when(passkeys.findAllByUserId(anyString())).thenReturn(List.of());
        when(hotp.findByUserId(anyString())).thenReturn(Optional.empty());
        when(recovery.findAllByUserIdAndUsedFalse(anyString())).thenReturn(List.of());
        when(users.findByUserId(anyString())).thenReturn(Optional.empty());
    }

    @Test
    void aggregatesEveryFactorStoreIntoOneList() {
        when(passkeys.findAllByUserId("u1"))
                .thenReturn(List.of(new WebAuthnCredentialEntity("cred-1", "u1", "att", 7)));
        when(devices.findAllByUserId("u1"))
                .thenReturn(List.of(new DeviceCredentialEntity("dev-1", "u1", "pk", "apple-app-attest", true)));
        when(hotp.findByUserId("u1")).thenReturn(Optional.of(new HotpCredentialEntity("u1", "secret", 3)));
        when(recovery.findAllByUserIdAndUsedFalse("u1"))
                .thenReturn(List.of(new RecoveryCodeEntity("rc-1", "u1", "h1"),
                        new RecoveryCodeEntity("rc-2", "u1", "h2")));
        final UserCredentials user = new UserCredentials();
        user.setMfaEnabled(true);
        user.setMfaSecret("totp-secret");
        when(users.findByUserId("u1")).thenReturn(Optional.of(user));

        final List<CredentialSummary> all = service.list("u1");

        assertThat(all).extracting(CredentialSummary::type)
                .containsExactlyInAnyOrder("passkey", "device", "totp", "hotp", "recovery-code");
        assertThat(all).filteredOn(c -> c.type().equals("passkey")).first()
                .extracting(CredentialSummary::id).isEqualTo("cred-1");
        assertThat(all).filteredOn(c -> c.type().equals("recovery-code")).first()
                .extracting(CredentialSummary::detail).asString().contains("2");
    }

    @Test
    void omitsTotpWhenSecretAbsentEvenIfFlagSet() {
        final UserCredentials user = new UserCredentials();
        user.setMfaEnabled(true);
        user.setMfaSecret(null);
        when(users.findByUserId("u1")).thenReturn(Optional.of(user));

        assertThat(service.list("u1")).noneMatch(c -> c.type().equals("totp"));
    }

    @Test
    void revokePasskeyDeletesOnlyFromPasskeyStore() {
        when(passkeys.findById("cred-1"))
                .thenReturn(Optional.of(new WebAuthnCredentialEntity("cred-1", "u1", "att", 1)));

        assertThat(service.revoke("u1", "passkey", "cred-1")).isTrue();

        verify(passkeys).deleteById("cred-1");
        verify(devices, never()).deleteById(anyString());
    }

    @Test
    void revokePasskeyOwnedByAnotherUserIsRejected() {
        when(passkeys.findById("cred-1"))
                .thenReturn(Optional.of(new WebAuthnCredentialEntity("cred-1", "someone-else", "att", 1)));

        assertThat(service.revoke("u1", "passkey", "cred-1")).isFalse();
        verify(passkeys, never()).deleteById(anyString());
    }

    @Test
    void revokeDeviceDeletesFromDeviceStore() {
        when(devices.findById("dev-1"))
                .thenReturn(Optional.of(new DeviceCredentialEntity("dev-1", "u1", "pk", "none", false)));

        assertThat(service.revoke("u1", "device", "dev-1")).isTrue();
        verify(devices).deleteById("dev-1");
    }

    @Test
    void revokeTotpClearsSecretAndFlagOnUser() {
        final UserCredentials user = new UserCredentials();
        user.setMfaEnabled(true);
        user.setMfaSecret("totp-secret");
        when(users.findByUserId("u1")).thenReturn(Optional.of(user));
        when(users.save(any(UserCredentials.class))).thenAnswer(inv -> inv.getArgument(0));

        assertThat(service.revoke("u1", "totp", "totp")).isTrue();

        assertThat(user.getMfaSecret()).isNull();
        assertThat(user.isMfaEnabled()).isFalse();
        verify(users).save(user);
    }

    @Test
    void revokeHotpDeletesByUserId() {
        when(hotp.findByUserId("u1")).thenReturn(Optional.of(new HotpCredentialEntity("u1", "s", 0)));

        assertThat(service.revoke("u1", "hotp", "hotp")).isTrue();
        verify(hotp).deleteById("u1");
    }

    @Test
    void revokeRecoveryCodesDeletesAllForUser() {
        when(recovery.findAllByUserIdAndUsedFalse("u1"))
                .thenReturn(List.of(new RecoveryCodeEntity("rc-1", "u1", "h")));

        assertThat(service.revoke("u1", "recovery-code", "recovery-codes")).isTrue();
        verify(recovery).deleteAllByUserId("u1");
    }

    @Test
    void revokeUnknownTypeReturnsFalse() {
        assertThat(service.revoke("u1", "smoke-signal", "x")).isFalse();
    }
}
