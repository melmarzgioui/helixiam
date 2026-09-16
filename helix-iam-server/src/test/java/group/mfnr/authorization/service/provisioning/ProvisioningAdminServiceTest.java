package group.mfnr.authorization.service.provisioning;

import group.mfnr.authorization.domain.provisioning.DcrInitialAccessToken;
import group.mfnr.authorization.domain.provisioning.RealmProvisioningConfig;
import group.mfnr.authorization.domain.provisioning.admin.DcrBindRequest;
import group.mfnr.authorization.domain.provisioning.admin.DcrRegistrationDto;
import group.mfnr.authorization.domain.provisioning.admin.ProvisioningConfigResult;
import group.mfnr.authorization.domain.provisioning.admin.ProvisioningConfigWriteDto;
import group.mfnr.authorization.domain.provisioning.admin.ScimTokenCheck;
import group.mfnr.authorization.repository.provisioning.DcrInitialAccessTokenRepository;
import group.mfnr.authorization.repository.provisioning.DcrRegistrationRepository;
import group.mfnr.authorization.repository.provisioning.RealmProvisioningConfigRepository;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E11: the provisioning-domain store — SCIM token rotate/verify (stored hashed; rejects when no
 * token is set or the wrong token is presented), DCR open/gated default, and single-use initial access
 * tokens. The clear token is returned exactly once on rotate; only its hash is persisted.
 */
class ProvisioningAdminServiceTest {

    private final RealmProvisioningConfigRepository configs = mock(RealmProvisioningConfigRepository.class);
    private final DcrRegistrationRepository registrations = mock(DcrRegistrationRepository.class);
    private final DcrInitialAccessTokenRepository initialTokens = mock(DcrInitialAccessTokenRepository.class);
    private final ProvisioningAdminService service =
            new ProvisioningAdminService(configs, registrations, initialTokens);

    @Test
    void rotateScimToken_returnsClearTokenOnce_andStoresOnlyTheHash() {
        when(configs.findById("gov")).thenReturn(Optional.empty());
        when(configs.save(any())).thenAnswer(inv -> inv.getArgument(0));

        final ProvisioningConfigResult result = service.saveConfig(
                new ProvisioningConfigWriteDto("gov", null, true, false));

        assertThat(result.newScimToken()).isNotBlank();
        assertThat(result.config().scimTokenSet()).isTrue();

        final var captor = org.mockito.ArgumentCaptor.forClass(RealmProvisioningConfig.class);
        verify(configs).save(captor.capture());
        // Persisted value is the SHA-256 hash, never the clear token.
        assertThat(captor.getValue().getScimTokenHash())
                .isEqualTo(ProvisioningTokens.hash(result.newScimToken()))
                .isNotEqualTo(result.newScimToken());
    }

    @Test
    void verifyScimToken_trueOnlyForTheStoredToken() {
        final String token = "the-real-token";
        final RealmProvisioningConfig config = RealmProvisioningConfig.defaults("gov");
        config.setScimTokenHash(ProvisioningTokens.hash(token));
        when(configs.findById("gov")).thenReturn(Optional.of(config));

        assertThat(service.verifyScimToken(new ScimTokenCheck("gov", token))).isTrue();
        assertThat(service.verifyScimToken(new ScimTokenCheck("gov", "wrong"))).isFalse();
    }

    @Test
    void verifyScimToken_falseWhenRealmHasNoTokenSet() {
        when(configs.findById("gov")).thenReturn(Optional.of(RealmProvisioningConfig.defaults("gov")));

        assertThat(service.verifyScimToken(new ScimTokenCheck("gov", "anything"))).isFalse();
    }

    @Test
    void dcrIsGatedByDefault_whenNoRowExists() {
        when(configs.findById("gov")).thenReturn(Optional.empty());

        assertThat(service.isDcrOpen("gov")).isFalse();
    }

    @Test
    void consumeInitialAccessToken_validatesAndDeletesSingleUse() {
        final String token = "iat-123";
        final DcrInitialAccessToken stored = new DcrInitialAccessToken("gov", ProvisioningTokens.hash(token));
        when(initialTokens.findByRealmIdAndTokenHash("gov", ProvisioningTokens.hash(token)))
                .thenReturn(Optional.of(stored));

        assertThat(service.consumeInitialAccessToken("gov", token)).isTrue();
        verify(initialTokens).delete(stored);
    }

    @Test
    void consumeInitialAccessToken_falseForUnknownToken() {
        when(initialTokens.findByRealmIdAndTokenHash(any(), any())).thenReturn(Optional.empty());

        assertThat(service.consumeInitialAccessToken("gov", "nope")).isFalse();
    }

    @Test
    void bind_issuesRegistrationTokenOnce_andStoresHash() {
        when(registrations.save(any())).thenAnswer(inv -> inv.getArgument(0));

        final DcrRegistrationDto dto = service.bind(new DcrBindRequest("gov", "internal-1", "dcr-abc"));

        assertThat(dto.registrationToken()).isNotBlank();
        assertThat(dto.clientId()).isEqualTo("dcr-abc");
        assertThat(dto.clientInternalId()).isEqualTo("internal-1");
    }
}
