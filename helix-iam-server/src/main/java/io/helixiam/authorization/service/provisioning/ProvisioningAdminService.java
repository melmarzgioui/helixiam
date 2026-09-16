package io.helixiam.authorization.service.provisioning;

import io.helixiam.authorization.domain.provisioning.DcrInitialAccessToken;
import io.helixiam.authorization.domain.provisioning.DcrRegistration;
import io.helixiam.authorization.domain.provisioning.RealmProvisioningConfig;
import io.helixiam.authorization.domain.provisioning.admin.DcrBindRequest;
import io.helixiam.authorization.domain.provisioning.admin.DcrRegistrationDto;
import io.helixiam.authorization.domain.provisioning.admin.DcrTokenCheck;
import io.helixiam.authorization.domain.provisioning.admin.ProvisioningConfigDto;
import io.helixiam.authorization.domain.provisioning.admin.ProvisioningConfigResult;
import io.helixiam.authorization.domain.provisioning.admin.ProvisioningConfigWriteDto;
import io.helixiam.authorization.domain.provisioning.admin.ScimTokenCheck;
import io.helixiam.authorization.repository.provisioning.DcrInitialAccessTokenRepository;
import io.helixiam.authorization.repository.provisioning.DcrRegistrationRepository;
import io.helixiam.authorization.repository.provisioning.RealmProvisioningConfigRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Helix IAM E11: the provisioning-domain store — per-realm SCIM bearer token + DCR policy, the DCR
 * registration→management-token bindings (RFC 7592) and the single-use initial access tokens (RFC 7591).
 * Tokens are persisted hashed; clear values are returned to the caller exactly once on generation.
 */
@Service
public class ProvisioningAdminService {

    private final RealmProvisioningConfigRepository configs;
    private final DcrRegistrationRepository registrations;
    private final DcrInitialAccessTokenRepository initialTokens;

    public ProvisioningAdminService(final RealmProvisioningConfigRepository configs,
                                    final DcrRegistrationRepository registrations,
                                    final DcrInitialAccessTokenRepository initialTokens) {
        this.configs = configs;
        this.registrations = registrations;
        this.initialTokens = initialTokens;
    }

    /** The realm's provisioning config (defaults when no row exists). */
    public ProvisioningConfigDto getConfig(final String realmId) {
        return toDto(configs.findById(realmId).orElseGet(() -> RealmProvisioningConfig.defaults(realmId)));
    }

    /** Upsert the DCR policy and optionally rotate / clear the SCIM token. */
    @Transactional
    public ProvisioningConfigResult saveConfig(final ProvisioningConfigWriteDto write) {
        final RealmProvisioningConfig config = configs.findById(write.realmId())
                .orElseGet(() -> RealmProvisioningConfig.defaults(write.realmId()));
        if (write.dcrOpen() != null) {
            config.setDcrOpen(write.dcrOpen());
        }
        String newToken = null;
        if (write.clearScimToken()) {
            config.setScimTokenHash(null);
        } else if (write.rotateScimToken()) {
            newToken = ProvisioningTokens.generate();
            config.setScimTokenHash(ProvisioningTokens.hash(newToken));
        }
        return new ProvisioningConfigResult(toDto(configs.save(config)), newToken);
    }

    /** {@code true} when the presented SCIM bearer token matches the realm's stored token. */
    public boolean verifyScimToken(final ScimTokenCheck check) {
        return configs.findById(check.realmId())
                .map(RealmProvisioningConfig::getScimTokenHash)
                .map(hash -> ProvisioningTokens.matches(check.token(), hash))
                .orElse(false);
    }

    /** {@code true} when the realm permits open (un-gated) Dynamic Client Registration. */
    public boolean isDcrOpen(final String realmId) {
        return configs.findById(realmId).map(RealmProvisioningConfig::isDcrOpen)
                .orElse(RealmProvisioningConfig.DEFAULT_DCR_OPEN);
    }

    /** Mint an initial access token for the realm (RFC 7591 §1.2); returned once, stored hashed. */
    @Transactional
    public String issueInitialAccessToken(final String realmId) {
        final String token = ProvisioningTokens.generate();
        initialTokens.save(new DcrInitialAccessToken(realmId, ProvisioningTokens.hash(token)));
        return token;
    }

    /** Validate + consume (single-use) an initial access token; {@code true} when it was valid. */
    @Transactional
    public boolean consumeInitialAccessToken(final String realmId, final String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        return initialTokens.findByRealmIdAndTokenHash(realmId, ProvisioningTokens.hash(token))
                .map(found -> {
                    initialTokens.delete(found);
                    return true;
                })
                .orElse(false);
    }

    /** Bind a freshly-created OAuth client to a new registration_access_token (returned once). */
    @Transactional
    public DcrRegistrationDto bind(final DcrBindRequest request) {
        final String token = ProvisioningTokens.generate();
        final DcrRegistration registration = new DcrRegistration(request.realmId(), request.clientInternalId(),
                request.clientId(), ProvisioningTokens.hash(token));
        final DcrRegistration saved = registrations.save(registration);
        return new DcrRegistrationDto(saved.getRegistrationId(), saved.getRealmId(), saved.getClientInternalId(),
                saved.getClientId(), token);
    }

    /** {@code true} when the registration_access_token matches the client's binding (RFC 7592 auth). */
    public boolean verifyRegistrationToken(final DcrTokenCheck check) {
        return registrations.findByRealmIdAndClientInternalId(check.realmId(), check.clientInternalId())
                .map(DcrRegistration::getRegistrationTokenHash)
                .map(hash -> ProvisioningTokens.matches(check.token(), hash))
                .orElse(false);
    }

    /** Forget a client's registration binding (called when the client is deleted via RFC 7592). */
    @Transactional
    public void unbind(final String realmId, final String clientInternalId) {
        registrations.findByRealmIdAndClientInternalId(realmId, clientInternalId).ifPresent(registrations::delete);
    }

    private static ProvisioningConfigDto toDto(final RealmProvisioningConfig config) {
        return new ProvisioningConfigDto(config.getRealmId(), config.getScimTokenHash() != null, config.isDcrOpen());
    }
}
