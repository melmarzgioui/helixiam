package io.helixiam.authorization.service.device;

import io.helixiam.authorization.domain.device.DeviceCredentialEntity;
import io.helixiam.authorization.repository.device.DeviceCredentialRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.Date;

/**
 * Helix IAM E4.1: owns enrolled device-factor credentials. Enrollment verifies the platform
 * attestation (Apple App Attest / Android Key Attestation, or the dev "none" verifier) over the
 * server nonce before storing the device's P-256 public key. Login/step-up assertions are verified
 * by ES256 ({@link DeviceSignatureVerifier}) over the exact single-use server challenge — no shared
 * secret is stored, so this is phishing-resistant and bound to genuine device hardware.
 */
@Service
public class DeviceCredentialService {

    private static final Logger LOG = LogManager.getLogger(DeviceCredentialService.class);

    private final DeviceCredentialRepository repository;
    private final AttestationVerifierRegistry attestation;

    public DeviceCredentialService(final DeviceCredentialRepository repository,
                                   final AttestationVerifierRegistry attestation) {
        this.repository = repository;
        this.attestation = attestation;
    }

    /** Verifies the platform attestation and stores the device's signing credential. */
    @Transactional
    public boolean enroll(final String userId, final String deviceId, final byte[] publicKeySpki,
                          final String platform, final byte[] attestationStatement, final byte[] nonce,
                          final boolean biometric) {
        try {
            if (!attestation.verify(platform, attestationStatement, nonce, publicKeySpki)) {
                LOG.warn("Device enrollment attestation rejected for user {} device {} (platform {})",
                        userId, deviceId, platform);
                return false;
            }
            repository.save(new DeviceCredentialEntity(deviceId, userId,
                    Base64.getEncoder().encodeToString(publicKeySpki), platform, biometric));
            LOG.info("Enrolled device {} for user {} (platform {}, biometric {})",
                    deviceId, userId, platform, biometric);
            return true;
        } catch (final RuntimeException e) {
            LOG.warn("Device enrollment failed for user {} device {}: {}", userId, deviceId, e.getMessage());
            return false;
        }
    }

    /** Verifies an ES256 device assertion over the exact server challenge for the bound user. */
    @Transactional
    public boolean verifyAssertion(final String userId, final String deviceId, final byte[] challenge,
                                   final byte[] signature) {
        final DeviceCredentialEntity entity = repository.findById(deviceId).orElse(null);
        if (entity == null || !entity.getUserId().equals(userId)) {
            return false;
        }
        final byte[] spki = Base64.getDecoder().decode(entity.getPublicKey());
        if (!DeviceSignatureVerifier.verify(spki, challenge, signature)) {
            LOG.warn("Device assertion rejected for user {} device {}", userId, deviceId);
            return false;
        }
        entity.setLastUsedDate(new Date());
        repository.save(entity);
        return true;
    }
}
