package io.helixiam.authorization.repository.mfa;

import io.helixiam.authorization.domain.mfa.WebAuthnCredentialEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Persistence for WebAuthn/FIDO2 credentials ({@link WebAuthnCredentialEntity}). */
@Repository
public interface WebAuthnCredentialRepository extends JpaRepository<WebAuthnCredentialEntity, String> {

    Optional<WebAuthnCredentialEntity> findByCredentialId(String credentialId);

    List<WebAuthnCredentialEntity> findAllByUserId(String userId);
}
