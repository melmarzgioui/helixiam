package io.helixiam.authorization.repository.saml;

import io.helixiam.authorization.domain.saml.SamlRelyingPartyEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Helix IAM: persistence for per-realm SAML2 relying parties (service providers).
 */
@Repository
public interface SamlRelyingPartyRepository extends JpaRepository<SamlRelyingPartyEntity, String> {

    List<SamlRelyingPartyEntity> findAllByRealmId(String realmId);

    /** Helix IAM (Application model): the SAML relying parties linked to an Application, for cascade-delete. */
    List<SamlRelyingPartyEntity> findAllByApplicationId(String applicationId);

    Optional<SamlRelyingPartyEntity> findByRealmIdAndEntityId(String realmId, String entityId);

    boolean existsByRealmIdAndEntityId(String realmId, String entityId);

    void deleteByRealmIdAndEntityId(String realmId, String entityId);
}
