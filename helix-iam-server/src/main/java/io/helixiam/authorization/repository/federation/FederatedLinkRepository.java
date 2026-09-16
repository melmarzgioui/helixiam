package io.helixiam.authorization.repository.federation;

import io.helixiam.authorization.domain.federation.FederatedLinkEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/** Persistence for federated-identity links ({@link FederatedLinkEntity}). */
@Repository
public interface FederatedLinkRepository extends JpaRepository<FederatedLinkEntity, String> {

    List<FederatedLinkEntity> findAllByUserId(String userId);
}
