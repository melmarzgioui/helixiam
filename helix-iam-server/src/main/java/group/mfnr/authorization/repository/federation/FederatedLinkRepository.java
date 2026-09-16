package group.mfnr.authorization.repository.federation;

import group.mfnr.authorization.domain.federation.FederatedLinkEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/** Persistence for federated-identity links ({@link FederatedLinkEntity}). */
@Repository
public interface FederatedLinkRepository extends JpaRepository<FederatedLinkEntity, String> {

    List<FederatedLinkEntity> findAllByUserId(String userId);
}
