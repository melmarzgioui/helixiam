package group.mfnr.authorization.repository.scim;

import group.mfnr.authorization.domain.scim.ScimTarget;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/** Helix IAM B7: persistence for per-realm outbound SCIM provisioning targets. */
@Repository
public interface ScimTargetRepository extends JpaRepository<ScimTarget, String> {

    List<ScimTarget> findAllByRealmIdOrderByCreationDateAsc(String realmId);

    List<ScimTarget> findAllByRealmIdAndEnabledTrue(String realmId);
}
