package group.mfnr.authorization.repository.provisioning;

import group.mfnr.authorization.domain.provisioning.RealmProvisioningConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/** Persistence for {@link RealmProvisioningConfig} (keyed by realm id). */
@Repository
public interface RealmProvisioningConfigRepository extends JpaRepository<RealmProvisioningConfig, String> {
}
