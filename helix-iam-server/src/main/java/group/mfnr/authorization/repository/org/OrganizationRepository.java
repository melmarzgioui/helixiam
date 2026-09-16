package group.mfnr.authorization.repository.org;

import group.mfnr.authorization.domain.org.Organization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Persistence for realm-scoped {@link Organization}s. */
@Repository
public interface OrganizationRepository extends JpaRepository<Organization, String> {

    List<Organization> findAllByTenantId(String tenantId);

    Optional<Organization> findByTenantIdAndName(String tenantId, String name);

    boolean existsByTenantIdAndName(String tenantId, String name);
}
