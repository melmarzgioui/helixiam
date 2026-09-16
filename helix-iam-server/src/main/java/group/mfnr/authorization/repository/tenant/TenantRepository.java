package group.mfnr.authorization.repository.tenant;

import group.mfnr.authorization.domain.tenant.Tenant;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TenantRepository extends JpaRepository<Tenant, String> {

}