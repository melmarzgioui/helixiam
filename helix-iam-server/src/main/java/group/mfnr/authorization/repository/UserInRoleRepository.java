package group.mfnr.authorization.repository;

import group.mfnr.authorization.domain.user.UserInRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserInRoleRepository extends JpaRepository<UserInRole, String> {
    Optional<UserInRole> findByRoleIdAndUserIdAndTenantUserId(final String roleId, final String userId, final String tenantUserId);

    Optional<UserInRole> findByRoleIdAndUserId(final String roleId, final String userId);

    List<UserInRole> findAllByRoleId(final String roleId);
}
