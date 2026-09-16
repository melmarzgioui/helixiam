package io.helixiam.authorization.domain.adminrbac;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/** Helix IAM: persistence for admin-role → admin-permission grants ({@link AdminRolePermissionEntity}). */
@Repository
public interface AdminRolePermissionRepository extends JpaRepository<AdminRolePermissionEntity, String> {

    List<AdminRolePermissionEntity> findAllByRealmId(String realmId);

    List<AdminRolePermissionEntity> findAllByRealmIdAndRoleId(String realmId, String roleId);

    /** All grants whose role is one of {@code roleIds} in the realm — used to resolve a principal's permissions. */
    List<AdminRolePermissionEntity> findAllByRealmIdAndRoleIdIn(String realmId, List<String> roleIds);

    void deleteByRealmIdAndRoleId(String realmId, String roleId);

    long countByRealmId(String realmId);
}
