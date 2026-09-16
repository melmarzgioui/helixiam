package io.helixiam.authorization.repository.group;

import io.helixiam.authorization.domain.group.UserGroup;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/** Persistence for realm-scoped {@link UserGroup}s. */
@Repository
public interface UserGroupRepository extends JpaRepository<UserGroup, String> {

    List<UserGroup> findAllByTenantId(String tenantId);

    List<UserGroup> findAllByParentId(String parentId);

    boolean existsByTenantIdAndParentIdAndName(String tenantId, String parentId, String name);
}
