package group.mfnr.authorization.repository.group;

import group.mfnr.authorization.domain.group.UserGroupRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Persistence for group→role mappings ({@link UserGroupRole}). */
@Repository
public interface UserGroupRoleRepository extends JpaRepository<UserGroupRole, String> {

    List<UserGroupRole> findAllByGroupId(String groupId);

    Optional<UserGroupRole> findByGroupIdAndRoleId(String groupId, String roleId);
}
