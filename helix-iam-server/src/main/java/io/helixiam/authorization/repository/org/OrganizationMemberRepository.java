package io.helixiam.authorization.repository.org;

import io.helixiam.authorization.domain.org.OrganizationMember;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Persistence for organization membership ({@link OrganizationMember}). */
@Repository
public interface OrganizationMemberRepository extends JpaRepository<OrganizationMember, String> {

    List<OrganizationMember> findAllByOrgId(String orgId);

    List<OrganizationMember> findAllByUserId(String userId);

    Optional<OrganizationMember> findByOrgIdAndUserId(String orgId, String userId);

    long countByOrgId(String orgId);
}
