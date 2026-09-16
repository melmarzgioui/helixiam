/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.group;

import io.helixiam.authorization.domain.group.UserGroupMember;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Persistence for group membership ({@link UserGroupMember}). */
@Repository
public interface UserGroupMemberRepository extends JpaRepository<UserGroupMember, String> {

    List<UserGroupMember> findAllByGroupId(String groupId);

    List<UserGroupMember> findAllByUserId(String userId);

    Optional<UserGroupMember> findByGroupIdAndUserId(String groupId, String userId);

    long countByGroupId(String groupId);
}
