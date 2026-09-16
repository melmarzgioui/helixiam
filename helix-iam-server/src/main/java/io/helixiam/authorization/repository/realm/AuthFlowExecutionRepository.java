package io.helixiam.authorization.repository.realm;

import io.helixiam.authorization.domain.realm.AuthFlowExecutionEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/** Persistence for the executions belonging to an {@link io.helixiam.authorization.domain.realm.AuthFlowEntity}. */
@Repository
public interface AuthFlowExecutionRepository extends JpaRepository<AuthFlowExecutionEntity, String> {

    List<AuthFlowExecutionEntity> findAllByFlowId(String flowId);

    /** Removes every execution of a flow — the editor replaces the whole set on save. */
    @Modifying
    @Transactional
    void deleteByFlowId(String flowId);
}
