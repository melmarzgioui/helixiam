package group.mfnr.authorization.repository.agent;

import group.mfnr.authorization.domain.agent.AgentIdentity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AgentIdentityRepository extends JpaRepository<AgentIdentity, String> {

    List<AgentIdentity> findAllByRealmIdOrderByCreatedAtAsc(String realmId);

    /** The realm-unique natural key — backs the duplicate-name guard on create. */
    Optional<AgentIdentity> findByRealmIdAndName(String realmId, String name);

    /** Resolve the agent bound to an OIDC client (by clientId) — backs token-issuance enrichment. */
    Optional<AgentIdentity> findFirstByRealmIdAndClientId(String realmId, String clientId);
}
