package group.mfnr.authorization.repository.authzstore;

import group.mfnr.authorization.domain.authzstore.HelixAuthorization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/** Persistence for the queue-backed OAuth2 authorization store (Q1). */
@Repository
public interface HelixAuthorizationRepository extends JpaRepository<HelixAuthorization, String> {
}
