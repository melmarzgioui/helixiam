package group.mfnr.authorization.repository.authzstore;

import group.mfnr.authorization.domain.authzstore.HelixAuthorizationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/** The findByToken index for the queue-backed authorization store (Q1). */
@Repository
public interface HelixAuthorizationTokenRepository extends JpaRepository<HelixAuthorizationToken, String> {

    void deleteByAuthorizationId(String authorizationId);
}
