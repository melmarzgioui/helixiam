package group.mfnr.authorization.repository.provisioning;

import group.mfnr.authorization.domain.provisioning.DcrRegistration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/** Persistence for {@link DcrRegistration} (RFC 7592 manage credential binding). */
@Repository
public interface DcrRegistrationRepository extends JpaRepository<DcrRegistration, String> {

    Optional<DcrRegistration> findByRealmIdAndClientInternalId(String realmId, String clientInternalId);
}
