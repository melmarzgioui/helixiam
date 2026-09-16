package group.mfnr.authorization.repository.messaging;

import group.mfnr.authorization.domain.messaging.MessageTemplate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Persistence for {@link MessageTemplate}, keyed by realm + template key. */
@Repository
public interface MessageTemplateRepository extends JpaRepository<MessageTemplate, String> {

    List<MessageTemplate> findByRealmId(String realmId);

    Optional<MessageTemplate> findByRealmIdAndTemplateKey(String realmId, String templateKey);
}
