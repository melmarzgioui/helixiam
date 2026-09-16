package io.helixiam.authorization.repository.messaging;

import io.helixiam.authorization.domain.messaging.MessagingProvider;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/** Persistence for {@link MessagingProvider}, keyed by realm + channel + driver. */
@Repository
public interface MessagingProviderRepository extends JpaRepository<MessagingProvider, String> {

    List<MessagingProvider> findByRealmId(String realmId);

    List<MessagingProvider> findByRealmIdAndChannel(String realmId, String channel);

    Optional<MessagingProvider> findByRealmIdAndChannelAndDriver(String realmId, String channel, String driver);
}
