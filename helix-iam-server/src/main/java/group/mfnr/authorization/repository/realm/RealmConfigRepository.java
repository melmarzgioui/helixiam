package group.mfnr.authorization.repository.realm;

import group.mfnr.authorization.domain.realm.RealmConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/** Persistence for {@link RealmConfig} (keyed by realm id == tenant id). */
@Repository
public interface RealmConfigRepository extends JpaRepository<RealmConfig, String> {
}
