package group.mfnr.authorization.repository.device;

import group.mfnr.authorization.domain.device.DeviceCredentialEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/** Persistence for enrolled device-factor signing credentials ({@link DeviceCredentialEntity}). */
@Repository
public interface DeviceCredentialRepository extends JpaRepository<DeviceCredentialEntity, String> {

    List<DeviceCredentialEntity> findAllByUserId(String userId);
}
