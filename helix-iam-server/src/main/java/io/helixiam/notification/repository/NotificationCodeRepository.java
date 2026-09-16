package io.helixiam.notification.repository;

import io.helixiam.notification.domain.NotificationCode;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface NotificationCodeRepository extends JpaRepository<NotificationCode, String> {
    Optional<NotificationCode> findByIdentifierAndType(final String identifier, final String type);
    Optional<NotificationCode> findByCodeAndType(final String code, final String type);
}
