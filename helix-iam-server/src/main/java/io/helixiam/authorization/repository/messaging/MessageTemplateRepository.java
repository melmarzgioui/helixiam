/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.messaging;

import io.helixiam.authorization.domain.messaging.MessageTemplate;
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
