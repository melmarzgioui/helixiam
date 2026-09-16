/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.repository.webhook;

import io.helixiam.authorization.domain.webhook.WebhookSubscription;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/** Helix IAM B6: persistence for per-realm outbound webhook subscriptions. */
@Repository
public interface WebhookSubscriptionRepository extends JpaRepository<WebhookSubscription, String> {

    List<WebhookSubscription> findAllByRealmIdOrderByCreationDateAsc(String realmId);

    List<WebhookSubscription> findAllByRealmIdAndEnabledTrue(String realmId);
}
