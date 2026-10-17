/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import io.helixiam.authorization.domain.tenant.TenantUser;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import jakarta.persistence.EntityManagerFactory;
import org.junit.jupiter.api.Test;
import org.springframework.orm.jpa.EntityManagerFactoryUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Regression (round 6): a user with memberships in two realms has two {@code tenant_user} rows. Their profile
 * attributes used to be mapped on each as one element collection keyed by {@code user_id}, so both entities shared a
 * collection and any flush of a session that loaded both failed ("Found shared references to a collection").
 */
class TenantUserMappingE2eTest extends AbstractE2eTest {

    @Test
    void aSessionHoldingTwoMembershipsOfOneUserFlushes() {
        final String realmA = E2eSeed.unique("tua");
        final String realmB = E2eSeed.unique("tub");
        seed().realm(realmA);
        seed().realm(realmB);
        final E2eSeed.SeededUser user = seed().user(realmA, E2eSeed.unique("both"), "Two-Realms-Passw0rd!");
        final TenantUserRepository memberships = context.getBean(TenantUserRepository.class);
        final TransactionTemplate tx = new TransactionTemplate(context.getBean(PlatformTransactionManager.class));
        tx.executeWithoutResult(t -> {
            final TenantUser second = new TenantUser();
            second.setUserId(user.userId());
            second.setTenantId(realmB);
            memberships.save(second);
        });

        assertThatCode(() -> tx.executeWithoutResult(t -> {
            final List<TenantUser> both = memberships.findAllByUserId(user.userId());
            assertThat(both).hasSizeGreaterThanOrEqualTo(2);
            EntityManagerFactoryUtils.getTransactionalEntityManager(context.getBean(EntityManagerFactory.class)).flush();
        })).doesNotThrowAnyException();
    }
}
