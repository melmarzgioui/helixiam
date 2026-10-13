/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;

/** {@link TokenExchangeActorScenario} on the default (queue, PostgreSQL) token store. */
class TokenExchangeActorRefusedE2eTest extends AbstractE2eTest {

    @Test
    void anActorToken_isInvalidRequest_andNothingIsStored() {
        scenario().anActorToken_isInvalidRequest_andNothingIsStored();
    }

    @Test
    void anExchangeWithoutAnActor_stillWorks() {
        scenario().anExchangeWithoutAnActor_stillWorks();
    }

    private TokenExchangeActorScenario scenario() {
        final JdbcTemplate jdbc = new JdbcTemplate(context.getBean(DataSource.class));
        return new TokenExchangeActorScenario(seed(), this::oidc, () -> {
            final Long count = jdbc.queryForObject("select count(*) from helix_authorization", Long.class);
            return count == null ? 0 : count;
        });
    }
}
