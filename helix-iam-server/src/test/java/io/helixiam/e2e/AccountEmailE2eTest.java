/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Review rc.3 #4: an email address already in use is a 409 (it was a 500 exposing the DB constraint); changing an
 * email clears its verified flag; tokens say whether the email is verified ({@code email_verified}).
 */
class AccountEmailE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Acc0unt-Email-Passw0rd!";

    @Test
    void duplicateEmailIs409_changingItClearsVerification_andTokensCarryEmailVerified() {
        final String realm = E2eSeed.unique("mail");
        seed().realm(realm);
        final E2eSeed.SeededUser joe = seed().user(realm, E2eSeed.unique("joe"), PASSWORD);
        final E2eSeed.SeededUser maya = seed().user(realm, E2eSeed.unique("maya"), PASSWORD);
        final JdbcTemplate jdbc = context.getBean(JdbcTemplate.class);
        // The pool runs with auto-commit off, so commit explicitly.
        new org.springframework.transaction.support.TransactionTemplate(
                context.getBean(org.springframework.transaction.PlatformTransactionManager.class))
                .executeWithoutResult(tx -> jdbc.update("UPDATE user_credentials SET email_verified = true WHERE user_id = ?", maya.userId()));
        final E2eSeed.SeededClient web = seed().confidentialClient(realm, "web", List.of("openid", "email"));

        final OidcFlow oidc = oidc(realm);
        final OidcFlow.Tokens before = oidc.authorizationCode("web", web.secret(), web.redirectUri(), maya.username(),
                PASSWORD, "openid email");
        assertThat(oidc.verify(before.idToken()).getClaim("email_verified")).isEqualTo(Boolean.TRUE);

        final E2eAdminSession session = E2eAdminSession.login(newBrowser(), realm, maya.username(), PASSWORD);
        final E2eHttp.Response taken = session.put("/realms/" + realm + "/account/profile", Map.of("email", joe.dto().email()));
        assertThat(taken.status()).as(taken.toString()).isEqualTo(409);
        assertThat(taken.body()).doesNotContain("constraint").doesNotContain("duplicate key");

        final String fresh = E2eSeed.unique("maya") + "@new.example";
        assertThat(session.put("/realms/" + realm + "/account/profile", Map.of("email", fresh)).status()).isEqualTo(200);
        final OidcFlow.Tokens after = oidc.authorizationCode("web", web.secret(), web.redirectUri(), maya.username(),
                PASSWORD, "openid email");
        assertThat(oidc.verify(after.idToken()).getClaim("email")).isEqualTo(fresh);
        assertThat(oidc.verify(after.idToken()).getClaim("email_verified")).isEqualTo(Boolean.FALSE);
        assertThat(oidc.userinfo(after.accessToken()).json().path("email_verified").isBoolean()).isTrue();

        // Admin API: same 409 instead of a 500.
        final E2eHttp.Response adminTaken = adminSession(realm).put("/admin/realms/" + realm + "/users/" + joe.userId(),
                Map.of("username", joe.username(), "email", fresh, "enabled", true, "locked", false));
        assertThat(adminTaken.status()).as(adminTaken.toString()).isEqualTo(409);
    }
}
