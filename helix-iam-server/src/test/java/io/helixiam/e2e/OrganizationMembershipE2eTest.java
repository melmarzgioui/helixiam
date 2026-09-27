/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Open issue E5: {@code PUT /admin/realms/{r}/organizations/{org}/members/{user}} changes a member's role in place
 * (no delete and re-add), answers 201 when it adds a member and 200 with the membership when it changes one, and
 * 404 (never 409) for an organization or user that is not in the path realm.
 */
class OrganizationMembershipE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Member-Passw0rd!";

    private String realm;
    private E2eAdminSession admin;
    private String orgId;
    private E2eSeed.SeededUser joe;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("members");
        seed().realm(realm);
        admin = adminSession(realm);
        orgId = admin.post("/admin/realms/" + realm + "/organizations", Map.of("name", E2eSeed.unique("harbor")))
                .json().path("orgId").asText();
        joe = seed().user(realm, E2eSeed.unique("joe"), PASSWORD);
    }

    private String memberPath(final String org, final String userId) {
        return "/admin/realms/" + realm + "/organizations/" + org + "/members/" + userId;
    }

    private JsonNode members() {
        final E2eHttp.Response r = admin.get("/admin/realms/" + realm + "/organizations/" + orgId + "/members");
        assertThat(r.status()).as(r.toString()).isEqualTo(200);
        return r.json();
    }

    @Test
    void putChangesTheRoleInPlace() {
        final E2eHttp.Response added = admin.put(memberPath(orgId, joe.userId()), Map.of("role", "owner"));
        assertThat(added.status()).as(added.toString()).isEqualTo(201);
        assertThat(added.json().path("role").asText()).isEqualTo("owner");
        assertThat(added.json().path("userId").asText()).isEqualTo(joe.userId());

        final E2eHttp.Response changed = admin.put(memberPath(orgId, joe.userId()), Map.of("role", "client"));
        assertThat(changed.status()).as(changed.toString()).isEqualTo(200);
        assertThat(changed.json().path("role").asText()).isEqualTo("client");
        assertThat(changed.json().path("username").asText()).isEqualTo(joe.username());

        final JsonNode list = members();
        assertThat(list).hasSize(1);
        assertThat(list.get(0).path("role").asText()).isEqualTo("client");

        // The same role again is a no-op, still 200.
        assertThat(admin.put(memberPath(orgId, joe.userId()), Map.of("role", "client")).status()).isEqualTo(200);
        // No body keeps the member's current role (it never silently resets it to the default).
        final E2eHttp.Response noBody = admin.put(memberPath(orgId, joe.userId()), Map.of());
        assertThat(noBody.status()).isEqualTo(200);
        assertThat(noBody.json().path("role").asText()).isEqualTo("client");

        // Delete and re-add still works.
        assertThat(admin.delete(memberPath(orgId, joe.userId())).status()).isEqualTo(204);
        assertThat(members()).isEmpty();
        final E2eHttp.Response readded = admin.put(memberPath(orgId, joe.userId()), Map.of());
        assertThat(readded.status()).isEqualTo(201);
        assertThat(readded.json().path("role").asText()).as("default role").isEqualTo("member");
    }

    @Test
    void anInvalidRoleIsA400() {
        final E2eHttp.Response r = admin.put(memberPath(orgId, joe.userId()), Map.of("role", "<script>"));
        assertThat(r.status()).as(r.toString()).isEqualTo(400);
        assertThat(r.json().path("fieldErrors").has("role")).isTrue();
        final E2eHttp.Response tooLong = admin.put(memberPath(orgId, joe.userId()), Map.of("role", "x".repeat(65)));
        assertThat(tooLong.status()).isEqualTo(400);
        assertThat(members()).isEmpty();
    }

    @Test
    void anUnknownOrganizationOrUser_orOneOfAnotherRealm_isA404_notA409() {
        assertThat(admin.put(memberPath("no-such-org", joe.userId()), Map.of("role", "owner")).status()).isEqualTo(404);
        assertThat(admin.put(memberPath(orgId, "no-such-user"), Map.of("role", "owner")).status()).isEqualTo(404);

        final String other = E2eSeed.unique("other");
        seed().realm(other);
        final E2eSeed.SeededUser stranger = seed().user(other, E2eSeed.unique("tina"), PASSWORD);
        assertThat(admin.put(memberPath(orgId, stranger.userId()), Map.of("role", "owner")).status())
                .as("a user of another realm").isEqualTo(404);
        final String foreignOrg = adminSession(other).post("/admin/realms/" + other + "/organizations",
                Map.of("name", E2eSeed.unique("foreign"))).json().path("orgId").asText();
        assertThat(admin.put(memberPath(foreignOrg, joe.userId()), Map.of("role", "owner")).status())
                .as("another realm's organization").isEqualTo(404);
        assertThat(members()).isEmpty();
    }
}
