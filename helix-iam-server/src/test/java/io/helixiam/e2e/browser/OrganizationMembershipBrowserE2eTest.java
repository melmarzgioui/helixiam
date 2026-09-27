/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import io.helixiam.e2e.E2eAdminSession;
import io.helixiam.e2e.E2eHttp;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Item E4: an organization can REQUIRE membership when it is hinted ({@code organization=} on the authorization
 * request), not only brand the sign-in. A non-member who signs in is sent back to the app with
 * {@code error=access_denied}; a member completes; an organization that does not require membership only brands.
 */
class OrganizationMembershipBrowserE2eTest extends AbstractBrowserE2eTest {

    private static final String PASSWORD = "Org-Member-Passw0rd-2026!";

    @Test
    void aHintedOrganizationThatRequiresMembership_letsMembersIn_andSendsOthersBackWithAccessDenied() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eAdminSession admin = adminSession();
        final String org = createOrganization(admin, realm.realm(), E2eSeed.unique("harbor"), true);
        final E2eSeed.SeededUser member = seed().user(realm.realm(), E2eSeed.unique("ann"), PASSWORD);
        final E2eSeed.SeededUser outsider = seed().user(realm.realm(), E2eSeed.unique("joe"), PASSWORD);
        final E2eHttp.Response added = admin.put("/admin/realms/" + realm.realm() + "/organizations/" + org + "/members/"
                + member.userId(), Map.of("role", "member"));
        assertThat(added.status()).as(added.toString()).isLessThan(300);

        startSignInAtRp(realm.web(), Map.of("organization", org));
        signInWithPassword(outsider.username(), outsider.password());
        final TestRelyingParty.Callback denied = rpLastCallback().orElseThrow(() -> new AssertionError(describeBrowser()));
        assertThat(onRpOrigin()).as(describeBrowser()).isTrue();
        assertThat(denied.params()).containsEntry("error", "access_denied").containsKey("state")
                .doesNotContainKey("code");

        clearCookies();
        rp().reset();
        startSignInAtRp(realm.web(), Map.of("organization", org));
        signInWithPassword(member.username(), member.password());
        assertThat(assertLandedOnRpCallback().subject()).isEqualTo(member.userId());
    }

    @Test
    void anOrganizationThatDoesNotRequireMembership_onlyBrandsTheSignIn() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final String org = createOrganization(adminSession(), realm.realm(), E2eSeed.unique("open"), false);
        final E2eSeed.SeededUser outsider = seed().user(realm.realm(), E2eSeed.unique("joe"), PASSWORD);

        startSignInAtRp(realm.web(), Map.of("organization", org));
        signInWithPassword(outsider.username(), outsider.password());
        assertThat(assertLandedOnRpCallback().subject()).isEqualTo(outsider.userId());
    }

    @Test
    void requireMembership_isPartOfTheOrganizationApi() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eAdminSession admin = adminSession();
        final String name = E2eSeed.unique("api");
        final String org = createOrganization(admin, realm.realm(), name, true);
        final String path = "/admin/realms/" + realm.realm() + "/organizations/" + org;
        assertThat(admin.get(path).json().path("requireMembership").asBoolean()).isTrue();
        // Omitted on update = unchanged; false switches it off.
        assertThat(admin.put(path, Map.of("name", name)).json().path("requireMembership").asBoolean()).isTrue();
        assertThat(admin.put(path, Map.of("name", name, "requireMembership", false)).json().path("requireMembership")
                .asBoolean()).isFalse();
    }

    private static String createOrganization(final E2eAdminSession admin, final String realm, final String name,
                                              final boolean requireMembership) {
        final Map<String, Object> body = new LinkedHashMap<>();
        body.put("name", name);
        body.put("displayName", "Harbor & Pine");
        body.put("requireMembership", requireMembership);
        final E2eHttp.Response created = admin.post("/admin/realms/" + realm + "/organizations", body);
        assertThat(created.status()).as(created.toString()).isEqualTo(201);
        assertThat(created.json().path("requireMembership").asBoolean()).isEqualTo(requireMembership);
        return created.json().path("orgId").asText();
    }
}
