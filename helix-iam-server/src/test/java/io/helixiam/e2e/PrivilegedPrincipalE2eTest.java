/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Security review H5 (present in rc.11, found by live probes): <b>you cannot act on an admin more privileged than
 * you.</b> A {@code view-clients} admin could read an admin service account's secret; {@code manage-clients} could set
 * it; {@code manage-users} could impersonate a realm admin or reset their password. Each action is refused (403) for
 * a lower-privileged admin and still works for a realm admin — and for ordinary targets (no over-blocking).
 */
class PrivilegedPrincipalE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Privileged-Passw0rd!";

    private String realm;
    private E2eAdminSession admin;
    private String adminRoleId;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("priv");
        seed().realm(realm);
        admin = adminSession();
        for (final JsonNode r : admin.get(base() + "/roles").json()) {
            if ("admin".equals(r.path("name").asText())) {
                adminRoleId = r.path("roleId").asText();
            }
        }
    }

    // ------------------------------------------------------------------------------------------------ clients

    @Test
    void adminServiceAccountClients_areOffLimitsBelowRealmAdmin() {
        final E2eSeed.SeededClient sa = adminServiceAccount();
        final E2eSeed.SeededClient plain = seed().serviceAccountClient(realm, E2eSeed.unique("plain"), List.of("openid"));

        // Reveal: view-clients is not enough any more; manage-clients is refused for an admin service account.
        assertThat(scoped("view-clients").session().get(base() + "/clients/" + sa.id() + "/secret").status())
                .isEqualTo(403);
        final Scoped mc = scoped("manage-clients");
        assertThat(mc.session().get(base() + "/clients/" + sa.id() + "/secret").status()).isEqualTo(403);
        assertThat(mc.session().post(base() + "/clients/" + sa.id() + "/secret",
                Map.of("secret", "Attacker-chosen-secret-0123456789-abcdef")).status()).isEqualTo(403);
        assertThat(mc.session().post(base() + "/clients/" + sa.id() + "/secret", Map.of()).status()).isEqualTo(403);
        assertThat(mc.session().put(base() + "/clients/" + sa.id(), clientBody(sa, "http://evil.example/cb")).status())
                .isEqualTo(403);
        assertThat(mc.session().delete(base() + "/clients/" + sa.id()).status()).isEqualTo(403);
        // The service account still signs in with its own secret.
        oidc(realm).clientCredentials(sa.clientId(), sa.secret(), "openid");

        // Ordinary clients: manage-clients keeps working.
        assertThat(mc.session().get(base() + "/clients/" + plain.id() + "/secret").status()).isEqualTo(200);
        assertThat(mc.session().post(base() + "/clients/" + plain.id() + "/secret", Map.of()).status()).isEqualTo(200);
        assertThat(mc.session().put(base() + "/clients/" + plain.id(), clientBody(plain, "http://localhost/cb2"))
                .status()).isEqualTo(200);
        assertThat(mc.session().delete(base() + "/clients/" + plain.id()).status()).isEqualTo(204);

        // A realm admin may do all of it.
        assertThat(admin.get(base() + "/clients/" + sa.id() + "/secret").status()).isEqualTo(200);
        assertThat(admin.post(base() + "/clients/" + sa.id() + "/secret", Map.of()).status()).isEqualTo(200);
    }

    @Test
    void clientRoleWithoutItsClient_isRejected_neverRealmScoped() {
        final E2eSeed.SeededClient sa = seed().serviceAccountClient(realm, E2eSeed.unique("svc"), List.of("openid"));
        final E2eHttp.Response r = scoped("manage-clients").session().post(base() + "/clients/" + sa.clientId()
                + "/service-account/roles", Map.of("roleName", "admin", "roleType", "CLIENT"));
        assertThat(r.status()).as(r.toString()).isEqualTo(400);
        assertThat(admin.post(base() + "/clients/" + sa.clientId() + "/service-account/roles",
                Map.of("roleName", "admin", "roleType", "CLIENT")).status()).isEqualTo(400);
        final String token = oidc(realm).clientCredentials(sa.clientId(), sa.secret(), "openid").accessToken();
        assertThat(newBrowser().get(base() + "/admin-roles", "Authorization", "Bearer " + token, "Accept",
                "application/json").status()).isIn(401, 403);
    }

    // ------------------------------------------------------------------------------------------------ users

    @Test
    void manageUsers_cannotTakeOverARealmAdmin_butManagesOrdinaryUsers() {
        final E2eSeed.SeededUser victim = seed().user(realm, E2eSeed.unique("radmin"), PASSWORD);
        assertThat(admin.post(base() + "/users/" + victim.userId() + "/roles", Map.of("roleId", adminRoleId)).status())
                .isEqualTo(204);
        final Scoped mu = scoped("manage-users");
        final String u = base() + "/users/" + victim.userId();

        assertThat(mu.session().post(u + "/impersonate", Map.of()).status()).isEqualTo(403);
        assertThat(mu.session().put(u + "/password", Map.of("newPassword", "Taken-Over-Passw0rd!x")).status())
                .isEqualTo(403);
        assertThat(mu.session().put(u, userBody(victim, "attacker@evil.example", true)).status()).isEqualTo(403);
        assertThat(mu.session().put(u, userBody(victim, null, false)).status()).isEqualTo(403);
        assertThat(mu.session().put(u + "/required-actions", Map.of("requiredActions", "UPDATE_PASSWORD")).status())
                .isEqualTo(403);
        assertThat(mu.session().delete(u + "/credentials/totp/any").status()).isEqualTo(403);
        assertThat(mu.session().delete(u + "/gdpr").status()).isEqualTo(403);
        assertThat(mu.session().delete(u).status()).isEqualTo(403);
        // Revoking sessions stays allowed: it is not an escalation.
        assertThat(mu.session().delete(u + "/sessions").status()).isNotEqualTo(403);
        // The victim still signs in with the old password.
        E2eAdminSession.login(newBrowser(), realm, victim.username(), PASSWORD);

        // Ordinary users: manage-users keeps working (no over-blocking).
        final E2eSeed.SeededUser plain = seed().user(realm, E2eSeed.unique("plain"), PASSWORD);
        final String p = base() + "/users/" + plain.userId();
        assertThat(mu.session().put(p + "/password", Map.of("newPassword", "Fresh-Passw0rd-1234!")).status())
                .isIn(200, 204);
        assertThat(mu.session().put(p, userBody(plain, "plain@ok.example", true)).status()).isEqualTo(200);
        assertThat(mu.session().put(p + "/required-actions", Map.of("requiredActions", "UPDATE_PASSWORD")).status())
                .isIn(200, 204);
        assertThat(mu.session().delete(p).status()).isEqualTo(204);

        // A realm admin may act on the realm admin.
        final E2eSeed.SeededUser ra = seed().user(realm, E2eSeed.unique("ra"), PASSWORD);
        assertThat(admin.post(base() + "/users/" + ra.userId() + "/roles", Map.of("roleId", adminRoleId)).status())
                .isEqualTo(204);
        final E2eAdminSession realmAdmin = E2eAdminSession.login(newBrowser(), realm, ra.username(), PASSWORD);
        assertThat(realmAdmin.put(u + "/password", Map.of("newPassword", "Reset-By-Realm-Admin-1!")).status())
                .isIn(200, 204);
    }

    @Test
    void scim_cannotChangeOrDeleteAnAdmin() {
        final E2eSeed.SeededUser victim = seed().user(realm, E2eSeed.unique("scimadm"), PASSWORD);
        assertThat(admin.post(base() + "/users/" + victim.userId() + "/roles", Map.of("roleId", adminRoleId)).status())
                .isEqualTo(204);
        final String token = admin.put(base() + "/provisioning", Map.of("dcrOpen", false, "rotateScimToken", true,
                "clearScimToken", false)).json().path("newScimToken").asText();
        final E2eHttp.Response r = newBrowser().delete("/realms/" + realm + "/scim/v2/Users/" + victim.userId(),
                "Authorization", "Bearer " + token, "Accept", "application/scim+json");
        assertThat(r.status()).as(r.toString()).isEqualTo(403);
        E2eAdminSession.login(newBrowser(), realm, victim.username(), PASSWORD);
    }

    @Test
    void encodedPathVariants_ofGuardedActions_areStillRefused() {
        final E2eSeed.SeededUser victim = seed().user(realm, E2eSeed.unique("encadm"), PASSWORD);
        assertThat(admin.post(base() + "/users/" + victim.userId() + "/roles", Map.of("roleId", adminRoleId)).status())
                .isEqualTo(204);
        final E2eSeed.SeededClient sa = adminServiceAccount();
        final Scoped mu = scoped("manage-users");
        final Scoped mc = scoped("manage-clients");
        final String token = xsrf(mu.session());
        final String ctoken = xsrf(mc.session());
        final String u = baseUrl() + base() + "/users/" + victim.userId();
        for (final String[] t : new String[][] {{"PUT", u + "/p%61ssword"}, {"POST", u + "/impers%6Fnate"},
                {"PUT", u + "/required%2Dactions"}, {"DELETE", baseUrl() + base() + "/users/" + victim.userId() + "%20"},
                {"PUT", baseUrl() + base() + "/u%73ers/" + victim.userId() + "/password"}}) {
            final E2eHttp.Response r = mu.session().http().sendJson(t[0], t[1],
                    Map.of("newPassword", "Taken-Over-Passw0rd!x", "requiredActions", "UPDATE_PASSWORD"),
                    "X-XSRF-TOKEN", token, "Accept", "application/json");
            assertThat(r.status()).as(t[1] + " → " + r).isIn(400, 403, 404, 405);
        }
        final E2eHttp.Response secret = mc.session().http().get(baseUrl() + base() + "/clients/" + sa.id() + "/s%65cret",
                "Accept", "application/json");
        assertThat(secret.status()).as(secret.toString()).isIn(400, 403, 404);
        assertThat(secret.body()).doesNotContain(sa.secret());
        E2eAdminSession.login(newBrowser(), realm, victim.username(), PASSWORD);
    }

    @Test
    void withoutADeclaredActor_guardedActionsOnAdminsAreRefused_asSystemIsExplicit() {
        final E2eSeed.SeededUser victim = seed().user(realm, E2eSeed.unique("noactor"), PASSWORD);
        assertThat(admin.post(base() + "/users/" + victim.userId() + "/roles", Map.of("roleId", adminRoleId)).status())
                .isEqualTo(204);
        final io.helixiam.authorization.service.user.UserAdminService users =
                context.getBean(io.helixiam.authorization.service.user.UserAdminService.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> users.resetPassword(
                        new io.helixiam.authorization.domain.user.admin.UserPasswordDto(realm, victim.userId(),
                                "No-Actor-Passw0rd!1")))
                .isInstanceOf(io.helixiam.authorization.service.adminrbac.AdminGrantGuard.AdminGrantDeniedException.class);
        assertThat(io.helixiam.authorization.service.adminrbac.AdminActor.asSystem("test: explicit internal reset",
                () -> users.resetPassword(new io.helixiam.authorization.domain.user.admin.UserPasswordDto(realm,
                        victim.userId(), "System-Reset-Passw0rd!1")))).isTrue();
    }

    @Test
    void aMasterAdminReachableFromTheRealm_isProtected_andMasterAdminsStillManageRealmUsers() {
        // A master-realm admin who is also a member of this realm (as a tenant creator is).
        final E2eSeed.SeededUser boss = seed().user(MASTER, E2eSeed.unique("boss"), PASSWORD);
        String masterAdminRole = null;
        for (final JsonNode r : admin.get("/admin/realms/master/roles").json()) {
            if ("admin".equals(r.path("name").asText())) {
                masterAdminRole = r.path("roleId").asText();
            }
        }
        assertThat(admin.post("/admin/realms/master/users/" + boss.userId() + "/roles",
                Map.of("roleId", masterAdminRole)).status()).isEqualTo(204);
        final org.springframework.transaction.support.TransactionTemplate tx =
                new org.springframework.transaction.support.TransactionTemplate(
                        context.getBean(org.springframework.transaction.PlatformTransactionManager.class));
        tx.executeWithoutResult(t -> {
            final io.helixiam.authorization.domain.tenant.TenantUser link =
                    new io.helixiam.authorization.domain.tenant.TenantUser();
            link.setUserId(boss.userId());
            link.setTenantId(realm);
            context.getBean(io.helixiam.authorization.repository.tenant.TenantUserRepository.class).save(link);
        });
        final Scoped mu = scoped("manage-users");
        assertThat(mu.session().put(base() + "/users/" + boss.userId() + "/password",
                Map.of("newPassword", "Taken-Over-Passw0rd!x")).status()).isEqualTo(403);
        assertThat(mu.session().post(base() + "/users/" + boss.userId() + "/impersonate", Map.of()).status())
                .isEqualTo(403);
        // The master admin keeps managing this realm's users.
        final E2eSeed.SeededUser plain = seed().user(realm, E2eSeed.unique("plainm"), PASSWORD);
        assertThat(admin.put(base() + "/users/" + plain.userId() + "/password",
                Map.of("newPassword", "Master-Reset-Passw0rd!1")).status()).isIn(200, 204);
    }

    private static String xsrf(final E2eAdminSession session) {
        session.get("/admin/realms/master/settings");
        return session.http().cookieFor("XSRF-TOKEN", "/admin/realms/master/settings").orElseGet(() -> {
            throw new AssertionError("no XSRF cookie");
        });
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private String base() {
        return "/admin/realms/" + realm;
    }

    private E2eSeed.SeededClient adminServiceAccount() {
        final E2eSeed.SeededClient sa = seed().serviceAccountClient(realm, E2eSeed.unique("adminsvc"), List.of("openid"));
        assertThat(admin.post(base() + "/clients/" + sa.clientId() + "/service-account/roles",
                Map.of("roleName", "admin", "roleType", "REALM")).status()).isEqualTo(201);
        return sa;
    }

    private Map<String, Object> clientBody(final E2eSeed.SeededClient c, final String redirect) {
        final tools.jackson.databind.node.ObjectNode body =
                (tools.jackson.databind.node.ObjectNode) admin.get(base() + "/clients/" + c.id()).json();
        body.remove(List.of("realmId", "id", "secret"));
        body.putArray("redirectUris").add(redirect);
        final Map<String, Object> out = new LinkedHashMap<>();
        body.properties().forEach(e -> out.put(e.getKey(), e.getValue()));
        return out;
    }

    private static Map<String, Object> userBody(final E2eSeed.SeededUser u, final String email, final boolean enabled) {
        final Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", u.username());
        body.put("email", email);
        body.put("enabled", enabled);
        body.put("locked", false);
        return body;
    }

    private record Scoped(E2eAdminSession session, String userId) {
    }

    private Scoped scoped(final String permission) {
        final String roleName = E2eSeed.unique("pp-" + permission);
        String roleId = admin.post(base() + "/roles", Map.of("name", roleName)).json().path("roleId").asText();
        if (roleId.isBlank()) {
            for (final JsonNode r : admin.get(base() + "/roles").json()) {
                if (roleName.equals(r.path("name").asText())) {
                    roleId = r.path("roleId").asText();
                }
            }
        }
        assertThat(admin.put(base() + "/admin-roles/" + roleId, Map.of("permissions", List.of(permission))).status())
                .isEqualTo(200);
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("pp-u"), PASSWORD);
        assertThat(admin.post(base() + "/users/" + user.userId() + "/roles", Map.of("roleId", roleId)).status())
                .isEqualTo(204);
        return new Scoped(E2eAdminSession.login(newBrowser(), realm, user.username(), PASSWORD), user.userId());
    }
}
