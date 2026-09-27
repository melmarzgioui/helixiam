/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import io.helixiam.authorization.amqp.client.ClientAdminPublisher;
import io.helixiam.authorization.amqp.client.ClientDto;
import io.helixiam.authorization.amqp.client.ClientWriteDto;
import io.helixiam.e2e.E2eAdminSession;
import io.helixiam.e2e.E2eHttp;
import io.helixiam.e2e.E2eSeed;
import org.springframework.context.ApplicationContext;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The spec's "Reference setup" (what Monthfold runs), seeded into a fresh, uniquely named realm:
 * <ul>
 *   <li>realm: {@code requireMfa} with skip grace 0 (or MFA off, see {@link Options}), access token 300 s,
 *       self-registration on, an HTTP email provider that posts to the {@link MailSink};</li>
 *   <li>confidential client {@code web}: authorization code + refresh token, {@code client_secret_basic}, PKCE
 *       (the RP always sends S256), redirect / post-logout / back-channel logout URIs on the
 *       {@link TestRelyingParty}'s origin, scopes {@code openid profile email}, no consent;</li>
 *   <li>service account {@code monthfold-identity} (client credentials), whose only realm role grants just the
 *       {@code view-users} and {@code manage-users} admin permissions.</li>
 * </ul>
 * Realm settings go through the master admin's admin API (the same calls a provisioner makes); clients through
 * the admin service beans ({@link E2eSeed}'s approach) so the one-time secrets come back.
 */
public final class ReferenceSetup {

    public static final String WEB = "web";
    public static final String IDENTITY_SERVICE = "monthfold-identity";
    public static final String IDENTITY_ROLE = "identity-service";
    public static final String SCOPE = "openid profile email";

    private ReferenceSetup() {
    }

    /** Knobs for variants of the reference realm. */
    public record Options(boolean requireMfa, String displayName) {

        /** Exactly the reference setup. */
        public static Options reference() {
            return new Options(true, "Monthfold");
        }

        /** Same realm without the two-step requirement (password-only sign-in). */
        public static Options withoutMfa() {
            return new Options(false, "Monthfold");
        }
    }

    /** The seeded realm, ready to drive from a browser. */
    public record Realm(String realm, String displayName, TestRelyingParty.Client web, E2eSeed.SeededClient webClient,
                        E2eSeed.SeededClient identityService, MailSink mail) {

        /** {@code /realms/{realm}}. */
        public String path() {
            return "/realms/" + realm;
        }
    }

    static Realm seed(final ApplicationContext context, final E2eSeed seed, final E2eAdminSession master,
                      final TestRelyingParty rp, final MailSink mail, final Options options) {
        final String realm = E2eSeed.unique("monthfold");
        seed.realm(realm, options.displayName());
        final String admin = "/admin/realms/" + realm;

        final Map<String, Object> settings = new LinkedHashMap<>();
        settings.put("displayName", options.displayName());
        settings.put("accessTokenTtlSeconds", 300);
        settings.put("refreshTokenTtlSeconds", 86400);
        settings.put("enabled", true);
        settings.put("passwordMinLength", 12);
        settings.put("requireMfa", options.requireMfa());
        settings.put("registrationEnabled", true);
        expect(master.put(admin + "/settings", settings), 200, "realm settings");
        expect(master.put(admin + "/settings/mfa", Map.of("requireMfa", options.requireMfa(), "skipGraceDays", 0)),
                200, "MFA policy");

        final Map<String, Object> provider = new LinkedHashMap<>();
        provider.put("channel", "EMAIL");
        provider.put("driver", "HTTP");
        provider.put("enabled", true);
        provider.put("fromAddress", "no-reply@monthfold.test");
        provider.put("fromName", options.displayName());
        provider.put("config", Map.of("url", mail.url()));
        provider.put("secret", "mail-sink-token");
        expect(master.put(admin + "/messaging/providers", provider), 200, "HTTP email provider");

        final ClientDto web = context.getBean(ClientAdminPublisher.class).create(new ClientWriteDto(realm, null, WEB,
                List.of("authorization_code", "refresh_token"), List.of(rp.callbackUri()), List.of("openid", "profile", "email"),
                null, null, "Monthfold web", "Reference-setup web client (test RP)", List.of(rp.postLogoutUri()),
                List.of(rp.origin()), false, false, true, null, null, null, null, false,
                null, null, null, false, "client_secret_basic", null,
                rp.backchannelLogoutUri(), null, null, false, false, null));
        if (web == null || web.secret() == null) {
            throw new AssertionError("Creating the web client returned no secret");
        }
        final E2eSeed.SeededClient webClient = new E2eSeed.SeededClient(realm, web.id(), WEB, web.secret(),
                rp.callbackUri(), web);

        final E2eSeed.SeededClient identity = seed.serviceAccountClient(realm, IDENTITY_SERVICE, List.of("openid"));
        final E2eHttp.Response role = master.post(admin + "/roles", Map.of("name", IDENTITY_ROLE));
        expect(role, 201, "identity-service role");
        expect(master.put(admin + "/admin-roles/" + role.json().path("roleId").asText(),
                Map.of("permissions", List.of("view-users", "manage-users"))), 200, "role admin permissions");
        expect(master.post(admin + "/clients/" + IDENTITY_SERVICE + "/service-account/roles",
                Map.of("roleName", IDENTITY_ROLE, "roleType", "REALM")), 201, "service-account role");

        final TestRelyingParty.Client rpClient = rp.register(realm, WEB, web.secret(), SCOPE);
        return new Realm(realm, options.displayName(), rpClient, webClient, identity, mail);
    }

    private static void expect(final E2eHttp.Response r, final int status, final String what) {
        if (r.status() != status) {
            throw new AssertionError("Reference setup: " + what + " expected HTTP " + status + ", got " + r);
        }
    }
}
