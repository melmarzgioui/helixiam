/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.scim;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM B7: pure helpers for outbound SCIM 2.0 provisioning — builds the User resource (RFC 7643) and
 * the request URLs the {@link ScimProvisioningDispatcher} sends to a downstream service provider. The Helix
 * {@code userId} is carried as the SCIM {@code externalId}, the stable key used to locate an
 * already-provisioned resource for update/delete. Kept side-effect-free so it is fully unit-testable.
 */
public final class ScimProvisioningClient {

    private static final String USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";

    private ScimProvisioningClient() {
    }

    /** The SCIM core User resource for a local user (externalId = Helix userId, active = enabled flag). */
    public static Map<String, Object> userResource(final ScimUserView view) {
        final Map<String, Object> resource = new LinkedHashMap<>();
        resource.put("schemas", List.of(USER_SCHEMA));
        resource.put("userName", view.username());
        resource.put("externalId", view.userId());
        resource.put("active", view.active());
        if (notBlank(view.firstName()) || notBlank(view.lastName())) {
            final Map<String, Object> name = new LinkedHashMap<>();
            if (notBlank(view.firstName())) {
                name.put("givenName", view.firstName());
            }
            if (notBlank(view.lastName())) {
                name.put("familyName", view.lastName());
            }
            resource.put("name", name);
        }
        if (notBlank(view.email())) {
            final Map<String, Object> email = new LinkedHashMap<>();
            email.put("value", view.email());
            email.put("primary", true);
            final List<Map<String, Object>> emails = new ArrayList<>();
            emails.add(email);
            resource.put("emails", emails);
        }
        return resource;
    }

    /** The SCIM {@code /Users} collection URL for a service-provider base URL (trailing slash tolerated). */
    public static String usersUrl(final String baseUrl) {
        return trimSlash(baseUrl) + "/Users";
    }

    /** The {@code /Users?filter=externalId eq "<id>"} URL used to find an already-provisioned resource. */
    public static String externalIdFilterUrl(final String baseUrl, final String userId) {
        final String filter = URLEncoder.encode("externalId eq \"" + userId + "\"", StandardCharsets.UTF_8)
                .replace("+", "%20");
        return usersUrl(baseUrl) + "?filter=" + filter;
    }

    private static String trimSlash(final String url) {
        if (url == null) {
            return "";
        }
        String u = url.trim();
        while (u.endsWith("/")) {
            u = u.substring(0, u.length() - 1);
        }
        return u;
    }

    private static boolean notBlank(final String v) {
        return v != null && !v.isBlank();
    }
}
