/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.audit;

import java.util.Arrays;
import java.util.List;

/**
 * Helix IAM E8.5-S4 (Events): pure mapping from an admin HTTP request
 * ({@code method}, {@code path}, response {@code status}) to a semantic audit descriptor. No I/O — the
 * whole behaviour is here so it can be unit-tested exhaustively. Paths are
 * {@code /admin/realms/{realm}/{resource}[/{id}[/{sub}/{subId}]]}; unmapped mutating routes fall back to
 * {@code ADMIN_<METHOD>} so coverage never silently regresses as new admin endpoints are added.
 */
public final class AuditEventMapper {

    private AuditEventMapper() {
    }

    /** Resolved admin audit descriptor. */
    public record AdminAudit(String realm, String type, String resourceType, String resourceId, String outcome) {
    }

    public static AdminAudit map(final String method, final String path, final int status) {
        final List<String> seg = Arrays.stream(path.split("/")).filter(s -> !s.isBlank()).toList();
        final String outcome = outcome(status);
        // Expect: admin / realms / {realm} / {resource} [...]
        if (seg.size() < 4 || !"admin".equals(seg.get(0)) || !"realms".equals(seg.get(1))) {
            return new AdminAudit(null, "ADMIN_" + method, seg.isEmpty() ? null : seg.get(seg.size() - 1), null, outcome);
        }
        final String realm = seg.get(2);
        final String resource = seg.get(3);
        final String id = seg.size() > 4 ? seg.get(4) : null;
        final String sub = seg.size() > 5 ? seg.get(5) : null;
        // Structured theming: /theme/assets[/{id}] — uploaded fonts and images (the detail carries their metadata).
        if ("theme".equals(resource) && "assets".equals(id)) {
            final String assetType = "POST".equals(method) ? "THEME_ASSET_UPLOAD"
                    : "DELETE".equals(method) ? "THEME_ASSET_DELETE" : "ADMIN_" + method;
            return new AdminAudit(realm, assetType, "theme-asset", sub, outcome);
        }
        final String type = type(method, resource, sub);
        final String resourceType = singular(resource);
        return new AdminAudit(realm, type != null ? type : "ADMIN_" + method, resourceType, id, outcome);
    }

    private static String type(final String method, final String resource, final String sub) {
        return switch (resource) {
            case "users" -> {
                if ("sessions".equals(sub) && "DELETE".equals(method)) {
                    yield "USER_SESSIONS_REVOKE"; // open issue E7: every session of the user
                }
                if ("password".equals(sub)) {
                    yield "PASSWORD_RESET";
                }
                if ("roles".equals(sub)) {
                    yield "PUT".equals(method) ? "ROLE_ASSIGN" : "ROLE_UNASSIGN";
                }
                yield crud(method, "USER");
            }
            case "roles" -> "POST".equals(method) ? "ROLE_CREATE" : "DELETE".equals(method) ? "ROLE_DELETE" : null;
            case "clients" -> "secret".equals(sub) ? "CLIENT_SECRET_ROTATE" : crud(method, "CLIENT");
            case "settings" -> "PUT".equals(method) ? "REALM_UPDATE" : null;
            case "theme" -> "PUT".equals(method) ? "THEME_UPDATE" : null;
            case "organizations" -> {
                if ("members".equals(sub)) {
                    // Open issue E5: PUT adds a member or changes its role in place (the detail says which).
                    yield "PUT".equals(method) ? "ORGANIZATION_MEMBER_PUT"
                            : "DELETE".equals(method) ? "ORGANIZATION_MEMBER_REMOVE" : null;
                }
                yield ("theme".equals(sub) || "branding".equals(sub)) && "PUT".equals(method)
                        ? "ORGANIZATION_THEME_UPDATE" : null;
            }
            case "sessions" -> "DELETE".equals(method) ? "SESSION_REVOKE" : null;
            case "flow" -> "PUT".equals(method) ? "FLOW_UPDATE" : null;
            case "groups" -> {
                if ("members".equals(sub)) {
                    yield "PUT".equals(method) ? "GROUP_MEMBER_ADD" : "GROUP_MEMBER_REMOVE";
                }
                if ("roles".equals(sub)) {
                    yield "PUT".equals(method) ? "GROUP_ROLE_ASSIGN" : "GROUP_ROLE_UNASSIGN";
                }
                yield crud(method, "GROUP");
            }
            default -> null;
        };
    }

    private static String crud(final String method, final String resource) {
        return switch (method) {
            case "POST" -> resource + "_CREATE";
            case "PUT", "PATCH" -> resource + "_UPDATE";
            case "DELETE" -> resource + "_DELETE";
            default -> null;
        };
    }

    private static String singular(final String resource) {
        if (resource == null) {
            return null;
        }
        return switch (resource) {
            case "users" -> "user";
            case "roles" -> "role";
            case "clients" -> "client";
            case "groups" -> "group";
            case "sessions" -> "session";
            case "settings" -> "realm";
            case "flow" -> "flow";
            default -> resource;
        };
    }

    private static String outcome(final int status) {
        if (status < 400) {
            return "SUCCESS";
        }
        return status < 500 ? "DENIED" : "FAILURE";
    }
}
