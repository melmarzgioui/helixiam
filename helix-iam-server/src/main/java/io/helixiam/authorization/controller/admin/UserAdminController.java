/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.user.CredentialRevokeRef;
import io.helixiam.authorization.amqp.user.CredentialSummary;
import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.amqp.user.UserAdminRef;
import io.helixiam.authorization.amqp.user.UserPasswordDto;
import io.helixiam.authorization.amqp.user.UserRequiredActionsDto;
import io.helixiam.authorization.amqp.user.UserWriteDto;
import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.security.impersonation.ImpersonationService;
import io.helixiam.authorization.security.scim.ScimProvisioningDispatcher;
import io.helixiam.authorization.security.scim.ScimUserView;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Helix IAM E8.5: admin REST API for per-realm users — the backend behind the console's Users screen.
 * Users live in the global credential store and are bound to a realm via the tenant link; the realm
 * always comes from the path so a user can only be managed within its realm. Passwords are write-only
 * (Argon2id-encoded by the user domain) and never returned.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/users")
@Tag(name = "Users", description = "Per-realm user management (CRUD, password reset, enrolled credentials).")
public class UserAdminController {

    private final UserAdminPublisher publisher;
    private final ImpersonationService impersonationService;
    private final AuditLog auditLog;
    private final ScimProvisioningDispatcher scimDispatcher;

    public UserAdminController(final UserAdminPublisher publisher,
                               final ImpersonationService impersonationService, final AuditLog auditLog,
                               final ScimProvisioningDispatcher scimDispatcher) {
        this.publisher = publisher;
        this.impersonationService = impersonationService;
        this.auditLog = auditLog;
        this.scimDispatcher = scimDispatcher;
    }

    @GetMapping
    @Operation(summary = "List users", description = "All users in the realm.")
    public List<UserAdminDto> list(@PathVariable final String realmId) {
        return publisher.list(realmId);
    }

    @GetMapping("/{userId}")
    @Operation(summary = "Get a user", description = "Fetch one user by id; 404 if absent in the realm.")
    public ResponseEntity<UserAdminDto> get(@PathVariable final String realmId, @PathVariable final String userId) {
        final UserAdminDto user = publisher.get(new UserAdminRef(realmId, userId));
        return user == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(user);
    }

    /** B10: bulk-import users from a pasted/uploaded CSV or JSON array. Idempotent (existing usernames are skipped). */
    public record ImportRequest(String payload) {
    }

    /** Outcome of a bulk import: counts + per-row failures (so the console can show exactly what didn't load). */
    public record ImportResult(int created, int skipped, List<Map<String, String>> failed) {
    }

    @PostMapping("/import")
    @Operation(summary = "Bulk-import users", description = "Create users from a CSV or JSON array; existing usernames are skipped.")
    public ResponseEntity<ImportResult> importUsers(@PathVariable final String realmId,
                                                    @RequestBody final ImportRequest request) {
        final List<UserImportParser.Row> rows;
        try {
            rows = UserImportParser.parse(request == null ? null : request.payload());
        } catch (final IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(new ImportResult(0, 0,
                    List.of(Map.of("username", "", "error", e.getMessage()))));
        }
        // Idempotency: skip usernames that already exist in the realm (case-insensitive, matching login).
        final java.util.Set<String> existing = new java.util.HashSet<>();
        publisher.list(realmId).forEach(u -> existing.add(u.username() == null ? "" : u.username().toLowerCase()));

        int created = 0;
        int skipped = 0;
        final List<Map<String, String>> failed = new java.util.ArrayList<>();
        for (final UserImportParser.Row row : rows) {
            if (existing.contains(row.username().toLowerCase())) {
                skipped++;
                continue;
            }
            try {
                final boolean noPassword = row.password() == null || row.password().isBlank();
                final String password = noPassword ? randomTempPassword() : row.password();
                final UserAdminDto saved = publisher.create(new UserWriteDto(realmId, null, row.username(),
                        row.email(), password, row.enabled(), false, row.attributes()));
                if (saved == null) {
                    failed.add(Map.of("username", row.username(), "error", "Create returned no user."));
                    continue;
                }
                // No supplied password → force the user to set one at first login (B1 required action).
                if (noPassword) {
                    publisher.setRequiredActions(new UserRequiredActionsDto(realmId, saved.userId(), "UPDATE_PASSWORD"));
                }
                provision(realmId, ScimProvisioningDispatcher.Operation.CREATE, saved); // B7: push to outbound SCIM too
                existing.add(row.username().toLowerCase());
                created++;
            } catch (final RuntimeException e) {
                failed.add(Map.of("username", row.username(), "error", rootMessage(e)));
            }
        }
        return ResponseEntity.ok(new ImportResult(created, skipped, failed));
    }

    /** A strong random temporary password (satisfies any realm policy); the user resets it via UPDATE_PASSWORD. */
    private static String randomTempPassword() {
        final String alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
        final java.security.SecureRandom rnd = new java.security.SecureRandom();
        final StringBuilder sb = new StringBuilder("Aa1!");
        for (int i = 0; i < 20; i++) {
            sb.append(alphabet.charAt(rnd.nextInt(alphabet.length())));
        }
        return sb.toString();
    }

    private static String rootMessage(final Throwable e) {
        Throwable t = e;
        while (t.getCause() != null && t.getCause() != t) {
            t = t.getCause();
        }
        final String m = t.getMessage();
        return m == null || m.isBlank() ? t.getClass().getSimpleName() : m;
    }

    @PostMapping
    @Operation(summary = "Create a user", description = "Create a realm user; password is write-only and never returned.")
    public ResponseEntity<UserAdminDto> create(@PathVariable final String realmId,
                                               @Valid @RequestBody final UserAdminRequest request) {
        final UserAdminDto saved = publisher.create(new UserWriteDto(realmId, null, request.username(),
                request.email(), request.password(), request.enabledOrDefault(), request.locked(), attrs(request)));
        provision(realmId, ScimProvisioningDispatcher.Operation.CREATE, saved);
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    @PutMapping("/{userId}")
    @Operation(summary = "Update a user", description = "Update profile/flags; the password is not changed here.")
    public ResponseEntity<UserAdminDto> update(@PathVariable final String realmId, @PathVariable final String userId,
                                               @Valid @RequestBody final UserAdminRequest request) {
        final UserAdminDto saved = publisher.update(new UserWriteDto(realmId, userId, request.username(),
                request.email(), null, request.enabledOrDefault(), request.locked(), attrs(request)));
        if (saved != null) {
            provision(realmId, ScimProvisioningDispatcher.Operation.UPDATE, saved);
        }
        return saved == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(saved);
    }

    @PutMapping("/{userId}/password")
    @Operation(summary = "Reset password", description = "Set a new password for the user (write-only).")
    public ResponseEntity<Void> resetPassword(@PathVariable final String realmId, @PathVariable final String userId,
                                              @Valid @RequestBody final UserPasswordRequest request) {
        final boolean ok = Boolean.TRUE.equals(
                publisher.resetPassword(new UserPasswordDto(realmId, userId, request.newPassword())));
        return ok ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    @DeleteMapping("/{userId}")
    @Operation(summary = "Delete a user", description = "Remove the user from the realm; 404 if absent.")
    public ResponseEntity<Void> delete(@PathVariable final String realmId, @PathVariable final String userId) {
        final boolean removed = Boolean.TRUE.equals(publisher.delete(new UserAdminRef(realmId, userId)));
        if (removed) {
            // DELETE resolves the downstream resource by externalId (= userId); other fields are unused.
            scimDispatcher.provision(realmId, ScimProvisioningDispatcher.Operation.DELETE,
                    new ScimUserView(userId, null, null, false, null, null));
        }
        return removed ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    /** Every enrolled authentication factor for the user — the console's Device &amp; passkeys screen. */
    @GetMapping("/{userId}/credentials")
    @Operation(summary = "List credentials", description = "Every enrolled authentication factor for the user.")
    public List<CredentialSummary> credentials(@PathVariable final String realmId,
                                               @PathVariable final String userId) {
        return publisher.listCredentials(new UserAdminRef(realmId, userId));
    }

    /** Revoke a single factor by type + id; 404 when it is absent or not owned by the user. */
    @DeleteMapping("/{userId}/credentials/{type}/{id}")
    @Operation(summary = "Revoke a credential", description = "Revoke one factor by type + id; 404 if absent/not owned.")
    public ResponseEntity<Void> revokeCredential(@PathVariable final String realmId, @PathVariable final String userId,
                                                 @PathVariable final String type, @PathVariable final String id) {
        final boolean removed = Boolean.TRUE.equals(
                publisher.revokeCredential(new CredentialRevokeRef(realmId, userId, type, id)));
        return removed ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    /**
     * Helix IAM B4: start impersonating this user — establishes an authenticated session AS them on the
     * auth server and returns where to land + who you now are. The admin's original identity is recorded
     * on the session so it can be ended via {@code /stop-impersonation}. 404 if the user is absent.
     */
    @PostMapping("/{userId}/impersonate")
    @Operation(summary = "Impersonate a user", description = "Start an admin impersonation session as the target user.")
    public ResponseEntity<Map<String, String>> impersonate(@PathVariable final String realmId,
                                                           @PathVariable final String userId,
                                                           final HttpServletRequest request,
                                                           final HttpServletResponse response) {
        final UserAdminDto target = publisher.get(new UserAdminRef(realmId, userId));
        if (target == null) {
            return ResponseEntity.notFound().build();
        }
        final String admin = AuditContext.adminActor();
        final ImpersonationService.Result result = impersonationService.impersonate(realmId, userId, admin, request, response);
        auditLog.emit(AuditEvent.admin(AuditContext.nowIso(), "IMPERSONATE_START", realmId, admin,
                AuditContext.clientIp(request), "users", userId, "SUCCESS"));
        // Show the human username/email in the console, never the opaque user id.
        final String label = target.username() != null && !target.username().isBlank() ? target.username() : userId;
        return ResponseEntity.ok(Map.of("impersonating", label, "redirectUrl", result.redirectUrl()));
    }

    /** B1: the user's pending required actions (CSV) — the console's Required-actions control reads this. */
    @GetMapping("/{userId}/required-actions")
    @Operation(summary = "Get required actions", description = "The CSV of actions the user must complete at next login.")
    public Map<String, String> getRequiredActions(@PathVariable final String realmId, @PathVariable final String userId) {
        final String csv = publisher.getRequiredActions(userId);
        return Map.of("requiredActions", csv == null ? "" : csv);
    }

    /** B1: replace the user's required actions (CSV, e.g. "UPDATE_PASSWORD,VERIFY_EMAIL"; empty clears). */
    @PutMapping("/{userId}/required-actions")
    @Operation(summary = "Set required actions", description = "Replace the actions the user must complete at next login.")
    public ResponseEntity<Void> setRequiredActions(@PathVariable final String realmId, @PathVariable final String userId,
                                                   @RequestBody final RequiredActionsRequest body) {
        final boolean ok = Boolean.TRUE.equals(publisher.setRequiredActions(
                new UserRequiredActionsDto(realmId, userId, body.requiredActions())));
        return ok ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    /** Body for setting required actions: the full comma-separated replacement list (empty = none). */
    public record RequiredActionsRequest(String requiredActions) {
    }

    /** B7: push a user lifecycle change to the realm's outbound SCIM targets (best-effort, off-thread). */
    private void provision(final String realmId, final ScimProvisioningDispatcher.Operation op, final UserAdminDto user) {
        final Map<String, String> a = user.attributes() == null ? Map.of() : user.attributes();
        scimDispatcher.provision(realmId, op, new ScimUserView(user.userId(), user.username(), user.email(),
                user.enabled(), a.get("firstName"), a.get("lastName")));
    }

    private static Map<String, String> attrs(final UserAdminRequest request) {
        return request.attributes() == null ? Map.of() : request.attributes();
    }
}
