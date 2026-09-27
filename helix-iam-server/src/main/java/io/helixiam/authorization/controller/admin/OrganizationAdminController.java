/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.org.OrgDto;
import io.helixiam.authorization.amqp.org.OrgMemberChange;
import io.helixiam.authorization.amqp.org.OrgMemberDto;
import io.helixiam.authorization.amqp.org.OrgRef;
import io.helixiam.authorization.amqp.org.OrgWriteDto;
import io.helixiam.authorization.amqp.org.OrganizationAdminPublisher;
import io.helixiam.authorization.security.audit.AuditContext;
import io.swagger.v3.oas.annotations.Operation;
import jakarta.servlet.http.HttpServletRequest;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
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
 * Helix IAM Organizations: admin REST API for a realm's B2B organizations (Keycloak Organizations /
 * WorkOS-class) — CRUD on organizations plus membership management, the backend behind the console's
 * Organizations screen. Realm comes from the path (the {@code /realms/{realm}} prefix is stripped by the
 * RealmRoutingFilter; RealmContextHolder carries the realm).
 *
 * <p>Bad input is signalled via Bean Validation ({@code @Valid}) → {@code AdminValidationAdvice} (400),
 * never by throwing {@code ResponseStatusException} (which would 302-redirect to login via {@code /error}).
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/organizations")
@Tag(name = "Organizations", description = "B2B organizations and membership within a realm.")
public class OrganizationAdminController {

    private final OrganizationAdminPublisher publisher;

    public OrganizationAdminController(final OrganizationAdminPublisher publisher) {
        this.publisher = publisher;
    }

    @GetMapping
    @Operation(summary = "List organizations", description = "All organizations in the realm.")
    public List<OrgDto> list(@PathVariable final String realmId) {
        return publisher.list(realmId);
    }

    @GetMapping("/{orgId}")
    @Operation(summary = "Get an organization", description = "Fetch one organization by id; 404 if absent.")
    public ResponseEntity<OrgDto> get(@PathVariable final String realmId, @PathVariable final String orgId) {
        final OrgDto org = publisher.get(new OrgRef(realmId, orgId, null, null));
        return org == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(org);
    }

    @PostMapping
    @Operation(summary = "Create an organization")
    public ResponseEntity<OrgDto> create(@PathVariable final String realmId, @Valid @RequestBody final OrgRequest request) {
        final OrgDto saved = publisher.create(new OrgWriteDto(
                realmId, null, request.name().trim(), blankToNull(request.displayName()),
                request.domains(), request.enabled() == null || request.enabled()));
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    @PutMapping("/{orgId}")
    @Operation(summary = "Update an organization", description = "Update name/display/domains/enabled; 404 if absent.")
    public ResponseEntity<OrgDto> update(@PathVariable final String realmId, @PathVariable final String orgId,
                                         @Valid @RequestBody final OrgRequest request) {
        final OrgDto saved = publisher.update(new OrgWriteDto(
                realmId, orgId, request.name().trim(), blankToNull(request.displayName()),
                request.domains(), request.enabled() == null || request.enabled()));
        return saved == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(saved);
    }

    @DeleteMapping("/{orgId}")
    @Operation(summary = "Delete an organization", description = "Remove the organization; 404 if absent.")
    public ResponseEntity<Void> delete(@PathVariable final String realmId, @PathVariable final String orgId) {
        return Boolean.TRUE.equals(publisher.delete(new OrgRef(realmId, orgId, null, null)))
                ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    @GetMapping("/{orgId}/members")
    @Operation(summary = "List members", description = "Users that are members of the organization.")
    public ResponseEntity<List<OrgMemberDto>> members(@PathVariable final String realmId, @PathVariable final String orgId) {
        final List<OrgMemberDto> members = publisher.members(new OrgRef(realmId, orgId, null, null));
        return members == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(members);
    }

    @PutMapping("/{orgId}/members/{userId}")
    @Operation(summary = "Add a member or change its role",
            description = "Adds the user to the organization (201, default role member) or changes an existing member's "
                    + "role in place (200; no role keeps the current one). Answers the membership. 404 when the "
                    + "organization or the user is not in this realm.")
    public ResponseEntity<OrgMemberDto> putMember(@PathVariable final String realmId, @PathVariable final String orgId,
                                                  @PathVariable final String userId,
                                                  @Valid @RequestBody(required = false) final MemberRequest request,
                                                  final HttpServletRequest http) {
        final String role = request == null ? null : blankToNull(request.role());
        final OrgMemberChange change = publisher.putMember(new OrgRef(realmId, orgId, userId, role));
        if (change == null) {
            return ResponseEntity.notFound().build();
        }
        if (http != null) {
            AuditContext.attachDetail(http, Map.of("change", change.created() ? "added" : "role",
                    "userId", userId, "role", change.member().role()));
        }
        return ResponseEntity.status(change.created() ? HttpStatus.CREATED : HttpStatus.OK).body(change.member());
    }

    @DeleteMapping("/{orgId}/members/{userId}")
    @Operation(summary = "Remove a member", description = "Remove a user from the organization; 404 if not a member.")
    public ResponseEntity<Void> removeMember(@PathVariable final String realmId, @PathVariable final String orgId,
                                             @PathVariable final String userId) {
        return Boolean.TRUE.equals(publisher.removeMember(new OrgRef(realmId, orgId, userId, null)))
                ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    private static String blankToNull(final String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    /** Create/update body. {@code domains} and {@code displayName} are optional; {@code enabled} defaults to true. */
    public record OrgRequest(@NotBlank(message = "Organization name is required.") String name,
                             String displayName, List<String> domains, Boolean enabled) {
    }

    /**
     * Put-member body: the role within the org (a new member defaults to {@code member}; an existing member keeps its
     * role when none is given). A short token: letters, digits, {@code . _ : -}.
     */
    public record MemberRequest(@Size(max = 64, message = "Role must be at most 64 characters.")
                                @Pattern(regexp = "\\s*|[A-Za-z0-9][A-Za-z0-9._:-]*",
                                        message = "Role may only contain letters, digits, '.', '_', ':' and '-'.")
                                String role) {
    }
}
