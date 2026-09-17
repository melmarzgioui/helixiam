/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.security.adminrbac.RealmAdminAuthorities;
import io.helixiam.authorization.security.audit.AuditConfigDto;
import io.helixiam.authorization.security.audit.HelixAuditProperties;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Helix IAM E8.5-S4 (Events): read-only view of the server's audit/SIEM delivery configuration for the
 * console's Events screen. Global (one config per deployment, managed in the config file / env) — NOT
 * editable here, and the SIEM auth secret is never returned ({@link AuditConfigDto} is sanitized).
 *
 * <p>Tenant isolation (pentest P2): this is a realm-INDEPENDENT route exposing DEPLOYMENT-GLOBAL config,
 * so the request-level authorization manager only proves the caller is an admin of some realm. Global
 * config must be master-realm-admin only — otherwise any realm admin could read the deployment's SIEM
 * delivery configuration.
 */
@RestController
@RequestMapping("/admin/audit/config")
public class AuditConfigController {

    private final HelixAuditProperties props;

    public AuditConfigController(final HelixAuditProperties props) {
        this.props = props;
    }

    @GetMapping
    public ResponseEntity<AuditConfigDto> get(final Authentication auth) {
        if (!RealmAdminAuthorities.isAdminOf(auth, RealmConfig.ADMIN_REALM_ID)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.ok(AuditConfigDto.from(props));
    }
}
