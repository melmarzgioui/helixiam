/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.security.audit.AuditConfigDto;
import io.helixiam.authorization.security.audit.HelixAuditProperties;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Helix IAM E8.5-S4 (Events): read-only view of the server's audit/SIEM delivery configuration for the
 * console's Events screen. Global (one config per deployment, managed in the config file / env) — NOT
 * editable here, and the SIEM auth secret is never returned ({@link AuditConfigDto} is sanitized).
 */
@RestController
@RequestMapping("/admin/audit/config")
public class AuditConfigController {

    private final HelixAuditProperties props;

    public AuditConfigController(final HelixAuditProperties props) {
        this.props = props;
    }

    @GetMapping
    public AuditConfigDto get() {
        return AuditConfigDto.from(props);
    }
}
