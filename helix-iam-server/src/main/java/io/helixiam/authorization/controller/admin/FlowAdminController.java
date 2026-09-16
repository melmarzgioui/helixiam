/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.flow.FlowAdminPublisher;
import io.helixiam.authorization.amqp.flow.FlowCreateDto;
import io.helixiam.authorization.amqp.flow.FlowDefinitionDto;
import io.helixiam.authorization.amqp.flow.FlowExecutionDto;
import io.helixiam.authorization.amqp.flow.FlowRefDto;
import io.helixiam.authorization.amqp.flow.FlowRenameDto;
import io.helixiam.authorization.amqp.flow.FlowSaveDto;
import io.helixiam.authorization.amqp.flow.FlowSummaryDto;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Helix IAM E8.5-S4 + named flows: admin REST API for a realm's authentication flows — the backend behind
 * the console's Auth-flow editor. A realm has one built-in {@code browser} flow plus any number of named
 * flows that clients can be bound to (per-client flow overrides). {@code /flow} keeps editing the browser
 * flow (back-compat); {@code /flows} manages the full set.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}")
public class FlowAdminController {

    private static final String BROWSER_ALIAS = "browser";

    private final FlowAdminPublisher publisher;

    public FlowAdminController(final FlowAdminPublisher publisher) {
        this.publisher = publisher;
    }

    // ---- back-compat: the realm's default browser flow ----
    @GetMapping("/flow")
    public FlowDefinitionDto getBrowser(@PathVariable final String realmId) {
        return publisher.get(realmId);
    }

    @PutMapping("/flow")
    public FlowDefinitionDto saveBrowser(@PathVariable final String realmId, @RequestBody final FlowSaveRequest request) {
        return publisher.save(new FlowSaveDto(realmId, BROWSER_ALIAS, exec(request)));
    }

    // ---- named flows ----
    @GetMapping("/flows")
    public List<FlowSummaryDto> list(@PathVariable final String realmId) {
        return publisher.list(realmId);
    }

    @PostMapping("/flows")
    public FlowSummaryDto create(@PathVariable final String realmId, @Valid @RequestBody final FlowCreateRequest request) {
        return publisher.create(new FlowCreateDto(realmId, request.alias(), request.copyFromAlias()));
    }

    @GetMapping("/flows/{alias}")
    public FlowDefinitionDto get(@PathVariable final String realmId, @PathVariable final String alias) {
        return publisher.getByAlias(new FlowRefDto(realmId, alias));
    }

    @PutMapping("/flows/{alias}")
    public FlowDefinitionDto save(@PathVariable final String realmId, @PathVariable final String alias, @RequestBody final FlowSaveRequest request) {
        return publisher.save(new FlowSaveDto(realmId, alias, exec(request)));
    }

    @PatchMapping("/flows/{alias}")
    public FlowSummaryDto rename(@PathVariable final String realmId, @PathVariable final String alias, @Valid @RequestBody final FlowRenameRequest request) {
        return publisher.rename(new FlowRenameDto(realmId, alias, request.alias()));
    }

    @DeleteMapping("/flows/{alias}")
    public void delete(@PathVariable final String realmId, @PathVariable final String alias) {
        publisher.delete(new FlowRefDto(realmId, alias));
    }

    private static List<FlowExecutionDto> exec(final FlowSaveRequest request) {
        return request.executions() == null ? List.of() : request.executions();
    }

    public record FlowSaveRequest(List<FlowExecutionDto> executions) { }
    public record FlowCreateRequest(@NotBlank(message = "Flow alias is required.") String alias, String copyFromAlias) { }
    public record FlowRenameRequest(@NotBlank(message = "Flow alias is required.") String alias) { }
}
