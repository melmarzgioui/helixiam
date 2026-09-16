/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin.io;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.helixiam.authorization.amqp.authz.AuthzPermissionDto;
import io.helixiam.authorization.amqp.authz.AuthzPolicyDto;
import io.helixiam.authorization.amqp.authz.AuthzResourceDto;
import io.helixiam.authorization.amqp.authz.AuthzScopeDto;
import io.helixiam.authorization.amqp.authz.AuthzServerDto;

import java.util.List;

/**
 * Helix IAM: one client's complete UMA Authorization-Services configuration, bundled for realm export/import.
 * Keyed by the portable OAuth {@code clientId} string (never the registered-client UUID) so the slice re-homes
 * into another realm. On import each {@code clientId} is resolved against the target realm's clients and the
 * server/scopes/resources/policies/permissions are upserted (the subscriber's {@code createX} are idempotent
 * by {@code (realmId, clientId, name)}). Clients with no Authorization-Services config are omitted on export.
 *
 * @param clientId    the OAuth {@code client_id} this authz config belongs to (portable key)
 * @param server      the resource-server toggle + decision strategy ({@code null} when never enabled)
 * @param scopes      authorization scopes
 * @param resources   protected resources (with their URIs + scopes)
 * @param policies    role-based policies
 * @param permissions resource/scope permissions binding policies
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ClientAuthorizationDto(String clientId,
                                     AuthzServerDto server,
                                     List<AuthzScopeDto> scopes,
                                     List<AuthzResourceDto> resources,
                                     List<AuthzPolicyDto> policies,
                                     List<AuthzPermissionDto> permissions) {
}
