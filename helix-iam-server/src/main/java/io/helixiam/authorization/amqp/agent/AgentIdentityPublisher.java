/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.agent;


import java.util.List;

/**
 * Helix IAM Agent (NHI): the admin API's seam onto the per-realm agent registry (subscriber). {@code list}/
 * {@code get}/{@code save}/{@code delete} back the console CRUD; {@code suspend}/{@code activate}/{@code
 * revoke} run the status lifecycle. All-dot routing keys for the dash→dot binding (the subscriber binds
 * {@code authorization-agent-list} as {@code authorization.agent.list}). Reuses the EXISTING per-feature
 * authorization exchange convention — no new exchange topology.
 */
public interface AgentIdentityPublisher {

    String EXCHANGE_AUTHORIZATION_AGENT = "exchange-authorization-agent";
    // The subscriber binds each @AnonymousListener key with EVERY dash turned into a dot, so the
    // subscriber's `authorization-agent-list` binds as `authorization.agent.list`. These sender keys must
    // therefore be ALL dots, or the RPC never matches a binding and hangs (HTTP 000).
    String AGENT_LIST = "authorization.agent.list";
    String AGENT_GET = "authorization.agent.get";
    String AGENT_SAVE = "authorization.agent.save";
    String AGENT_DELETE = "authorization.agent.delete";
    String AGENT_SUSPEND = "authorization.agent.suspend";
    String AGENT_ACTIVATE = "authorization.agent.activate";
    String AGENT_REVOKE = "authorization.agent.revoke";
    String AGENT_BY_CLIENT = "authorization.agent.byclient";
    String AGENT_OWNER_REVIEW = "authorization.agent.owner.review";

    List<AgentIdentityDto> list(final String realmId);

    /** Owner-integrity review: every agent tagged VALID/UNKNOWN/ORPHANED against the realm's users. */
    List<AgentOwnerReviewDto> ownerReview(final String realmId);

    AgentIdentityDto get(final AgentIdentityRef ref);

    AgentIdentityDto save(final AgentIdentityDto dto);

    Boolean delete(final AgentIdentityRef ref);

    AgentIdentityDto suspend(final AgentIdentityRef ref);

    AgentIdentityDto activate(final AgentIdentityRef ref);

    AgentIdentityDto revoke(final AgentIdentityRef ref);

    /** Resolve the agent bound to an OIDC client (or null) — the token customizer's enrichment lookup. */
    AgentIdentityDto findByClient(final AgentClientQuery query);
}
