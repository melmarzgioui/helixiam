package io.helixiam.authorization.amqp;

import io.helixiam.authorization.flow.persistence.AuthFlowDefinition;

/**
 * Helix IAM E2.5: fetches a realm's persisted authentication flow from the subscriber (the owner
 * of the auth_flow tables). The flow engine maps the returned {@link AuthFlowDefinition} into its
 * tree and drives login from it. JSON-marshalled, two-copy DTO (like the login exchange).
 */
public interface AuthFlowPublisher {

    String EXCHANGE_AUTHORIZATION_FLOW = "exchange-authorization-flow";
    String AUTHORIZATION_FLOW_BROWSER_GET = "authorization.flow.browser.get";
    String AUTHORIZATION_FLOW_CLIENT_GET = "authorization.flow.client.get";

    /** The realm's browser login flow, or {@code null} if the realm has none configured. */
    AuthFlowDefinition retrieveBrowserFlow(final String realmId);

    /**
     * Helix IAM (named flows): the login flow bound to the in-flight client, or the realm's {@code browser}
     * default when the client has no override. {@code realmScopedClientId} packs the realm ahead of the
     * client id (see {@link RealmScopedKey#pack}).
     */
    AuthFlowDefinition retrieveFlowForClient(final String realmScopedClientId);
}
