package group.mfnr.authorization.session.logout;

import group.mfnr.authorization.amqp.client.ClientAdminPublisher;
import group.mfnr.authorization.amqp.client.ClientDto;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM SSO P6: resolves a realm's clients (via the client-admin store) to their registered
 * back-/front-channel logout endpoints, filtered to the clients that took part in the SSO session.
 */
@Component
public class ClientAdminLogoutTargetResolver implements LogoutTargetResolver {

    private final ClientAdminPublisher clientPublisher;

    public ClientAdminLogoutTargetResolver(final ClientAdminPublisher clientPublisher) {
        this.clientPublisher = clientPublisher;
    }

    @Override
    public List<BackchannelLogoutNotifier.Target> backchannelTargets(final String realm, final List<String> clientRefs) {
        final Map<String, ClientDto> byRef = byAnyRef(realm);
        final List<BackchannelLogoutNotifier.Target> targets = new ArrayList<>();
        for (final String ref : dedupe(clientRefs)) {
            final ClientDto client = byRef.get(ref);
            // The logout_token `aud` must be the OAuth client_id the RP knows itself by (not our internal id).
            if (client != null && isNotBlank(client.backchannelLogoutUri())) {
                targets.add(new BackchannelLogoutNotifier.Target(client.clientId(), client.backchannelLogoutUri()));
            }
        }
        return targets;
    }

    @Override
    public List<FrontchannelTarget> frontchannelTargets(final String realm, final List<String> clientRefs) {
        final Map<String, ClientDto> byRef = byAnyRef(realm);
        final List<FrontchannelTarget> targets = new ArrayList<>();
        for (final String ref : dedupe(clientRefs)) {
            final ClientDto client = byRef.get(ref);
            if (client != null && isNotBlank(client.frontchannelLogoutUri())) {
                targets.add(new FrontchannelTarget(client.clientId(), client.frontchannelLogoutUri()));
            }
        }
        return targets;
    }

    /**
     * Index the realm's clients by BOTH the internal registered-client id and the OAuth client_id, since an
     * SSO session's clients are keyed by {@code oauth2_authorization.registered_client_id} (our internal id),
     * while admin/UI references use the OAuth client_id.
     */
    private Map<String, ClientDto> byAnyRef(final String realm) {
        final List<ClientDto> clients = clientPublisher.list(realm);
        if (clients == null) {
            return Map.of();
        }
        final Map<String, ClientDto> byRef = new java.util.LinkedHashMap<>();
        for (final ClientDto c : clients) {
            if (c.id() != null) {
                byRef.putIfAbsent(c.id(), c);
            }
            if (c.clientId() != null) {
                byRef.putIfAbsent(c.clientId(), c);
            }
        }
        return byRef;
    }

    private static List<String> dedupe(final List<String> clientIds) {
        return clientIds == null ? List.of()
                : clientIds.stream().filter(java.util.Objects::nonNull).distinct().toList();
    }

    private static boolean isNotBlank(final String value) {
        return value != null && !value.isBlank();
    }
}
