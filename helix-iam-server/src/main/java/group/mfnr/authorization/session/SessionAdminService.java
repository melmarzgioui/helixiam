package group.mfnr.authorization.session;

import group.mfnr.authorization.amqp.agent.AgentClientQuery;
import group.mfnr.authorization.amqp.agent.AgentIdentityDto;
import group.mfnr.authorization.amqp.agent.AgentIdentityPublisher;
import group.mfnr.authorization.amqp.client.ClientAdminPublisher;
import group.mfnr.authorization.amqp.client.ClientDto;
import group.mfnr.authorization.amqp.user.UserAdminDto;
import group.mfnr.authorization.amqp.user.UserAdminPublisher;
import group.mfnr.authorization.amqp.user.UserAdminRef;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Helix IAM SSO P7: Sessions administration in true SSO sessions. {@link #listSso} rolls the realm's active
 * authorizations up into one row per browser login (each client labelled with its human OAuth id);
 * {@link #revokeSso} cascades a Single Logout (revoke every authorization + HTTP session + fire OIDC
 * back-channel logout) through {@link SsoLogoutService}. {@link #listServiceAccounts} surfaces the
 * non-interactive {@code client_credentials} grants separately.
 */
@Service
public class SessionAdminService {

    private static final Logger LOG = LogManager.getLogger(SessionAdminService.class);

    private final SessionStore store;
    private final OAuth2AuthorizationService authorizationService;
    private final ClientAdminPublisher clients;
    private final SsoSessionStore ssoSessionStore;
    private final SsoLogoutService ssoLogoutService;
    private final UserAdminPublisher users;
    private final AgentIdentityPublisher agents;
    private final String idpBaseUrl;

    public SessionAdminService(final SessionStore store, final OAuth2AuthorizationService authorizationService,
                               final ClientAdminPublisher clients, final SsoSessionStore ssoSessionStore,
                               final SsoLogoutService ssoLogoutService, final UserAdminPublisher users,
                               final AgentIdentityPublisher agents,
                               @Value("${idp.base.url}") final String idpBaseUrl) {
        this.store = store;
        this.authorizationService = authorizationService;
        this.clients = clients;
        this.ssoSessionStore = ssoSessionStore;
        this.ssoLogoutService = ssoLogoutService;
        this.users = users;
        this.agents = agents;
        this.idpBaseUrl = idpBaseUrl;
    }

    /** Unified active-identity list for the realm: SSO sessions (user/agent) + service-account tokens, each
     *  resolved to a username + identity type, then filtered server-side by {@code type} and {@code q}. */
    public List<IdentitySessionView> listIdentities(final String realmId, final String q, final String type) {
        final List<ClientDto> realmClients = clients.list(realmId);
        final Map<String, String> humanIdByRegistered = realmClients.stream()
                .collect(Collectors.toMap(ClientDto::id, ClientDto::clientId, (a, b) -> a));
        final Map<String, String> nameByHumanId = realmClients.stream()
                .collect(Collectors.toMap(ClientDto::clientId, c -> c.name() != null ? c.name() : c.clientId(), (a, b) -> a));
        final Map<String, AgentIdentityDto> agentByHumanId = new HashMap<>();
        final Map<String, String> usernameByPrincipal = new HashMap<>();

        final List<IdentitySessionView> out = new ArrayList<>();

        // Interactive SSO sessions → USER or AGENT.
        for (final SsoSession s : ssoSessionStore.findAll()) {
            final List<IdentitySessionView.ClientView> cvs = new ArrayList<>();
            String firstHumanClient = null;
            for (final SsoSession.ClientInSession c : s.clients()) {
                final String humanId = humanIdByRegistered.get(c.clientId());
                if (humanId == null) {
                    continue;
                }
                if (firstHumanClient == null) {
                    firstHumanClient = humanId;
                }
                cvs.add(new IdentitySessionView.ClientView(humanId, c.grantType(), c.scopes(), c.issuedAt(), c.expiresAt()));
            }
            if (cvs.isEmpty()) {
                continue;
            }
            final String hc = firstHumanClient;
            final AgentIdentityDto agent = agentByHumanId.computeIfAbsent(hc,
                    k -> agents.findByClient(new AgentClientQuery(realmId, k)));
            final IdentityType t = agent != null ? IdentityType.AGENT : IdentityType.USER;
            final String display = agent != null
                    ? (agent.displayName() != null ? agent.displayName() : agent.name())
                    : usernameByPrincipal.computeIfAbsent(s.principalName(), p -> resolveUsername(realmId, p));
            out.add(new IdentitySessionView(s.ssoSessionId(), t, s.principalName(), display, realmId,
                    s.issuedAt(), s.expiresAt(), "SLO", cvs));
        }

        // Non-interactive service-account tokens (client_credentials) → SERVICE_ACCOUNT.
        for (final SessionRow row : store.findAll()) {
            if (!"client_credentials".equals(row.grantType())) {
                continue;
            }
            final String humanId = humanIdByRegistered.get(row.registeredClientId());
            if (humanId == null) {
                continue;
            }
            final String display = nameByHumanId.getOrDefault(humanId, humanId);
            out.add(new IdentitySessionView(row.id(), IdentityType.SERVICE_ACCOUNT, row.principalName(), display, realmId,
                    row.issuedAt(), row.expiresAt(), "TOKEN",
                    List.of(new IdentitySessionView.ClientView(humanId, row.grantType(), row.scopes(), row.issuedAt(), row.expiresAt()))));
        }

        return out.stream()
                .filter(v -> type == null || type.isBlank() || v.identityType().name().equalsIgnoreCase(type))
                .filter(v -> q == null || q.isBlank() || matchesQuery(v, q.toLowerCase()))
                .sorted(Comparator.comparing(IdentitySessionView::issuedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .collect(Collectors.toList());
    }

    /** SLO for an SSO session; else single-authorization revoke (service accounts). Realm-scoped. */
    public boolean revokeIdentity(final String realmId, final String id) {
        return revokeSso(realmId, id) || revoke(realmId, id);
    }

    private String resolveUsername(final String realmId, final String principal) {
        try {
            final UserAdminDto u = users.get(new UserAdminRef(realmId, principal));
            return u != null && u.username() != null ? u.username() : principal;
        } catch (final RuntimeException e) {
            return principal;
        }
    }

    private boolean matchesQuery(final IdentitySessionView v, final String q) {
        if (v.displayName() != null && v.displayName().toLowerCase().contains(q)) {
            return true;
        }
        if (v.principalName() != null && v.principalName().toLowerCase().contains(q)) {
            return true;
        }
        return v.clients().stream().anyMatch(c -> c.clientId() != null && c.clientId().toLowerCase().contains(q));
    }

    /** The realm's interactive SSO sessions, newest first, each client labelled with its human OAuth id. */
    public List<SsoSessionView> listSso(final String realmId) {
        final Map<String, String> clientIdById = realmClientIdById(realmId);
        return ssoSessionStore.findAll().stream()
                .map(s -> toView(s, realmId, clientIdById))
                .filter(v -> !v.clients().isEmpty())   // at least one client in this realm
                .sorted(Comparator.comparing(SsoSessionView::issuedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .collect(Collectors.toList());
    }

    /** The realm's non-interactive service-account ({@code client_credentials}) authorizations. */
    public List<SessionSummary> listServiceAccounts(final String realmId) {
        final Map<String, String> clientIdById = realmClientIdById(realmId);
        return store.findAll().stream()
                .filter(row -> "client_credentials".equals(row.grantType()))
                .filter(row -> clientIdById.containsKey(row.registeredClientId()))
                .map(row -> new SessionSummary(row.id(), row.principalName(), clientIdById.get(row.registeredClientId()),
                        row.grantType(), row.scopes(), row.issuedAt(), row.expiresAt()))
                .sorted(Comparator.comparing(SessionSummary::issuedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .collect(Collectors.toList());
    }

    /** Cascading Single Logout for an SSO session — only if it belongs to a client in this realm. */
    public boolean revokeSso(final String realmId, final String ssoSessionId) {
        final SsoSession session = ssoSessionStore.findById(ssoSessionId);
        if (session == null) {
            return false;
        }
        final Map<String, String> clientIdById = realmClientIdById(realmId);
        final boolean inRealm = session.clients().stream().anyMatch(c -> clientIdById.containsKey(c.clientId()));
        if (!inRealm) {
            LOG.warn("Refusing to revoke SSO session {} — no client in realm {}", ssoSessionId, realmId);
            return false;
        }
        ssoLogoutService.terminate(ssoSessionId, realmId, idpBaseUrl + "/realms/" + realmId);
        LOG.info("Admin revoked SSO session {} in realm {} (cascading logout)", ssoSessionId, realmId);
        return true;
    }

    /** Single-authorization revoke retained for service-account rows; realm-scoped. */
    public boolean revoke(final String realmId, final String id) {
        final var authorization = authorizationService.findById(id);
        if (authorization == null) {
            return false;
        }
        if (!realmClientIdById(realmId).containsKey(authorization.getRegisteredClientId())) {
            LOG.warn("Refusing to revoke session {} — not owned by realm {}", id, realmId);
            return false;
        }
        authorizationService.remove(authorization);
        return true;
    }

    private SsoSessionView toView(final SsoSession s, final String realmId, final Map<String, String> clientIdById) {
        final List<SsoSessionView.ClientView> views = new ArrayList<>();
        for (final SsoSession.ClientInSession c : s.clients()) {
            final String humanId = clientIdById.get(c.clientId());
            if (humanId != null) {   // only clients that belong to this realm
                views.add(new SsoSessionView.ClientView(humanId, c.grantType(), c.scopes(), c.issuedAt(), c.expiresAt()));
            }
        }
        return new SsoSessionView(s.ssoSessionId(), s.principalName(), realmId, s.issuedAt(), s.expiresAt(), views);
    }

    /** Map of registered-client id → human client id for every client in the realm. */
    private Map<String, String> realmClientIdById(final String realmId) {
        return clients.list(realmId).stream()
                .collect(Collectors.toMap(ClientDto::id, ClientDto::clientId, (a, b) -> a));
    }
}
