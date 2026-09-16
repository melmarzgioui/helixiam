package group.mfnr.authorization.service.authz;

import group.mfnr.authorization.domain.authz.*;
import group.mfnr.authorization.repository.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Helix IAM (Wave 6): Authorization-Services administration — resource server, scopes, resources, role-based
 * policies and permissions, plus the {@link #evaluate} decision endpoint (the console's Evaluate tool). All
 * scoped to a client acting as a resource server.
 */
@Service
public class AuthorizationAdminService {

    private final AuthzResourceServerRepository servers;
    private final AuthzScopeRepository scopes;
    private final AuthzResourceRepository resources;
    private final AuthzPolicyRepository policies;
    private final AuthzPermissionRepository permissions;

    @Autowired
    public AuthorizationAdminService(final AuthzResourceServerRepository servers, final AuthzScopeRepository scopes,
                                     final AuthzResourceRepository resources, final AuthzPolicyRepository policies,
                                     final AuthzPermissionRepository permissions) {
        this.servers = servers;
        this.scopes = scopes;
        this.resources = resources;
        this.policies = policies;
        this.permissions = permissions;
    }

    // --- Resource server ---

    @Transactional(readOnly = true)
    public AuthzServerDto getServer(final String realmId, final String clientId) {
        return servers.findByRealmIdAndClientId(realmId, clientId)
                .map(s -> new AuthzServerDto(s.getRealmId(), s.getClientId(), s.getEnabled(), s.getDecisionStrategy()))
                .orElse(new AuthzServerDto(realmId, clientId, false, "UNANIMOUS"));
    }

    @Transactional
    public AuthzServerDto setServer(final AuthzServerDto write) {
        final AuthzResourceServerEntity e = servers.findByRealmIdAndClientId(write.realmId(), write.clientId())
                .orElseGet(AuthzResourceServerEntity::new);
        e.setRealmId(write.realmId());
        e.setClientId(write.clientId());
        e.setEnabled(write.enabled() == null || write.enabled());
        e.setDecisionStrategy(blankTo(write.decisionStrategy(), "UNANIMOUS"));
        final AuthzResourceServerEntity s = servers.save(e);
        return new AuthzServerDto(s.getRealmId(), s.getClientId(), s.getEnabled(), s.getDecisionStrategy());
    }

    // --- Scopes ---

    @Transactional(readOnly = true)
    public List<AuthzScopeDto> listScopes(final String realmId, final String clientId) {
        return scopes.findAllByRealmIdAndClientIdOrderByName(realmId, clientId).stream()
                .map(s -> new AuthzScopeDto(s.getId(), s.getRealmId(), s.getClientId(), s.getName())).toList();
    }

    @Transactional
    public AuthzScopeDto createScope(final AuthzScopeDto write) {
        if (scopes.existsByRealmIdAndClientIdAndName(write.realmId(), write.clientId(), write.name())) {
            return scopes.findByRealmIdAndClientIdAndName(write.realmId(), write.clientId(), write.name())
                    .map(s -> new AuthzScopeDto(s.getId(), s.getRealmId(), s.getClientId(), s.getName())).orElse(null);
        }
        final AuthzScopeEntity e = new AuthzScopeEntity();
        e.setRealmId(write.realmId()); e.setClientId(write.clientId()); e.setName(write.name());
        final AuthzScopeEntity s = scopes.save(e);
        return new AuthzScopeDto(s.getId(), s.getRealmId(), s.getClientId(), s.getName());
    }

    @Transactional
    public boolean deleteScope(final String realmId, final String clientId, final String name) {
        return scopes.findByRealmIdAndClientIdAndName(realmId, clientId, name).map(s -> { scopes.delete(s); return true; }).orElse(false);
    }

    // --- Resources ---

    @Transactional(readOnly = true)
    public List<AuthzResourceDto> listResources(final String realmId, final String clientId) {
        return resources.findAllByRealmIdAndClientIdOrderByName(realmId, clientId).stream().map(this::toResource).toList();
    }

    @Transactional
    public AuthzResourceDto createResource(final AuthzResourceDto write) {
        final AuthzResourceEntity e = resources.findByRealmIdAndClientIdAndName(write.realmId(), write.clientId(), write.name())
                .orElseGet(AuthzResourceEntity::new);
        e.setRealmId(write.realmId()); e.setClientId(write.clientId()); e.setName(write.name());
        e.setUris(join(write.uris())); e.setScopes(join(write.scopes()));
        return toResource(resources.save(e));
    }

    @Transactional
    public boolean deleteResource(final String realmId, final String clientId, final String name) {
        return resources.findByRealmIdAndClientIdAndName(realmId, clientId, name).map(r -> { resources.delete(r); return true; }).orElse(false);
    }

    // --- Policies ---

    @Transactional(readOnly = true)
    public List<AuthzPolicyDto> listPolicies(final String realmId, final String clientId) {
        return policies.findAllByRealmIdAndClientIdOrderByName(realmId, clientId).stream().map(this::toPolicy).toList();
    }

    @Transactional
    public AuthzPolicyDto createPolicy(final AuthzPolicyDto write) {
        final AuthzPolicyEntity e = policies.findByRealmIdAndClientIdAndName(write.realmId(), write.clientId(), write.name())
                .orElseGet(AuthzPolicyEntity::new);
        e.setRealmId(write.realmId()); e.setClientId(write.clientId()); e.setName(write.name());
        e.setType(blankTo(write.type(), "ROLE")); e.setLogic(blankTo(write.logic(), "POSITIVE"));
        e.setRoles(join(write.roles()));
        return toPolicy(policies.save(e));
    }

    @Transactional
    public boolean deletePolicy(final String realmId, final String clientId, final String name) {
        return policies.findByRealmIdAndClientIdAndName(realmId, clientId, name).map(p -> { policies.delete(p); return true; }).orElse(false);
    }

    // --- Permissions ---

    @Transactional(readOnly = true)
    public List<AuthzPermissionDto> listPermissions(final String realmId, final String clientId) {
        return permissions.findAllByRealmIdAndClientIdOrderByName(realmId, clientId).stream().map(this::toPermission).toList();
    }

    @Transactional
    public AuthzPermissionDto createPermission(final AuthzPermissionDto write) {
        final AuthzPermissionEntity e = permissions.findByRealmIdAndClientIdAndName(write.realmId(), write.clientId(), write.name())
                .orElseGet(AuthzPermissionEntity::new);
        e.setRealmId(write.realmId()); e.setClientId(write.clientId()); e.setName(write.name());
        e.setType(blankTo(write.type(), "RESOURCE"));
        e.setResourceName(blankToNull(write.resourceName())); e.setScopeName(blankToNull(write.scopeName()));
        e.setPolicies(join(write.policies())); e.setDecisionStrategy(blankTo(write.decisionStrategy(), "UNANIMOUS"));
        return toPermission(permissions.save(e));
    }

    @Transactional
    public boolean deletePermission(final String realmId, final String clientId, final String name) {
        return permissions.findByRealmIdAndClientIdAndName(realmId, clientId, name).map(p -> { permissions.delete(p); return true; }).orElse(false);
    }

    // --- Evaluate ---

    @Transactional(readOnly = true)
    public AuthzEvalResult evaluate(final AuthzEvalRequest req) {
        final List<PermissionView> perms = permissions.findAllByRealmIdAndClientIdOrderByName(req.realmId(), req.clientId()).stream()
                .map(p -> new PermissionView(p.getName(), p.getType(), p.getResourceName(), p.getScopeName(),
                        split(p.getPolicies()), p.getDecisionStrategy())).toList();
        final Map<String, PolicyView> pol = policies.findAllByRealmIdAndClientIdOrderByName(req.realmId(), req.clientId()).stream()
                .collect(Collectors.toMap(AuthzPolicyEntity::getName,
                        p -> new PolicyView(p.getName(), p.getType(), p.getLogic(), Set.copyOf(split(p.getRoles())))));
        final String strategy = servers.findByRealmIdAndClientId(req.realmId(), req.clientId())
                .map(AuthzResourceServerEntity::getDecisionStrategy).orElse("UNANIMOUS");
        final Set<String> roles = req.roles() == null ? Set.of() : Set.copyOf(req.roles());
        final EvaluationResult r = AuthorizationEvaluator.evaluate(req.resourceName(), blankToNull(req.scopeName()),
                roles, perms, pol, strategy);
        return new AuthzEvalResult(r.granted(), r.grantingPermissions(), r.denyingPermissions());
    }

    private AuthzResourceDto toResource(final AuthzResourceEntity r) {
        return new AuthzResourceDto(r.getId(), r.getRealmId(), r.getClientId(), r.getName(), split(r.getUris()), split(r.getScopes()));
    }

    private AuthzPolicyDto toPolicy(final AuthzPolicyEntity p) {
        return new AuthzPolicyDto(p.getId(), p.getRealmId(), p.getClientId(), p.getName(), p.getType(), p.getLogic(), split(p.getRoles()));
    }

    private AuthzPermissionDto toPermission(final AuthzPermissionEntity p) {
        return new AuthzPermissionDto(p.getId(), p.getRealmId(), p.getClientId(), p.getName(), p.getType(),
                p.getResourceName(), p.getScopeName(), split(p.getPolicies()), p.getDecisionStrategy());
    }

    private static String join(final List<String> xs) {
        return xs == null ? "" : xs.stream().map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.joining(","));
    }

    private static List<String> split(final String csv) {
        return csv == null || csv.isBlank() ? List.of()
                : Arrays.stream(csv.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }

    private static String blankTo(final String v, final String dflt) {
        return v == null || v.isBlank() ? dflt : v.trim();
    }

    private static String blankToNull(final String v) {
        return v == null || v.isBlank() ? null : v.trim();
    }
}
