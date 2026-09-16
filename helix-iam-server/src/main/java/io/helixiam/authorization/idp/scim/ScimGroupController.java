package io.helixiam.authorization.idp.scim;

import io.helixiam.authorization.amqp.group.GroupAdminPublisher;
import io.helixiam.authorization.amqp.group.GroupDto;
import io.helixiam.authorization.amqp.group.GroupMemberDto;
import io.helixiam.authorization.amqp.group.GroupRef;
import io.helixiam.authorization.amqp.group.GroupWriteDto;
import io.helixiam.authorization.idp.provisioning.ProvisioningAdminPublisher;
import io.helixiam.authorization.idp.provisioning.ScimTokenCheck;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Helix IAM E7 (SCIM 2.0): inbound provisioning of Groups INTO Helix (RFC 7643/7644). Served per realm at
 * {@code /realms/{realm}/scim/v2/Groups}, mapping SCIM Groups onto the Helix group model over the existing
 * {@link GroupAdminPublisher} AMQP admin path. Same Bearer-token authn + never-throw contract as the Users
 * endpoint. Membership replacement is applied as add/remove deltas over the group-member admin path.
 */
@RestController
public class ScimGroupController {

    private static final String SCIM_JSON = "application/scim+json";
    private static final int DEFAULT_COUNT = 100;

    private final GroupAdminPublisher groups;
    private final ProvisioningAdminPublisher provisioning;

    public ScimGroupController(final GroupAdminPublisher groups, final ProvisioningAdminPublisher provisioning) {
        this.groups = groups;
        this.provisioning = provisioning;
    }

    @GetMapping(value = "/scim/v2/Groups", produces = SCIM_JSON)
    public ResponseEntity<?> list(@RequestParam(required = false) final String filter,
                                  @RequestParam(required = false) final Integer startIndex,
                                  @RequestParam(required = false) final Integer count,
                                  final HttpServletRequest request) {
        final String realm = RealmContextHolder.get();
        final ResponseEntity<?> denied = authorize(realm, request);
        if (denied != null) {
            return denied;
        }
        List<GroupDto> all = groups.list(realm);
        final String displayNameEq = ScimFilters.displayNameEq(filter);
        if (displayNameEq != null) {
            all = all.stream().filter(g -> displayNameEq.equalsIgnoreCase(g.name())).toList();
        }
        final int total = all.size();
        final int start = startIndex == null || startIndex < 1 ? 1 : startIndex;
        final int size = count == null || count < 0 ? DEFAULT_COUNT : count;
        final int from = Math.min(start - 1, total);
        final int to = Math.min(from + size, total);
        final String base = ScimSupport.baseUrl();
        final List<ScimGroup> page = all.subList(from, to).stream()
                .map(g -> ScimMapper.toScimGroup(g, base, members(realm, g.groupId(), base))).toList();
        return scim(HttpStatus.OK, ScimListResponse.of(page, total, start));
    }

    @GetMapping(value = "/scim/v2/Groups/{id}", produces = SCIM_JSON)
    public ResponseEntity<?> get(@PathVariable final String id, final HttpServletRequest request) {
        final String realm = RealmContextHolder.get();
        final ResponseEntity<?> denied = authorize(realm, request);
        if (denied != null) {
            return denied;
        }
        final GroupDto group = find(realm, id);
        if (group == null) {
            return scim(HttpStatus.NOT_FOUND, ScimError.of(404, "Group " + id + " not found."));
        }
        final String base = ScimSupport.baseUrl();
        return scim(HttpStatus.OK, ScimMapper.toScimGroup(group, base, members(realm, id, base)));
    }

    @PostMapping(value = "/scim/v2/Groups", consumes = MediaType.ALL_VALUE, produces = SCIM_JSON)
    public ResponseEntity<?> create(@RequestBody final ScimGroup body, final HttpServletRequest request) {
        final String realm = RealmContextHolder.get();
        final ResponseEntity<?> denied = authorize(realm, request);
        if (denied != null) {
            return denied;
        }
        if (body == null || body.displayName() == null || body.displayName().isBlank()) {
            return scim(HttpStatus.BAD_REQUEST, ScimError.of(400, "invalidValue", "displayName is required."));
        }
        final GroupDto saved = groups.create(new GroupWriteDto(realm, null, body.displayName(), null));
        if (saved == null) {
            return scim(HttpStatus.CONFLICT, ScimError.of(409, "uniqueness", "Group already exists."));
        }
        applyMembers(realm, saved.groupId(), body.members());
        final String base = ScimSupport.baseUrl();
        return scim(HttpStatus.CREATED, ScimMapper.toScimGroup(saved, base, members(realm, saved.groupId(), base)));
    }

    @PutMapping(value = "/scim/v2/Groups/{id}", consumes = MediaType.ALL_VALUE, produces = SCIM_JSON)
    public ResponseEntity<?> replace(@PathVariable final String id, @RequestBody final ScimGroup body,
                                     final HttpServletRequest request) {
        final String realm = RealmContextHolder.get();
        final ResponseEntity<?> denied = authorize(realm, request);
        if (denied != null) {
            return denied;
        }
        final GroupDto saved = groups.update(new GroupWriteDto(realm, id, body.displayName(), null));
        if (saved == null) {
            return scim(HttpStatus.NOT_FOUND, ScimError.of(404, "Group " + id + " not found."));
        }
        replaceMembers(realm, id, body.members());
        final String base = ScimSupport.baseUrl();
        return scim(HttpStatus.OK, ScimMapper.toScimGroup(saved, base, members(realm, id, base)));
    }

    @PatchMapping(value = "/scim/v2/Groups/{id}", consumes = MediaType.ALL_VALUE, produces = SCIM_JSON)
    public ResponseEntity<?> patch(@PathVariable final String id, @RequestBody final ScimPatchOp patch,
                                   final HttpServletRequest request) {
        final String realm = RealmContextHolder.get();
        final ResponseEntity<?> denied = authorize(realm, request);
        if (denied != null) {
            return denied;
        }
        final GroupDto group = find(realm, id);
        if (group == null) {
            return scim(HttpStatus.NOT_FOUND, ScimError.of(404, "Group " + id + " not found."));
        }
        // Member add/remove PATCH (the common Azure-AD shape: op=add/remove, path="members").
        if (patch != null && patch.Operations() != null) {
            for (final ScimPatchOp.Operation op : patch.Operations()) {
                if (op.path() != null && op.path().toLowerCase().startsWith("members")
                        && op.value() instanceof List<?> refs) {
                    for (final Object ref : refs) {
                        final String userId = refValue(ref);
                        if (userId == null) {
                            continue;
                        }
                        if ("remove".equalsIgnoreCase(op.op())) {
                            groups.removeMember(new GroupRef(realm, id, userId, null));
                        } else {
                            groups.addMember(new GroupRef(realm, id, userId, null));
                        }
                    }
                }
            }
        }
        final String base = ScimSupport.baseUrl();
        return scim(HttpStatus.OK, ScimMapper.toScimGroup(group, base, members(realm, id, base)));
    }

    @DeleteMapping(value = "/scim/v2/Groups/{id}", produces = SCIM_JSON)
    public ResponseEntity<?> delete(@PathVariable final String id, final HttpServletRequest request) {
        final String realm = RealmContextHolder.get();
        final ResponseEntity<?> denied = authorize(realm, request);
        if (denied != null) {
            return denied;
        }
        final boolean removed = Boolean.TRUE.equals(groups.delete(new GroupRef(realm, id, null, null)));
        if (!removed) {
            return scim(HttpStatus.NOT_FOUND, ScimError.of(404, "Group " + id + " not found."));
        }
        return ResponseEntity.noContent().build();
    }

    private GroupDto find(final String realm, final String id) {
        return groups.list(realm).stream().filter(g -> id.equals(g.groupId())).findFirst().orElse(null);
    }

    private List<ScimUser.Ref> members(final String realm, final String groupId, final String base) {
        return groups.members(new GroupRef(realm, groupId, null, null)).stream()
                .map(m -> new ScimUser.Ref(m.userId(), m.username())).toList();
    }

    private void applyMembers(final String realm, final String groupId, final List<ScimUser.Ref> refs) {
        if (refs == null) {
            return;
        }
        for (final ScimUser.Ref ref : refs) {
            if (ref.value() != null) {
                groups.addMember(new GroupRef(realm, groupId, ref.value(), null));
            }
        }
    }

    private void replaceMembers(final String realm, final String groupId, final List<ScimUser.Ref> refs) {
        for (final GroupMemberDto existing : groups.members(new GroupRef(realm, groupId, null, null))) {
            groups.removeMember(new GroupRef(realm, groupId, existing.userId(), null));
        }
        applyMembers(realm, groupId, refs);
    }

    private static String refValue(final Object ref) {
        if (ref instanceof java.util.Map<?, ?> map) {
            final Object value = map.get("value");
            return value == null ? null : String.valueOf(value);
        }
        return null;
    }

    private ResponseEntity<?> authorize(final String realm, final HttpServletRequest request) {
        if (realm == null) {
            return scim(HttpStatus.NOT_FOUND, ScimError.of(404, "Unknown realm."));
        }
        final String token = ScimSupport.bearerToken(request);
        if (token == null) {
            return scim(HttpStatus.UNAUTHORIZED, ScimError.of(401, "Missing or malformed Bearer token."));
        }
        if (!Boolean.TRUE.equals(provisioning.verifyScimToken(new ScimTokenCheck(realm, token)))) {
            return scim(HttpStatus.UNAUTHORIZED, ScimError.of(401, "Invalid SCIM token."));
        }
        return null;
    }

    private static ResponseEntity<Object> scim(final HttpStatus status, final Object body) {
        return ResponseEntity.status(status).header("Content-Type", SCIM_JSON).body(body);
    }
}
