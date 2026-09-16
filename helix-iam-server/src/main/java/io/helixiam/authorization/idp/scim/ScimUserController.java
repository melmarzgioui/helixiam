package io.helixiam.authorization.idp.scim;

import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.amqp.user.UserAdminRef;
import io.helixiam.authorization.amqp.user.UserWriteDto;
import io.helixiam.authorization.idp.provisioning.ProvisioningAdminPublisher;
import io.helixiam.authorization.idp.provisioning.ScimTokenCheck;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import java.util.UUID;

/**
 * Helix IAM E7 (SCIM 2.0): inbound provisioning of Users INTO Helix (RFC 7643/7644). Served per realm at
 * {@code /realms/{realm}/scim/v2/Users} — the realm comes from the {@code RealmRoutingFilter} context, the
 * servlet path is the flat {@code /scim/v2/Users}. Maps SCIM Users onto the Helix user model over the
 * existing {@link UserAdminPublisher} AMQP admin path. Authn is a per-realm Bearer SCIM token; every
 * endpoint returns a {@link ResponseEntity} (never throws — a thrown exception dispatches to {@code /error}
 * which Spring Security would turn into a 302 login redirect, breaking the SCIM client).
 */
@RestController
public class ScimUserController {

    private static final Logger LOG = LogManager.getLogger(ScimUserController.class);
    private static final String SCIM_JSON = "application/scim+json";
    private static final int DEFAULT_COUNT = 100;

    private final UserAdminPublisher users;
    private final ProvisioningAdminPublisher provisioning;

    public ScimUserController(final UserAdminPublisher users, final ProvisioningAdminPublisher provisioning) {
        this.users = users;
        this.provisioning = provisioning;
    }

    @GetMapping(value = "/scim/v2/Users", produces = SCIM_JSON)
    public ResponseEntity<?> list(@RequestParam(required = false) final String filter,
                                  @RequestParam(required = false) final Integer startIndex,
                                  @RequestParam(required = false) final Integer count,
                                  final HttpServletRequest request) {
        final String realm = RealmContextHolder.get();
        final ResponseEntity<?> denied = authorize(realm, request);
        if (denied != null) {
            return denied;
        }
        List<UserAdminDto> all = users.list(realm);
        final String userNameEq = ScimFilters.userNameEq(filter);
        if (userNameEq != null) {
            all = all.stream().filter(u -> userNameEq.equalsIgnoreCase(u.username())).toList();
        }
        final int total = all.size();
        final int start = startIndex == null || startIndex < 1 ? 1 : startIndex;
        final int size = count == null || count < 0 ? DEFAULT_COUNT : count;
        final int from = Math.min(start - 1, total);
        final int to = Math.min(from + size, total);
        final String base = ScimSupport.baseUrl();
        final List<ScimUser> page = all.subList(from, to).stream().map(u -> ScimMapper.toScimUser(u, base)).toList();
        return scim(HttpStatus.OK, ScimListResponse.of(page, total, start));
    }

    @GetMapping(value = "/scim/v2/Users/{id}", produces = SCIM_JSON)
    public ResponseEntity<?> get(@PathVariable final String id, final HttpServletRequest request) {
        final String realm = RealmContextHolder.get();
        final ResponseEntity<?> denied = authorize(realm, request);
        if (denied != null) {
            return denied;
        }
        final UserAdminDto user = users.get(new UserAdminRef(realm, id));
        if (user == null) {
            return scim(HttpStatus.NOT_FOUND, ScimError.of(404, "User " + id + " not found."));
        }
        return scim(HttpStatus.OK, ScimMapper.toScimUser(user, ScimSupport.baseUrl()));
    }

    @PostMapping(value = "/scim/v2/Users", consumes = MediaType.ALL_VALUE, produces = SCIM_JSON)
    public ResponseEntity<?> create(@RequestBody final ScimUser body, final HttpServletRequest request) {
        final String realm = RealmContextHolder.get();
        final ResponseEntity<?> denied = authorize(realm, request);
        if (denied != null) {
            return denied;
        }
        if (body == null || body.userName() == null || body.userName().isBlank()) {
            return scim(HttpStatus.BAD_REQUEST, ScimError.of(400, "invalidValue", "userName is required."));
        }
        // SCIM clients may not send a password; mint a strong random one so the account is provisioned but
        // unusable for direct password login until reset (provisioning-only accounts).
        final UserWriteDto write = ScimMapper.toWrite(realm, null, body, UUID.randomUUID().toString());
        final UserAdminDto saved = users.create(write);
        if (saved == null) {
            return scim(HttpStatus.CONFLICT, ScimError.of(409, "uniqueness", "userName already exists."));
        }
        return scim(HttpStatus.CREATED, ScimMapper.toScimUser(saved, ScimSupport.baseUrl()));
    }

    @PutMapping(value = "/scim/v2/Users/{id}", consumes = MediaType.ALL_VALUE, produces = SCIM_JSON)
    public ResponseEntity<?> replace(@PathVariable final String id, @RequestBody final ScimUser body,
                                     final HttpServletRequest request) {
        final String realm = RealmContextHolder.get();
        final ResponseEntity<?> denied = authorize(realm, request);
        if (denied != null) {
            return denied;
        }
        final UserAdminDto saved = users.update(ScimMapper.toWrite(realm, id, body, null));
        if (saved == null) {
            return scim(HttpStatus.NOT_FOUND, ScimError.of(404, "User " + id + " not found."));
        }
        return scim(HttpStatus.OK, ScimMapper.toScimUser(saved, ScimSupport.baseUrl()));
    }

    @PatchMapping(value = "/scim/v2/Users/{id}", consumes = MediaType.ALL_VALUE, produces = SCIM_JSON)
    public ResponseEntity<?> patch(@PathVariable final String id, @RequestBody final ScimPatchOp patch,
                                   final HttpServletRequest request) {
        final String realm = RealmContextHolder.get();
        final ResponseEntity<?> denied = authorize(realm, request);
        if (denied != null) {
            return denied;
        }
        final UserAdminDto current = users.get(new UserAdminRef(realm, id));
        if (current == null) {
            return scim(HttpStatus.NOT_FOUND, ScimError.of(404, "User " + id + " not found."));
        }
        final UserAdminDto saved = users.update(ScimMapper.applyPatch(current, patch, realm));
        if (saved == null) {
            return scim(HttpStatus.NOT_FOUND, ScimError.of(404, "User " + id + " not found."));
        }
        return scim(HttpStatus.OK, ScimMapper.toScimUser(saved, ScimSupport.baseUrl()));
    }

    @DeleteMapping(value = "/scim/v2/Users/{id}", produces = SCIM_JSON)
    public ResponseEntity<?> delete(@PathVariable final String id, final HttpServletRequest request) {
        final String realm = RealmContextHolder.get();
        final ResponseEntity<?> denied = authorize(realm, request);
        if (denied != null) {
            return denied;
        }
        final boolean removed = Boolean.TRUE.equals(users.delete(new UserAdminRef(realm, id)));
        if (!removed) {
            return scim(HttpStatus.NOT_FOUND, ScimError.of(404, "User " + id + " not found."));
        }
        return ResponseEntity.noContent().build();
    }

    /** {@code null} when authorized, else a 401/403 SCIM error response to return. */
    private ResponseEntity<?> authorize(final String realm, final HttpServletRequest request) {
        if (realm == null) {
            return scim(HttpStatus.NOT_FOUND, ScimError.of(404, "Unknown realm."));
        }
        final String token = ScimSupport.bearerToken(request);
        if (token == null) {
            return scim(HttpStatus.UNAUTHORIZED, ScimError.of(401, "Missing or malformed Bearer token."));
        }
        final boolean ok = Boolean.TRUE.equals(provisioning.verifyScimToken(new ScimTokenCheck(realm, token)));
        if (!ok) {
            LOG.debug("Rejected SCIM request for realm {} — invalid token", realm);
            return scim(HttpStatus.UNAUTHORIZED, ScimError.of(401, "Invalid SCIM token."));
        }
        return null;
    }

    private static ResponseEntity<Object> scim(final HttpStatus status, final Object body) {
        return ResponseEntity.status(status).header("Content-Type", SCIM_JSON).body(body);
    }
}
