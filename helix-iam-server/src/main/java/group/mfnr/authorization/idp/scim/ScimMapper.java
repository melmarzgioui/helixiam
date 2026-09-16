package group.mfnr.authorization.idp.scim;

import group.mfnr.authorization.amqp.group.GroupDto;
import group.mfnr.authorization.amqp.user.UserAdminDto;
import group.mfnr.authorization.amqp.user.UserWriteDto;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Helix IAM E7 (SCIM 2.0): pure mapping between SCIM resources (RFC 7643) and the Helix admin DTOs that
 * flow over the user / group AMQP admin paths. SCIM {@code name.*} and the primary {@code email} are
 * carried in / out via Helix user attributes ({@code givenName}, {@code familyName}); {@code active}
 * maps to the inverse of Helix {@code enabled=false} (a deactivated SCIM user is a disabled Helix user).
 */
public final class ScimMapper {

    public static final String ATTR_GIVEN_NAME = "givenName";
    public static final String ATTR_FAMILY_NAME = "familyName";

    private ScimMapper() {
    }

    /** Map an inbound SCIM User to a Helix user write payload. {@code userId} is null on create. */
    public static UserWriteDto toWrite(final String realmId, final String userId, final ScimUser user,
                                       final String password) {
        final Map<String, String> attributes = new LinkedHashMap<>();
        if (user.name() != null) {
            if (user.name().givenName() != null) {
                attributes.put(ATTR_GIVEN_NAME, user.name().givenName());
            }
            if (user.name().familyName() != null) {
                attributes.put(ATTR_FAMILY_NAME, user.name().familyName());
            }
        }
        // SCIM `active` defaults to true when absent (RFC 7643 §4.1.1).
        final boolean enabled = user.active() == null || user.active();
        return new UserWriteDto(realmId, userId, user.userName(), primaryEmail(user), password, enabled, false,
                attributes);
    }

    /** The primary (or first) email of a SCIM User, or {@code null}. */
    public static String primaryEmail(final ScimUser user) {
        if (user.emails() == null || user.emails().isEmpty()) {
            return null;
        }
        return user.emails().stream()
                .filter(e -> Boolean.TRUE.equals(e.primary()))
                .map(ScimUser.Email::value)
                .findFirst()
                .orElseGet(() -> user.emails().get(0).value());
    }

    /** Map a Helix user to a SCIM User resource. {@code baseUrl} is the realm SCIM base for {@code meta.location}. */
    public static ScimUser toScimUser(final UserAdminDto user, final String baseUrl) {
        final Map<String, String> attrs = user.attributes() == null ? Map.of() : user.attributes();
        final String given = attrs.get(ATTR_GIVEN_NAME);
        final String family = attrs.get(ATTR_FAMILY_NAME);
        final ScimUser.Name name = (given == null && family == null) ? null
                : new ScimUser.Name(given, family, joinName(given, family));
        final List<ScimUser.Email> emails = (user.email() == null || user.email().isBlank()) ? null
                : List.of(new ScimUser.Email(user.email(), "work", true));
        final String created = user.createdAt() == null ? null : Instant.ofEpochMilli(user.createdAt()).toString();
        final Meta meta = new Meta("User", baseUrl + "/Users/" + user.userId(), created, created);
        return new ScimUser(List.of(ScimSchemas.USER), user.userId(), user.username(), name, emails,
                user.enabled(), null, meta);
    }

    /** Map a Helix group to a SCIM Group resource. */
    public static ScimGroup toScimGroup(final GroupDto group, final String baseUrl, final List<ScimUser.Ref> members) {
        final Meta meta = new Meta("Group", baseUrl + "/Groups/" + group.groupId(), null, null);
        return new ScimGroup(List.of(ScimSchemas.GROUP), group.groupId(), group.name(),
                members == null ? List.of() : members, meta);
    }

    /** Apply a SCIM PATCH operation list to a Helix user, returning the next write payload. */
    public static UserWriteDto applyPatch(final UserAdminDto current, final ScimPatchOp patch, final String realmId) {
        boolean enabled = current.enabled();
        String username = current.username();
        String email = current.email();
        final Map<String, String> attributes = new LinkedHashMap<>(
                current.attributes() == null ? Map.of() : current.attributes());
        if (patch != null && patch.Operations() != null) {
            for (final ScimPatchOp.Operation op : patch.Operations()) {
                final String path = op.path() == null ? "" : op.path().toLowerCase();
                final Object value = op.value();
                switch (path) {
                    case "active" -> enabled = asBoolean(value, enabled);
                    case "username" -> username = asString(value, username);
                    case "name.givenname" -> put(attributes, ATTR_GIVEN_NAME, asString(value, null));
                    case "name.familyname" -> put(attributes, ATTR_FAMILY_NAME, asString(value, null));
                    case "emails", "emails[primary eq true].value" -> email = asString(value, email);
                    default -> { /* unsupported path — ignored (lenient, like Keycloak) */ }
                }
            }
        }
        return new UserWriteDto(realmId, current.userId(), username, email, null, enabled, current.locked(),
                attributes);
    }

    private static void put(final Map<String, String> attributes, final String key, final String value) {
        if (value != null) {
            attributes.put(key, value);
        }
    }

    private static boolean asBoolean(final Object value, final boolean fallback) {
        if (value instanceof Boolean b) {
            return b;
        }
        if (value instanceof String s) {
            return Boolean.parseBoolean(s);
        }
        return fallback;
    }

    private static String asString(final Object value, final String fallback) {
        return value == null ? fallback : String.valueOf(value);
    }

    private static String joinName(final String given, final String family) {
        final List<String> parts = new ArrayList<>();
        if (given != null) {
            parts.add(given);
        }
        if (family != null) {
            parts.add(family);
        }
        return parts.isEmpty() ? null : String.join(" ", parts);
    }
}
