package group.mfnr.authorization.idp.scim;

import group.mfnr.authorization.amqp.user.UserAdminDto;
import group.mfnr.authorization.amqp.user.UserWriteDto;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E7 (SCIM 2.0): the pure SCIM↔Helix mapping — userName / name.* / primary email / active are
 * carried both ways, {@code active} defaults to true when absent, and PATCH replace toggles enabled.
 */
class ScimMapperTest {

    @Test
    void toWrite_mapsUserNameNameEmailAndActive() {
        final ScimUser user = new ScimUser(List.of(ScimSchemas.USER), null, "jdoe",
                new ScimUser.Name("Jane", "Doe", null),
                List.of(new ScimUser.Email("jane@example.com", "work", true)), true, null, null);

        final UserWriteDto write = ScimMapper.toWrite("gov", null, user, "secret");

        assertThat(write.realmId()).isEqualTo("gov");
        assertThat(write.userId()).isNull();
        assertThat(write.username()).isEqualTo("jdoe");
        assertThat(write.email()).isEqualTo("jane@example.com");
        assertThat(write.enabled()).isTrue();
        assertThat(write.password()).isEqualTo("secret");
        assertThat(write.attributes())
                .containsEntry(ScimMapper.ATTR_GIVEN_NAME, "Jane")
                .containsEntry(ScimMapper.ATTR_FAMILY_NAME, "Doe");
    }

    @Test
    void toWrite_activeDefaultsToTrue_whenAbsent() {
        final ScimUser user = new ScimUser(List.of(ScimSchemas.USER), null, "jdoe", null, null, null, null, null);

        assertThat(ScimMapper.toWrite("gov", null, user, null).enabled()).isTrue();
    }

    @Test
    void primaryEmail_prefersPrimaryThenFirst() {
        final ScimUser user = new ScimUser(null, null, "u", null, List.of(
                new ScimUser.Email("alt@example.com", "home", false),
                new ScimUser.Email("primary@example.com", "work", true)), null, null, null);

        assertThat(ScimMapper.primaryEmail(user)).isEqualTo("primary@example.com");
    }

    @Test
    void toScimUser_roundTripsNameEmailAndActive() {
        final UserAdminDto user = new UserAdminDto("gov", "uid-1", "jdoe", "jane@example.com", true, false, false,
                List.of(), Map.of(ScimMapper.ATTR_GIVEN_NAME, "Jane", ScimMapper.ATTR_FAMILY_NAME, "Doe"), 1000L);

        final ScimUser scim = ScimMapper.toScimUser(user, "https://idp/realms/gov/scim/v2");

        assertThat(scim.id()).isEqualTo("uid-1");
        assertThat(scim.userName()).isEqualTo("jdoe");
        assertThat(scim.active()).isTrue();
        assertThat(scim.name().givenName()).isEqualTo("Jane");
        assertThat(scim.name().familyName()).isEqualTo("Doe");
        assertThat(scim.emails()).singleElement().satisfies(e -> {
            assertThat(e.value()).isEqualTo("jane@example.com");
            assertThat(e.primary()).isTrue();
        });
        assertThat(scim.meta().location()).isEqualTo("https://idp/realms/gov/scim/v2/Users/uid-1");
        assertThat(scim.schemas()).containsExactly(ScimSchemas.USER);
    }

    @Test
    void applyPatch_replaceActive_disablesUser() {
        final UserAdminDto current = new UserAdminDto("gov", "uid-1", "jdoe", "j@e.com", true, false, false,
                List.of(), Map.of(), 0L);
        final ScimPatchOp patch = new ScimPatchOp(List.of(ScimSchemas.PATCH_OP),
                List.of(new ScimPatchOp.Operation("replace", "active", false)));

        final UserWriteDto write = ScimMapper.applyPatch(current, patch, "gov");

        assertThat(write.enabled()).isFalse();
        assertThat(write.userId()).isEqualTo("uid-1");
        assertThat(write.username()).isEqualTo("jdoe");
    }
}
