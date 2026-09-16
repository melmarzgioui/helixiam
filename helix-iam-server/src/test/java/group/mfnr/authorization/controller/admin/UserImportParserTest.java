package group.mfnr.authorization.controller.admin;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Helix IAM B10: bulk user import. {@link UserImportParser} turns a pasted/uploaded CSV (or JSON array)
 * into validated import rows — the input to the admin import endpoint. Pure + unit-testable.
 */
class UserImportParserTest {

    @Test
    void parsesCsvWithAHeaderAndMapsNameColumnsToAttributes() {
        final String csv = "username,email,enabled,firstName,lastName\n"
                + "ada,ada@x.io,true,Ada,Lovelace\n"
                + "grace,grace@x.io,false,Grace,Hopper\n";

        final List<UserImportParser.Row> rows = UserImportParser.parse(csv);

        assertThat(rows).hasSize(2);
        assertThat(rows.get(0).username()).isEqualTo("ada");
        assertThat(rows.get(0).email()).isEqualTo("ada@x.io");
        assertThat(rows.get(0).enabled()).isTrue();
        assertThat(rows.get(0).attributes()).containsEntry("firstName", "Ada").containsEntry("lastName", "Lovelace");
        assertThat(rows.get(1).enabled()).isFalse();
    }

    @Test
    void csvHeaderOrderIsIgnoredAndUnknownColumnsBecomeAttributes() {
        final String csv = "email,username,department\n"
                + "bob@x.io,bob,Engineering\n";

        final List<UserImportParser.Row> rows = UserImportParser.parse(csv);

        assertThat(rows).hasSize(1);
        assertThat(rows.get(0).username()).isEqualTo("bob");
        assertThat(rows.get(0).email()).isEqualTo("bob@x.io");
        assertThat(rows.get(0).attributes()).containsEntry("department", "Engineering");
        assertThat(rows.get(0).enabled()).isTrue(); // default when absent
    }

    @Test
    void parsesAJsonArrayOfUserObjects() {
        final String json = "[{\"username\":\"ada\",\"email\":\"ada@x.io\",\"enabled\":false,"
                + "\"password\":\"Secret123456!\",\"attributes\":{\"firstName\":\"Ada\"}}]";

        final List<UserImportParser.Row> rows = UserImportParser.parse(json);

        assertThat(rows).hasSize(1);
        assertThat(rows.get(0).username()).isEqualTo("ada");
        assertThat(rows.get(0).enabled()).isFalse();
        assertThat(rows.get(0).password()).isEqualTo("Secret123456!");
        assertThat(rows.get(0).attributes()).containsEntry("firstName", "Ada");
    }

    @Test
    void skipsBlankLinesAndTrimsValues() {
        final String csv = "username,email\n\n  ada , ada@x.io \n\n";

        final List<UserImportParser.Row> rows = UserImportParser.parse(csv);

        assertThat(rows).hasSize(1);
        assertThat(rows.get(0).username()).isEqualTo("ada");
        assertThat(rows.get(0).email()).isEqualTo("ada@x.io");
    }

    @Test
    void rejectsRowsWithNoUsername() {
        assertThatThrownBy(() -> UserImportParser.parse("username,email\n,nobody@x.io\n"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("username");
    }

    @Test
    void rejectsEmptyOrBlankInput() {
        assertThatThrownBy(() -> UserImportParser.parse("   ")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> UserImportParser.parse("username,email\n")).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("No users");
    }
}
