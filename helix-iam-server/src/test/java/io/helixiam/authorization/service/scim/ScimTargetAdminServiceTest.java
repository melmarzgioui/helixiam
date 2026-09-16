package io.helixiam.authorization.service.scim;

import io.helixiam.authorization.domain.scim.ScimTarget;
import io.helixiam.authorization.domain.scim.ScimTargetDto;
import io.helixiam.authorization.repository.scim.ScimTargetRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Helix IAM B7: outbound SCIM target CRUD + the write-only-token rule. */
class ScimTargetAdminServiceTest {

    private final ScimTargetRepository repo = mock(ScimTargetRepository.class);
    private final ScimTargetAdminService service = new ScimTargetAdminService(repo);

    private ScimTargetDto dto(final String id, final String token) {
        return new ScimTargetDto(id, "master", "Slack", "https://api.slack.example/scim/v2", token, false,
                "USER_CREATE,USER_UPDATE,USER_DELETE", true, null);
    }

    @Test
    void save_createsWhenIdBlank_andPersistsTheToken() {
        when(repo.save(any(ScimTarget.class))).thenAnswer(i -> i.getArgument(0));

        service.save(dto(null, "bearer-xyz"));

        final ArgumentCaptor<ScimTarget> c = ArgumentCaptor.forClass(ScimTarget.class);
        verify(repo).save(c.capture());
        assertThat(c.getValue().getId()).isNotBlank();
        assertThat(c.getValue().getBaseUrl()).isEqualTo("https://api.slack.example/scim/v2");
        assertThat(c.getValue().getToken()).isEqualTo("bearer-xyz");
        assertThat(c.getValue().getEventTypes()).isEqualTo("USER_CREATE,USER_UPDATE,USER_DELETE");
        assertThat(c.getValue().isEnabled()).isTrue();
    }

    @Test
    void save_withBlankTokenOnUpdate_keepsTheStoredToken() {
        final ScimTarget existing = new ScimTarget();
        existing.setId("t1"); existing.setRealmId("master"); existing.setToken("original-bearer");
        when(repo.findById("t1")).thenReturn(Optional.of(existing));
        when(repo.save(any(ScimTarget.class))).thenAnswer(i -> i.getArgument(0));

        service.save(dto("t1", "")); // blank token on edit

        final ArgumentCaptor<ScimTarget> c = ArgumentCaptor.forClass(ScimTarget.class);
        verify(repo).save(c.capture());
        assertThat(c.getValue().getToken()).isEqualTo("original-bearer"); // preserved
    }

    @Test
    void active_returnsOnlyEnabled_mappedToDtoCarryingTheToken() {
        final ScimTarget t = new ScimTarget();
        t.setId("t1"); t.setRealmId("master"); t.setBaseUrl("https://x"); t.setToken("tok"); t.setEnabled(true);
        when(repo.findAllByRealmIdAndEnabledTrue("master")).thenReturn(List.of(t));

        final List<ScimTargetDto> active = service.active("master");

        assertThat(active).hasSize(1);
        assertThat(active.get(0).tokenSet()).isTrue();
        assertThat(active.get(0).token()).isEqualTo("tok"); // dispatcher needs it to authenticate
    }

    @Test
    void delete_onlyWithinItsRealm() {
        final ScimTarget t = new ScimTarget();
        t.setId("t1"); t.setRealmId("master");
        when(repo.findById("t1")).thenReturn(Optional.of(t));

        assertThat(service.delete("other", "t1")).isFalse();
        verify(repo, never()).delete(any());
        assertThat(service.delete("master", "t1")).isTrue();
        verify(repo).delete(t);
    }
}
