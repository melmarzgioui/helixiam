package io.helixiam.authorization.service.webhook;

import io.helixiam.authorization.domain.webhook.WebhookSubscription;
import io.helixiam.authorization.domain.webhook.WebhookSubscriptionDto;
import io.helixiam.authorization.repository.webhook.WebhookSubscriptionRepository;
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

/** Helix IAM B6: outbound webhook CRUD + the write-only-secret rule. */
class WebhookAdminServiceTest {

    private final WebhookSubscriptionRepository repo = mock(WebhookSubscriptionRepository.class);
    private final WebhookAdminService service = new WebhookAdminService(repo);

    private WebhookSubscriptionDto dto(final String id, final String secret) {
        return new WebhookSubscriptionDto(id, "master", "SIEM", "https://hooks.example/x", secret, false,
                "LOGIN_SUCCESS,LOGIN_FAILURE", true, null);
    }

    @Test
    void save_createsWhenIdBlank_andPersistsTheSecret() {
        when(repo.save(any(WebhookSubscription.class))).thenAnswer(i -> i.getArgument(0));

        service.save(dto(null, "shh-secret"));

        final ArgumentCaptor<WebhookSubscription> c = ArgumentCaptor.forClass(WebhookSubscription.class);
        verify(repo).save(c.capture());
        assertThat(c.getValue().getId()).isNotBlank();
        assertThat(c.getValue().getUrl()).isEqualTo("https://hooks.example/x");
        assertThat(c.getValue().getSecret()).isEqualTo("shh-secret");
        assertThat(c.getValue().getEventTypes()).isEqualTo("LOGIN_SUCCESS,LOGIN_FAILURE");
        assertThat(c.getValue().isEnabled()).isTrue();
    }

    @Test
    void save_withBlankSecretOnUpdate_keepsTheStoredSecret() {
        final WebhookSubscription existing = new WebhookSubscription();
        existing.setId("w1"); existing.setRealmId("master"); existing.setSecret("original");
        when(repo.findById("w1")).thenReturn(Optional.of(existing));
        when(repo.save(any(WebhookSubscription.class))).thenAnswer(i -> i.getArgument(0));

        service.save(dto("w1", "")); // blank secret on edit

        final ArgumentCaptor<WebhookSubscription> c = ArgumentCaptor.forClass(WebhookSubscription.class);
        verify(repo).save(c.capture());
        assertThat(c.getValue().getSecret()).isEqualTo("original"); // preserved
    }

    @Test
    void active_returnsOnlyEnabled_mappedToDto() {
        final WebhookSubscription w = new WebhookSubscription();
        w.setId("w1"); w.setRealmId("master"); w.setUrl("https://h"); w.setSecret("s"); w.setEnabled(true);
        when(repo.findAllByRealmIdAndEnabledTrue("master")).thenReturn(List.of(w));

        final List<WebhookSubscriptionDto> active = service.active("master");

        assertThat(active).hasSize(1);
        assertThat(active.get(0).secretSet()).isTrue();
        assertThat(active.get(0).secret()).isEqualTo("s"); // dispatcher needs it to sign
    }

    @Test
    void delete_onlyWithinItsRealm() {
        final WebhookSubscription w = new WebhookSubscription();
        w.setId("w1"); w.setRealmId("master");
        when(repo.findById("w1")).thenReturn(Optional.of(w));

        assertThat(service.delete("other", "w1")).isFalse();
        verify(repo, never()).delete(any());
        assertThat(service.delete("master", "w1")).isTrue();
        verify(repo).delete(w);
    }
}
