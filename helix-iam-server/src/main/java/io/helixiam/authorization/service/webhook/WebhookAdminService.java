package io.helixiam.authorization.service.webhook;

import io.helixiam.authorization.domain.webhook.WebhookSubscription;
import io.helixiam.authorization.domain.webhook.WebhookSubscriptionDto;
import io.helixiam.authorization.repository.webhook.WebhookSubscriptionRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Helix IAM B6: CRUD + active-lookup for per-realm outbound webhook subscriptions. The {@code secret}
 * is write-only from the console's perspective — a blank secret on update preserves the stored one
 * (so editing other fields never wipes the HMAC key).
 */
@Service
public class WebhookAdminService {

    private final WebhookSubscriptionRepository repository;

    public WebhookAdminService(final WebhookSubscriptionRepository repository) {
        this.repository = repository;
    }

    @Transactional(readOnly = true)
    public List<WebhookSubscriptionDto> list(final String realmId) {
        return repository.findAllByRealmIdOrderByCreationDateAsc(realmId).stream()
                .map(WebhookSubscriptionDto::from).toList();
    }

    /** Enabled webhooks for a realm — what the publisher's dispatcher fans events out to. */
    @Transactional(readOnly = true)
    public List<WebhookSubscriptionDto> active(final String realmId) {
        return repository.findAllByRealmIdAndEnabledTrue(realmId).stream()
                .map(WebhookSubscriptionDto::from).toList();
    }

    @Transactional
    public WebhookSubscriptionDto save(final WebhookSubscriptionDto dto) {
        final WebhookSubscription entity = dto.id() == null || dto.id().isBlank()
                ? newEntity(dto.realmId())
                : repository.findById(dto.id()).orElseGet(() -> newEntity(dto.realmId()));
        entity.setRealmId(dto.realmId());
        entity.setName(blankToNull(dto.name()));
        entity.setUrl(dto.url() == null ? null : dto.url().trim());
        entity.setEventTypes(dto.eventTypes() == null ? "" : dto.eventTypes().trim());
        entity.setEnabled(dto.enabled());
        // Secret is write-only: only overwrite when a new non-blank value is supplied.
        if (dto.secret() != null && !dto.secret().isBlank()) {
            entity.setSecret(dto.secret().trim());
        }
        return WebhookSubscriptionDto.from(repository.save(entity));
    }

    @Transactional
    public boolean delete(final String realmId, final String id) {
        return repository.findById(id)
                .filter(w -> realmId.equals(w.getRealmId()))
                .map(w -> {
                    repository.delete(w);
                    return true;
                }).orElse(false);
    }

    private WebhookSubscription newEntity(final String realmId) {
        final WebhookSubscription w = new WebhookSubscription();
        w.setId(UUID.randomUUID().toString());
        w.setRealmId(realmId);
        return w;
    }

    private static String blankToNull(final String v) {
        return v == null || v.isBlank() ? null : v.trim();
    }
}
