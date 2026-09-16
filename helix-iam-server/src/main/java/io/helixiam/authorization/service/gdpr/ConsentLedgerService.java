package io.helixiam.authorization.service.gdpr;

import io.helixiam.authorization.domain.gdpr.ConsentLedgerEntity;
import io.helixiam.authorization.domain.gdpr.GdprConsentRecordDto;
import io.helixiam.authorization.domain.gdpr.GdprConsentWithdrawDto;
import io.helixiam.authorization.domain.gdpr.GdprConsentWriteDto;
import io.helixiam.authorization.repository.gdpr.ConsentLedgerRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Helix IAM GDPR Art. 7: the consent ledger — records per-user, per-client consent grants and withdrawals.
 * Grants append an immutable row; withdrawals stamp {@code withdrawn_at} on the still-active rows for that
 * client (the rows are never deleted, so the consent history survives for audit). Read by both the admin
 * and account consoles; withdrawal is offered as account self-service.
 */
@Service
public class ConsentLedgerService {

    private static final Logger LOG = LogManager.getLogger(ConsentLedgerService.class);

    private final ConsentLedgerRepository repository;

    public ConsentLedgerService(final ConsentLedgerRepository repository) {
        this.repository = repository;
    }

    /** Record a consent grant; returns the persisted ledger row. */
    @Transactional
    public GdprConsentRecordDto record(final GdprConsentWriteDto write) {
        final String scopes = write.scopes() == null ? "" : String.join(",", write.scopes());
        final ConsentLedgerEntity saved = repository.save(
                new ConsentLedgerEntity(write.realmId(), write.userId(), write.clientId(), scopes));
        LOG.debug("Recorded consent grant for user {} client {} in realm {}",
                write.userId(), write.clientId(), write.realmId());
        return toDto(saved);
    }

    /** The full consent ledger for a user in a realm, newest grant first. */
    public List<GdprConsentRecordDto> list(final String realmId, final String userId) {
        return repository.findAllByRealmIdAndUserIdOrderByGrantedAtDesc(realmId, userId).stream()
                .map(ConsentLedgerService::toDto)
                .toList();
    }

    /**
     * Withdraw a user's consent for one client: stamps {@code withdrawn_at} on every still-active row.
     * Returns {@code false} when there was no active consent to withdraw.
     */
    @Transactional
    public boolean withdraw(final GdprConsentWithdrawDto withdraw) {
        final List<ConsentLedgerEntity> active = repository
                .findAllByRealmIdAndUserIdAndClientIdAndWithdrawnAtIsNull(
                        withdraw.realmId(), withdraw.userId(), withdraw.clientId());
        if (active.isEmpty()) {
            return false;
        }
        final Date now = new Date();
        active.forEach(row -> row.setWithdrawnAt(now));
        repository.saveAll(active);
        LOG.debug("Withdrew {} consent row(s) for user {} client {} in realm {}",
                active.size(), withdraw.userId(), withdraw.clientId(), withdraw.realmId());
        return true;
    }

    static GdprConsentRecordDto toDto(final ConsentLedgerEntity e) {
        final List<String> scopes = e.getScopes() == null || e.getScopes().isBlank() ? List.of()
                : Arrays.stream(e.getScopes().split(",")).map(String::trim).filter(s -> !s.isEmpty())
                        .collect(Collectors.toList());
        return new GdprConsentRecordDto(e.getId(), e.getRealmId(), e.getUserId(), e.getClientId(), scopes,
                e.getGrantedAt() == null ? null : e.getGrantedAt().getTime(),
                e.getWithdrawnAt() == null ? null : e.getWithdrawnAt().getTime());
    }
}
