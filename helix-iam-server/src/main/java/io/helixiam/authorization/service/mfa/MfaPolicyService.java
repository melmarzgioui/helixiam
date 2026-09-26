/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.mfa;

import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.repository.realm.RealmConfigRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * 1.0 item 6: the realm's two-step sign-in policy, read straight from {@code realm_config} at sign-in (no cache,
 * so a change applies to the next sign-in).
 *
 * <ul>
 *   <li><b>Required</b>: the realm's {@code requireMfa}, or the deployment-wide {@code mfa.enabled} switch.</li>
 *   <li><b>Skip grace</b>: enrolment may be skipped only while the account is younger than the realm's
 *       {@code mfaSkipGraceDays}; 0 (the default) means never.</li>
 *   <li><b>Issuer</b>: the realm display name, used as the otpauth issuer and label prefix.</li>
 * </ul>
 */
@Service
public class MfaPolicyService {

    private final RealmConfigRepository realms;
    private final boolean mfaRequiredEverywhere;

    public MfaPolicyService(final RealmConfigRepository realms,
                            @Value("${mfa.enabled:true}") final boolean mfaRequiredEverywhere) {
        this.realms = realms;
        this.mfaRequiredEverywhere = mfaRequiredEverywhere;
    }

    @Transactional(readOnly = true)
    public boolean required(final String realmId) {
        return mfaRequiredEverywhere || realm(realmId).map(RealmConfig::isRequireMfa).orElse(false);
    }

    @Transactional(readOnly = true)
    public int skipGraceDays(final String realmId) {
        return realm(realmId).map(RealmConfig::getMfaSkipGraceDays).orElse(0);
    }

    /** True when an account created at {@code createdAt} may still skip enrolment in this realm. */
    public boolean maySkip(final String realmId, final Date createdAt) {
        final int days = skipGraceDays(realmId);
        return days > 0 && createdAt != null
                && System.currentTimeMillis() - createdAt.getTime() < TimeUnit.DAYS.toMillis(days);
    }

    @Transactional(readOnly = true)
    public String issuer(final String realmId) {
        return realm(realmId).map(RealmConfig::getDisplayName).filter(n -> n != null && !n.isBlank())
                .orElse(realmId == null ? "HelixIAM" : realmId);
    }

    /** Updates the given fields (null = unchanged). Empty when the realm does not exist. */
    @Transactional
    public Optional<Policy> update(final String realmId, final Boolean requireMfa, final Integer skipGraceDays) {
        return realm(realmId).map(cfg -> {
            if (requireMfa != null) {
                cfg.setRequireMfa(requireMfa);
            }
            if (skipGraceDays != null) {
                cfg.setMfaSkipGraceDays(skipGraceDays);
            }
            realms.save(cfg);
            return new Policy(cfg.isRequireMfa(), cfg.getMfaSkipGraceDays());
        });
    }

    @Transactional(readOnly = true)
    public Optional<Policy> get(final String realmId) {
        return realm(realmId).map(cfg -> new Policy(cfg.isRequireMfa(), cfg.getMfaSkipGraceDays()));
    }

    private Optional<RealmConfig> realm(final String realmId) {
        return realmId == null ? Optional.empty() : realms.findById(realmId);
    }

    public record Policy(boolean requireMfa, int skipGraceDays) {
    }
}
