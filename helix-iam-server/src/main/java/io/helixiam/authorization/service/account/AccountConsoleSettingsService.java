/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.account;

import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.repository.realm.RealmConfigRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

/** B1: reads and stores a realm's {@link AccountConsoleSettings} (columns on {@code realm_config}). */
@Service
public class AccountConsoleSettingsService {

    private final RealmConfigRepository realms;

    public AccountConsoleSettingsService(final RealmConfigRepository realms) {
        this.realms = realms;
    }

    /** The realm's settings; {@link AccountConsoleSettings#DEFAULTS} for an unknown realm. */
    @Transactional(readOnly = true)
    public AccountConsoleSettings get(final String realmId) {
        return find(realmId).orElse(AccountConsoleSettings.DEFAULTS);
    }

    /** The realm's settings, empty when the realm does not exist. */
    @Transactional(readOnly = true)
    public Optional<AccountConsoleSettings> find(final String realmId) {
        return realmId == null ? Optional.empty() : realms.findById(realmId).map(AccountConsoleSettingsService::of);
    }

    /** Stores {@code settings} (missing fields take their defaults); empty when the realm does not exist. */
    @Transactional
    public Optional<AccountConsoleSettings> replace(final String realmId, final AccountConsoleSettings settings) {
        final AccountConsoleSettings s = (settings == null ? AccountConsoleSettings.DEFAULTS : settings).withDefaults();
        return realms.findById(realmId).map(cfg -> {
            cfg.setAccountAllowAuthenticatorRemoval(s.allowAuthenticatorRemoval());
            cfg.setAccountAllowDataExport(s.allowDataExport());
            cfg.setAccountAllowDeletion(s.allowAccountDeletion());
            return of(realms.save(cfg));
        });
    }

    static AccountConsoleSettings of(final RealmConfig cfg) {
        return new AccountConsoleSettings(cfg.isAccountAllowAuthenticatorRemoval(), cfg.isAccountAllowDataExport(),
                cfg.isAccountAllowDeletion());
    }
}
