/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.account;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * B1: what the realm's account console lets a signed-in user do on their own. Served by
 * {@code GET/PUT /admin/realms/{realm}/settings/account-console} and carried in the realm export as
 * {@code accountConsole}. A field left out of a PUT or an import keeps its default (see {@link #DEFAULTS}).
 *
 * @param allowAuthenticatorRemoval the user may remove their authenticator app (never when the realm requires MFA)
 * @param allowDataExport           the user may download their own data (GDPR Art. 15/20)
 * @param allowAccountDeletion      the user may delete their own account
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AccountConsoleSettings(Boolean allowAuthenticatorRemoval, Boolean allowDataExport,
                                     Boolean allowAccountDeletion) {

    /** A realm that never set anything: removal and export allowed (as the account API always did), deletion off. */
    public static final AccountConsoleSettings DEFAULTS = new AccountConsoleSettings(true, true, false);

    /** This value with every missing field taken from {@link #DEFAULTS}. */
    public AccountConsoleSettings withDefaults() {
        return new AccountConsoleSettings(
                allowAuthenticatorRemoval == null ? DEFAULTS.allowAuthenticatorRemoval : allowAuthenticatorRemoval,
                allowDataExport == null ? DEFAULTS.allowDataExport : allowDataExport,
                allowAccountDeletion == null ? DEFAULTS.allowAccountDeletion : allowAccountDeletion);
    }

    public boolean authenticatorRemoval() {
        return Boolean.TRUE.equals(withDefaults().allowAuthenticatorRemoval);
    }

    public boolean dataExport() {
        return Boolean.TRUE.equals(withDefaults().allowDataExport);
    }

    public boolean accountDeletion() {
        return Boolean.TRUE.equals(withDefaults().allowAccountDeletion);
    }
}
