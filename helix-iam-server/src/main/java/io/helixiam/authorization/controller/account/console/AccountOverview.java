/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.account.console;

import java.util.List;

/**
 * B1: what the account console's overview shows. Every value is the signed-in user's own, in the realm of the request.
 *
 * @param profile  name, username and email (with whether it is verified)
 * @param twoStep  the authenticator app and recovery codes
 * @param sessions this browser first, then the user's other sign-ins in this realm
 * @param canExport the realm lets users download their data
 * @param canDelete the realm lets users delete their account
 */
public record AccountOverview(Profile profile, TwoStep twoStep, List<SessionRow> sessions, boolean canExport,
                              boolean canDelete) {

    /** Profile values; null when not set. */
    public record Profile(String username, String email, boolean emailVerified, String givenName, String familyName,
                          String phone) {

        /** "Ada Lovelace", the username when no name is set. */
        public String displayName() {
            final String name = ((givenName == null ? "" : givenName) + " " + (familyName == null ? "" : familyName)).trim();
            return name.isEmpty() ? username : name;
        }
    }

    /**
     * @param enrolled          an authenticator app is set up
     * @param required          the realm requires two-step verification
     * @param canRemove         the realm lets the user remove it (and does not require it)
     * @param recoveryCodesLeft unused recovery codes
     */
    public record TwoStep(boolean enrolled, boolean required, boolean canRemove, int recoveryCodesLeft) {
    }

    /**
     * One browser sign-in.
     *
     * @param current  this browser
     * @param signedIn when it signed in, formatted (UTC), or null
     * @param apps     the applications it signed in to (client ids)
     */
    public record SessionRow(boolean current, String signedIn, List<String> apps) {
    }
}
