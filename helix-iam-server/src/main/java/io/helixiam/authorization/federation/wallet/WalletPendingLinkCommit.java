/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.FederatedLoginCommit;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Optional;

/**
 * Task 18: commits the wallet's upgrade link ({@link WalletLinkService.PendingLink}, from
 * {@link WalletLinkService#decide}) once the wallet login has fully succeeded, post-broker flow and step-up included.
 * The login may complete only when the number now belongs to the user being signed in: if another account claimed it
 * between the decision and now, the number wins and this login is refused (spec decision: the number is the stronger
 * subject). Anything that is not a pending link of this user is refused (fail closed).
 */
@Component
public class WalletPendingLinkCommit implements FederatedLoginCommit {

    private static final Logger LOG = LogManager.getLogger(WalletPendingLinkCommit.class);

    private final WalletLinkService links;

    public WalletPendingLinkCommit(final WalletLinkService links) {
        this.links = links;
    }

    @Override
    public boolean commit(final Serializable pending, final String userId) {
        if (!(pending instanceof WalletLinkService.PendingLink link) || userId == null
                || !userId.equals(link.userId())) {
            return false;
        }
        final Optional<String> owner = links.commitPendingLink(link);
        if (owner.isPresent() && owner.get().equals(userId)) {
            return true;
        }
        LOG.warn("wallet: upgrade link not committed, login refused: realm={} alias={} user={}",
                LogSafe.sanitize(link.realmId()), LogSafe.sanitize(link.alias()), LogSafe.sanitize(userId));
        return false;
    }
}
