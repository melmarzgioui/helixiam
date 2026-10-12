/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.dcql;

import io.helixiam.authorization.federation.wallet.VerifiedPresentation;

import java.util.List;
import java.util.Set;

/**
 * The verified presentations of a {@code vp_token} that satisfied its DCQL query, in query order, each holding only
 * the claims the query requested. {@code droppedClaimNames} names (never values) the claims that were disclosed but
 * not requested and were therefore removed.
 */
public record MatchedPresentations(List<VerifiedPresentation> presentations, Set<String> droppedClaimNames) {

    public MatchedPresentations {
        presentations = List.copyOf(presentations);
        droppedClaimNames = Set.copyOf(droppedClaimNames);
    }
}
