/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.FederationProviderFactory;
import io.helixiam.authorization.federation.eid.EidLevelOfAssurance;
import io.helixiam.authorization.federation.eid.EidScheme;
import io.helixiam.authorization.service.key.SoftwareRealmSigningKeys;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Security review item 8: the save-time rules between a verify-only connection and its {@code verify.linkedProvider}
 * (the admin API applies them with the realm's stored connections). Refused (field → message): a linked connection
 * that does not exist in the realm, is not a wallet connection, or cannot sign in ({@code NONE}); a {@code minimumLoa}
 * below the linked connection's. Only flagged ({@link #anchorsWithin}, logged as a WARN by the caller): trust anchors
 * the linked connection does not also trust — a stricter set is fine, and the two connections may legitimately be
 * configured at different times, so the server does not refuse it. Pure.
 */
public final class WalletVerifyLinkRules {

    private WalletVerifyLinkRules() {
    }

    /**
     * @param linkedProtocol the linked connection's protocol, {@code null} when the realm has no connection by that
     *                       alias
     * @param linkedConfig   its stored settings ({@code null} when absent)
     */
    public static Map<String, String> problems(final WalletProviderConfig verify, final String linkedProtocol,
                                               final Map<String, String> linkedConfig) {
        final Map<String, String> errors = new LinkedHashMap<>();
        if (!verify.subject().verifyOnly()) {
            return errors;
        }
        if (linkedProtocol == null || linkedConfig == null) {
            errors.put("verify.linkedProvider", "This realm has no identity provider with that alias.");
            return errors;
        }
        if (!FederationProviderFactory.isWallet(linkedProtocol)) {
            errors.put("verify.linkedProvider", "The linked connection must be an EU Digital Identity Wallet connection.");
            return errors;
        }
        final WalletProviderConfig linked = WalletProviderConfig.fromStored("linked", null, linkedConfig);
        if (linked.subject().verifyOnly()) {
            errors.put("verify.linkedProvider", "The linked connection must be one that signs users in, not another "
                    + "verify-only connection.");
            return errors;
        }
        if (EidLevelOfAssurance.rung(EidScheme.EUDI_WALLET, verify.minimumLoa())
                < EidLevelOfAssurance.rung(EidScheme.EUDI_WALLET, linked.minimumLoa())) {
            errors.put("minimumLoa", "The minimum level of assurance must be at least the linked connection's ("
                    + linked.minimumLoa() + ").");
        }
        return errors;
    }

    /**
     * pentest-b LOW: whether {@code verify} trusts nothing {@code linked} does not, across BOTH trust sources — the
     * pasted PEM {@code trustAnchors} and the named {@code trustedLists} (sources + service types). Comparing only
     * the PEM anchors (the original check) meant a connection that relies solely on trusted lists (no PEM anchors
     * at all) always failed this check, even against an identically-configured linked connection — a spurious
     * warning every time. False (not within) if either side's PEM bundle cannot be parsed.
     * <p>
     * An empty set on the {@code verify} side never widens trust, so it is always "within". An empty
     * {@code trustedLists.serviceTypes} means "every type the source extracts" ({@link TrustedLists}), the
     * broadest case, so it is always within too. Otherwise {@code verify}'s set must be a subset of {@code linked}'s.
     */
    public static boolean anchorsWithin(final WalletProviderConfig verify, final WalletProviderConfig linked) {
        final List<X509Certificate> mine;
        final Set<X509Certificate> theirs;
        try {
            mine = parseAnchorsOrEmpty(verify.trustAnchors());
            theirs = new HashSet<>(parseAnchorsOrEmpty(linked.trustAnchors()));
        } catch (final RuntimeException e) {
            return false;
        }
        if (!mine.isEmpty() && !theirs.containsAll(mine)) {
            return false;
        }
        final Set<String> theirSources = new HashSet<>(linked.trustedLists().sources());
        if (!theirSources.containsAll(verify.trustedLists().sources())) {
            return false;
        }
        final List<String> theirTypes = linked.trustedLists().serviceTypes();
        final List<String> myTypes = verify.trustedLists().serviceTypes();
        return theirTypes.isEmpty() || new HashSet<>(theirTypes).containsAll(myTypes);
    }

    /** No PEM anchors declared (null/blank) is an empty set, not a parse error. */
    private static List<X509Certificate> parseAnchorsOrEmpty(final String pem) {
        return (pem == null || pem.isBlank()) ? List.of() : SoftwareRealmSigningKeys.parseCertificateChain(pem);
    }
}
