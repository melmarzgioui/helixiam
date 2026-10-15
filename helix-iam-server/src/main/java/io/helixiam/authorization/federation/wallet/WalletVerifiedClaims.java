/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Verify-only mode ({@code subject.strategy=NONE}): what a verified presentation may release
 * ({@code verify.releasedClaims}, docs/superpowers/specs/2026-10-15-wallet-verify-only-design.md D6). Pure.
 *
 * <ul>
 *   <li>A release entry is a requested PID claim the mapper maps ({@link WalletAttributeMapper#isMappedClaim}); an
 *       object claim ({@code place_of_birth}) releases its dotted members ({@code place_of_birth.country}, ...).</li>
 *   <li>{@code age_over_NN} (NN 1–150, no leading zero) is derived from the verified {@code birthdate}, which must be
 *       requested; the birth date itself is released only when listed too.</li>
 *   <li>Nothing else is ever released: not the administrative number, not the Helix-only {@code helix_wallet_*}
 *       attributes, not a claim requested only to bind the wallet to the user.</li>
 * </ul>
 */
public final class WalletVerifiedClaims {

    /** {@code age_over_NN}, NN 1–150 without a leading zero. */
    static final Pattern AGE_OVER = Pattern.compile("age_over_([1-9][0-9]{0,2})");
    private static final int MAX_AGE = 150;
    private static final String BIRTHDATE = "birthdate";

    private WalletVerifiedClaims() {
    }

    /** Why {@code released} cannot be released for a provider requesting {@code requested}; empty when it can. */
    public static Optional<String> problem(final List<String> requested, final List<String> released) {
        final Set<String> seen = new HashSet<>();
        for (final String claim : released) {
            if (claim == null || claim.isBlank()) {
                return Optional.of("verify.releasedClaims must not contain empty entries");
            }
            if (!seen.add(claim)) {
                return Optional.of("Released claim listed twice: " + claim);
            }
            final Matcher age = AGE_OVER.matcher(claim);
            if (age.matches()) {
                if (Integer.parseInt(age.group(1)) > MAX_AGE) {
                    return Optional.of("Age thresholds go from age_over_1 to age_over_" + MAX_AGE + ": " + claim);
                }
                if (!requested.contains(BIRTHDATE)) {
                    return Optional.of(claim + " is derived from the birth date: request birthdate too");
                }
                continue;
            }
            if (claim.startsWith("age_over_")) {
                return Optional.of("Age thresholds go from age_over_1 to age_over_" + MAX_AGE + ": " + claim);
            }
            if (!requested.contains(claim)) {
                return Optional.of("Only requested claims can be released: " + claim);
            }
            if (!WalletAttributeMapper.isMappedClaim(claim)) {
                return Optional.of("This claim cannot be released: " + claim);
            }
        }
        return Optional.empty();
    }

    /**
     * The released claims of a verified presentation's mapped {@code attributes}, in {@code released} order: a fresh,
     * mutable map (never {@code Map.of}: it ends up in an ID token). A listed claim the PID did not carry, or an age
     * threshold without a readable birth date, is left out.
     */
    public static Map<String, Object> release(final Map<String, String> attributes, final List<String> released,
                                              final LocalDate today) {
        final Map<String, Object> out = new LinkedHashMap<>();
        for (final String claim : released) {
            final Matcher age = AGE_OVER.matcher(claim);
            if (age.matches()) {
                birthdate(attributes.get(BIRTHDATE)).ifPresent(birth ->
                        out.put(claim, !birth.plusYears(Integer.parseInt(age.group(1))).isAfter(today)));
                continue;
            }
            if (attributes.containsKey(claim)) {
                out.put(claim, attributes.get(claim));
                continue;
            }
            attributes.forEach((name, value) -> {
                if (name.startsWith(claim + ".")) {
                    out.put(name, value);
                }
            });
        }
        return out;
    }

    private static Optional<LocalDate> birthdate(final String value) {
        if (value == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(LocalDate.parse(value.trim()));
        } catch (final DateTimeParseException e) {
            return Optional.empty();
        }
    }
}
