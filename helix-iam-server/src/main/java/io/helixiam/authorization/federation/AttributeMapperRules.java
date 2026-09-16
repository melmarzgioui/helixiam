/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.federation.spi.BrokeredIdentity;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Helix IAM B5: the runtime engine for per-IdP attribute/claim mappers. An identity-provider config
 * carries a {@code mappers} value — a CSV of {@code source=target} pairs configured in the console — that
 * says how the upstream provider's claims map onto local user attributes. This parses that CSV and
 * projects a {@link BrokeredIdentity}'s claims onto the configured local attribute names at JIT
 * provisioning time. Pure + null-safe so a missing/malformed mapper config simply yields no extra
 * attributes (the {@link DefaultAttributeMapper} baseline still applies).
 */
public final class AttributeMapperRules {

    /** Source tokens that resolve to the identity's normalized email field rather than a raw claim. */
    private static final Set<String> EMAIL_SYNONYMS = Set.of("email", "mail", "emailaddress");
    /** Source tokens that resolve to the identity's external-subject field rather than a raw claim. */
    private static final Set<String> SUBJECT_SYNONYMS = Set.of("sub", "subject", "externalsubject", "nameid", "id");

    private AttributeMapperRules() {
    }

    /**
     * Parse a {@code "source1=target1,source2=target2"} CSV into ordered source→target rules, skipping
     * blank and malformed (missing either side) entries.
     */
    public static Map<String, String> parse(final String csv) {
        final Map<String, String> rules = new LinkedHashMap<>();
        if (csv == null || csv.isBlank()) {
            return rules;
        }
        for (final String pair : csv.split(",")) {
            final int eq = pair.indexOf('=');
            if (eq < 0) {
                // A bare attribute is a self-map (source==target), matching the console's serialization.
                final String bare = pair.trim();
                if (!bare.isEmpty()) {
                    rules.put(bare, bare);
                }
                continue;
            }
            if (eq == 0 || eq == pair.length() - 1) {
                continue; // empty source or empty target
            }
            final String source = pair.substring(0, eq).trim();
            final String target = pair.substring(eq + 1).trim();
            if (!source.isEmpty() && !target.isEmpty()) {
                rules.put(source, target);
            }
        }
        return rules;
    }

    /**
     * Apply the configured mapper CSV to an identity, returning the extra local attributes it produces.
     * A rule's source is read from the identity's raw claims; {@code email}/{@code sub} synonyms fall back
     * to the normalized identity fields. Rules whose source claim is absent or blank are skipped.
     */
    public static Map<String, String> apply(final BrokeredIdentity identity, final String csv) {
        final Map<String, String> rules = parse(csv);
        final Map<String, String> mapped = new LinkedHashMap<>();
        if (rules.isEmpty()) {
            return mapped;
        }
        final Map<String, String> claims = identity.attributes() == null ? Map.of() : identity.attributes();
        for (final Map.Entry<String, String> rule : rules.entrySet()) {
            final String value = resolve(identity, claims, rule.getKey());
            if (value != null && !value.isBlank()) {
                mapped.put(rule.getValue(), value);
            }
        }
        return mapped;
    }

    private static String resolve(final BrokeredIdentity identity, final Map<String, String> claims,
                                  final String source) {
        final String direct = claims.get(source);
        if (direct != null && !direct.isBlank()) {
            return direct;
        }
        final String key = source.toLowerCase(Locale.ROOT);
        if (EMAIL_SYNONYMS.contains(key)) {
            return identity.email();
        }
        if (SUBJECT_SYNONYMS.contains(key)) {
            return identity.externalSubject();
        }
        return direct; // null/blank — skipped by the caller
    }
}
