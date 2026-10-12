/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.dcql;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Builds the {@code dcql_query} (OpenID4VP §6, docs/eudi-wallet-spec-notes.md §1.4) a wallet login sends.
 *
 * <p><b>PID preset.</b> One Credential Query per requested format, in the order given: {@code pid_sd_jwt}
 * ({@code dc+sd-jwt}, {@code meta.vct_values} = every configured vct, national PIDs included) and {@code pid_mdoc}
 * ({@code mso_mdoc}, {@code meta.doctype_value} = the configured doctype, used as given). With two formats a single
 * required {@code credential_sets} entry lets either one satisfy the request; with one format there is no
 * {@code credential_sets}, so that query is simply required (§6.4.2). Nothing else is emitted: no {@code multiple},
 * {@code claim_sets}, claim {@code values}, {@code trusted_authorities} or
 * {@code require_cryptographic_holder_binding} (its default, {@code true}, is what we want), and claim paths are only
 * strings (at most two), never {@code null} wildcards or array indexes. Without {@code claim_sets} every listed claim
 * is requested (§6.4.1), so {@link DcqlResultMatcher} treats each as required.
 *
 * <p><b>Claim names.</b> Requested claims use Helix's canonical names: the SD-JWT VC claim names of the ARF PID
 * Rulebook (Annex 3.01 v1.7, 17 July 2026, notes §7.2), nested members dotted (spec §8.1 uses the same names). Each
 * maps to its SD-JWT VC path and to its mdoc element in the PID namespace {@code eu.europa.ec.eudi.pid.1} (also for a
 * domestic doctype: PID_06 keeps the EU attributes in that namespace). {@code address.house_number} has no mdoc
 * element: the Rulebook table recorded in notes §7.2 lists {@code resident_house_number} with an SD-JWT VC claim only
 * ("not listed for mdoc"), so no mdoc identifier is invented and the claim is requested from SD-JWT VC only.
 * {@code age_over_18} is no PID attribute any more (Rulebook v1.1) and is refused like any unknown name.
 */
public final class DcqlQueryBuilder {

    public static final String SD_JWT_FORMAT = "dc+sd-jwt";
    public static final String MDOC_FORMAT = "mso_mdoc";
    public static final String SD_JWT_QUERY_ID = "pid_sd_jwt";
    public static final String MDOC_QUERY_ID = "pid_mdoc";
    /** ARF Annex 2 PID_05: the namespace of the EU PID attributes. */
    public static final String PID_NAMESPACE = "eu.europa.ec.eudi.pid.1";

    /** Canonical (SD-JWT VC) claim name -> mdoc element identifier, or {@code null} when the mdoc PID has none. */
    private static final Map<String, String> PID_CLAIMS = pidClaims();

    private static Map<String, String> pidClaims() {
        final Map<String, String> m = new LinkedHashMap<>();
        m.put("family_name", "family_name");
        m.put("given_name", "given_name");
        m.put("birthdate", "birth_date");
        m.put("place_of_birth", "place_of_birth");
        m.put("nationalities", "nationality");
        m.put("picture", "portrait");
        m.put("address.formatted", "resident_address");
        m.put("address.country", "resident_country");
        m.put("address.region", "resident_state");
        m.put("address.locality", "resident_city");
        m.put("address.postal_code", "resident_postal_code");
        m.put("address.street_address", "resident_street");
        m.put("address.house_number", null);
        m.put("personal_administrative_number", "personal_administrative_number");
        m.put("birth_family_name", "family_name_birth");
        m.put("birth_given_name", "given_name_birth");
        m.put("sex", "sex");
        m.put("email", "email_address");
        m.put("phone_number", "mobile_phone_number");
        m.put("date_of_expiry", "expiry_date");
        m.put("issuing_authority", "issuing_authority");
        m.put("issuing_country", "issuing_country");
        m.put("document_number", "document_number");
        m.put("issuing_jurisdiction", "issuing_jurisdiction");
        m.put("date_of_issuance", "issuance_date");
        m.put("trust_anchor", "trust_anchor");
        m.put("attestation_legal_category", "attestation_legal_category");
        return Collections.unmodifiableMap(m);
    }

    /**
     * The PID preset for {@code formats} (a non-empty, duplicate-free list of {@code dc+sd-jwt} and/or
     * {@code mso_mdoc}). Returns a fresh JSON object to place in the request's {@code dcql_query}.
     *
     * @throws IllegalArgumentException for an unknown or repeated format or claim, no claims, a requested format whose
     *                                  type is not configured, or an mdoc query left without any claim
     */
    public ObjectNode pidQuery(final PidQuerySpec spec, final List<String> formats) {
        if (formats == null || formats.isEmpty() || new HashSet<>(formats).size() != formats.size()) {
            throw new IllegalArgumentException("formats must be a non-empty list without duplicates");
        }
        final List<String> claims = checkedClaims(spec.requestedClaims());
        final ObjectNode query = JsonNodeFactory.instance.objectNode();
        final ArrayNode credentials = query.putArray("credentials");
        final List<String> ids = new ArrayList<>();
        for (final String format : formats) {
            if (SD_JWT_FORMAT.equals(format)) {
                credentials.add(sdJwtQuery(spec, claims));
                ids.add(SD_JWT_QUERY_ID);
            } else if (MDOC_FORMAT.equals(format)) {
                credentials.add(mdocQuery(spec, claims));
                ids.add(MDOC_QUERY_ID);
            } else {
                throw new IllegalArgumentException("unsupported format: " + format);
            }
        }
        if (ids.size() > 1) {
            final ArrayNode options = query.putArray("credential_sets").addObject().putArray("options");
            ids.forEach(id -> options.addArray().add(id));
        }
        return query;
    }

    private static List<String> checkedClaims(final List<String> requested) {
        if (requested.isEmpty()) {
            throw new IllegalArgumentException("requestedClaims must not be empty");
        }
        final Set<String> seen = new HashSet<>();
        for (final String name : requested) {
            if (!PID_CLAIMS.containsKey(name)) {
                throw new IllegalArgumentException("not a PID claim: " + name);
            }
            if (!seen.add(name)) {
                throw new IllegalArgumentException("claim requested twice: " + name);
            }
        }
        return requested;
    }

    private static ObjectNode sdJwtQuery(final PidQuerySpec spec, final List<String> claims) {
        if (spec.sdJwtVcts().isEmpty() || spec.sdJwtVcts().stream().anyMatch(v -> v == null || v.isBlank())) {
            throw new IllegalArgumentException("dc+sd-jwt needs at least one vct and no blank one");
        }
        final ObjectNode q = credentialQuery(SD_JWT_QUERY_ID, SD_JWT_FORMAT);
        final ArrayNode vcts = q.putObject("meta").putArray("vct_values");
        spec.sdJwtVcts().forEach(vcts::add);
        final ArrayNode claimQueries = q.putArray("claims");
        for (final String name : claims) {
            final ArrayNode path = claimQueries.addObject().putArray("path");
            for (final String segment : name.split("\\.")) {
                path.add(segment);
            }
        }
        return q;
    }

    private static ObjectNode mdocQuery(final PidQuerySpec spec, final List<String> claims) {
        if (spec.mdocDoctype() == null || spec.mdocDoctype().isBlank()) {
            throw new IllegalArgumentException("mso_mdoc needs a doctype");
        }
        final ObjectNode q = credentialQuery(MDOC_QUERY_ID, MDOC_FORMAT);
        q.putObject("meta").put("doctype_value", spec.mdocDoctype());
        final ArrayNode claimQueries = q.putArray("claims");
        for (final String name : claims) {
            final String element = PID_CLAIMS.get(name);
            if (element != null) {
                claimQueries.addObject().putArray("path").add(PID_NAMESPACE).add(element);
            }
        }
        if (claimQueries.isEmpty()) {
            throw new IllegalArgumentException("none of the requested claims exists in an mdoc PID");
        }
        return q;
    }

    private static ObjectNode credentialQuery(final String id, final String format) {
        final ObjectNode q = JsonNodeFactory.instance.objectNode();
        q.put("id", id);
        q.put("format", format);
        return q;
    }
}
