/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.dcql;

import com.fasterxml.jackson.databind.JsonNode;
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
 * {@code credential_sets}, so that query is simply required (§6.4.2). An {@code aki} {@code trusted_authorities} query
 * is added when asked for (HAIP §5, see {@link #pidQuery(PidQuerySpec, List, List)}). Nothing else is emitted: no
 * {@code multiple}, claim {@code values} or {@code require_cryptographic_holder_binding} (its default,
 * {@code true}, is what we want), and claim paths are only strings (at most two), never {@code null} wildcards or
 * array indexes.
 *
 * <p><b>Optional subject claims (Task 21a).</b> The wallet's subject (maintainer decision 1: administrative number,
 * else an explicit link) needs {@code personal_administrative_number} and {@code issuing_country}, but a PID need not
 * carry the number. So both are requested <em>optionally</em> through the Credential Query's {@code claim_sets}
 * (§6.1; §6.4.1: the wallet returns the first option, in the verifier's order of preference, that it can satisfy):
 * <ol>
 *   <li>the requested claims + {@link #SUBJECT_CLAIMS} (administrative-number subject);</li>
 *   <li>the requested claims + {@code issuing_country} (so the attribute-tuple subject still gets the country);</li>
 *   <li>the requested claims only.</li>
 * </ol>
 * Options that coincide (a subject claim the admin already requests outright) are emitted once; when only one option
 * remains there is nothing optional and the query keeps its plain form (no {@code claim_sets}, no claim ids, every
 * listed claim required). With {@code claim_sets} every claim carries an {@code id} (§6.3: required then): its
 * canonical name with {@code .} replaced by {@code _} (e.g. {@code address_locality}), the same id in both formats.
 * {@link DcqlResultMatcher} accepts a presentation that fully satisfies <em>some</em> option and keeps every claim the
 * query lists.
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
    /** The PID claim holding the administrative number the wallet subject prefers (Task 21a). */
    public static final String ADMINISTRATIVE_NUMBER_CLAIM = "personal_administrative_number";
    /** The PID claim holding the issuing member state, part of every wallet subject (Task 21a). */
    public static final String ISSUING_COUNTRY_CLAIM = "issuing_country";
    /** The claims requested optionally for the wallet subject, in emitted order (see the class javadoc). */
    public static final List<String> SUBJECT_CLAIMS = List.of(ADMINISTRATIVE_NUMBER_CLAIM, ISSUING_COUNTRY_CLAIM);

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
     * Whether {@code name} is a PID claim this builder can request (a canonical SD-JWT VC name, nested members
     * dotted). Configuration validation uses it so that a stored {@code pid.requestedClaims} never reaches
     * {@link #pidQuery} with a name it would refuse.
     */
    public static boolean isPidClaim(final String name) {
        return name != null && PID_CLAIMS.containsKey(name);
    }

    /**
     * Every PID claim this builder can request (canonical names, in the Rulebook order of {@link #isPidClaim}) and
     * whether an mdoc PID has an element for it ({@code false}: requested from SD-JWT VC only). The admin console's
     * claim picker reads it, so the console never offers a name the validator would refuse.
     */
    public static Map<String, Boolean> pidClaimCatalogue() {
        final Map<String, Boolean> out = new LinkedHashMap<>();
        PID_CLAIMS.forEach((name, element) -> out.put(name, element != null));
        return Collections.unmodifiableMap(out);
    }

    /**
     * The PID preset for {@code formats} (a non-empty, duplicate-free list of {@code dc+sd-jwt} and/or
     * {@code mso_mdoc}). Returns a fresh JSON object to place in the request's {@code dcql_query}.
     *
     * @throws IllegalArgumentException for an unknown or repeated format or claim, no claims, a requested format whose
     *                                  type is not configured, or an mdoc query left without any claim
     */
    public ObjectNode pidQuery(final PidQuerySpec spec, final List<String> formats) {
        return pidQuery(spec, formats, List.of());
    }

    /**
     * As {@link #pidQuery(PidQuerySpec, List)}, and when {@code authorityKeyIds} is not empty every Credential Query
     * also carries {@code "trusted_authorities": [{"type": "aki", "values": authorityKeyIds}]} (OpenID4VP §6.1.1.1,
     * HAIP §5): the base64url key identifiers of the provider's trust anchors
     * ({@link io.helixiam.authorization.federation.wallet.trust.TrustAnchors#authorityKeyIdentifiers}), placed after
     * {@code meta}. It tells the wallet which issuers are acceptable; the PKIX validation of the presentation still
     * decides.
     *
     * @throws IllegalArgumentException additionally for a null or blank key identifier
     */
    public ObjectNode pidQuery(final PidQuerySpec spec, final List<String> formats,
                               final List<String> authorityKeyIds) {
        if (authorityKeyIds == null || authorityKeyIds.stream().anyMatch(v -> v == null || v.isBlank())) {
            throw new IllegalArgumentException("authority key identifiers must not be null or blank");
        }
        final ObjectNode query = presetQuery(spec, formats);
        if (!authorityKeyIds.isEmpty()) {
            for (final JsonNode credential : query.withArray("credentials")) {
                final ObjectNode q = (ObjectNode) credential;
                final ObjectNode reordered = JsonNodeFactory.instance.objectNode();
                final List<String> names = new ArrayList<>();
                q.fieldNames().forEachRemaining(names::add);
                for (final String name : names) {
                    reordered.set(name, q.get(name));
                    if ("meta".equals(name)) {
                        final ArrayNode values = reordered.putArray(TRUSTED_AUTHORITIES).addObject()
                                .put("type", "aki").putArray("values");
                        authorityKeyIds.forEach(values::add);
                    }
                }
                q.removeAll();
                q.setAll(reordered);
            }
        }
        return query;
    }

    /** The DCQL Credential Query member of the Trusted Authorities Query (OpenID4VP §6.1). */
    public static final String TRUSTED_AUTHORITIES = "trusted_authorities";

    private ObjectNode presetQuery(final PidQuerySpec spec, final List<String> formats) {
        if (formats == null || formats.isEmpty() || new HashSet<>(formats).size() != formats.size()) {
            throw new IllegalArgumentException("formats must be a non-empty list without duplicates");
        }
        final List<List<String>> claimOptions = claimOptions(checkedClaims(spec.requestedClaims()));
        final ObjectNode query = JsonNodeFactory.instance.objectNode();
        final ArrayNode credentials = query.putArray("credentials");
        final List<String> ids = new ArrayList<>();
        for (final String format : formats) {
            if (SD_JWT_FORMAT.equals(format)) {
                credentials.add(sdJwtQuery(spec, claimOptions));
                ids.add(SD_JWT_QUERY_ID);
            } else if (MDOC_FORMAT.equals(format)) {
                credentials.add(mdocQuery(spec, claimOptions));
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

    /**
     * The claim options in order of preference (see the class javadoc), as canonical names; the first is the full
     * claim list. Coinciding options are kept once.
     */
    private static List<List<String>> claimOptions(final List<String> requested) {
        final List<List<String>> options = new ArrayList<>();
        addOption(options, withMissing(requested, SUBJECT_CLAIMS));
        addOption(options, withMissing(requested, List.of(ISSUING_COUNTRY_CLAIM)));
        addOption(options, requested);
        return options;
    }

    private static List<String> withMissing(final List<String> requested, final List<String> extra) {
        final List<String> out = new ArrayList<>(requested);
        extra.stream().filter(name -> !out.contains(name)).forEach(out::add);
        return List.copyOf(out);
    }

    private static void addOption(final List<List<String>> options, final List<String> option) {
        if (!options.contains(option)) {
            options.add(option);
        }
    }

    /** The DCQL claim id for a canonical claim name (§6.3: alphanumeric, '_' or '-'). */
    static String claimId(final String name) {
        return name.replace('.', '_');
    }

    private static ObjectNode sdJwtQuery(final PidQuerySpec spec, final List<List<String>> options) {
        if (spec.sdJwtVcts().isEmpty() || spec.sdJwtVcts().stream().anyMatch(v -> v == null || v.isBlank())) {
            throw new IllegalArgumentException("dc+sd-jwt needs at least one vct and no blank one");
        }
        final ObjectNode q = credentialQuery(SD_JWT_QUERY_ID, SD_JWT_FORMAT);
        final ArrayNode vcts = q.putObject("meta").putArray("vct_values");
        spec.sdJwtVcts().forEach(vcts::add);
        final boolean withIds = options.size() > 1;
        final ArrayNode claimQueries = q.putArray("claims");
        for (final String name : options.get(0)) {
            final ObjectNode claim = claimQueries.addObject();
            if (withIds) {
                claim.put("id", claimId(name));
            }
            final ArrayNode path = claim.putArray("path");
            for (final String segment : name.split("\\.")) {
                path.add(segment);
            }
        }
        if (withIds) {
            putClaimSets(q, options);
        }
        return q;
    }

    private static ObjectNode mdocQuery(final PidQuerySpec spec, final List<List<String>> options) {
        if (spec.mdocDoctype() == null || spec.mdocDoctype().isBlank()) {
            throw new IllegalArgumentException("mso_mdoc needs a doctype");
        }
        // Only the claims an mdoc PID has an element for; options that then coincide are kept once.
        final List<List<String>> mdocOptions = new ArrayList<>();
        for (final List<String> option : options) {
            addOption(mdocOptions, option.stream().filter(name -> PID_CLAIMS.get(name) != null).toList());
        }
        if (mdocOptions.get(mdocOptions.size() - 1).isEmpty()) {
            // the last option is the requested claims alone
            throw new IllegalArgumentException("none of the requested claims exists in an mdoc PID");
        }
        final ObjectNode q = credentialQuery(MDOC_QUERY_ID, MDOC_FORMAT);
        q.putObject("meta").put("doctype_value", spec.mdocDoctype());
        final boolean withIds = mdocOptions.size() > 1;
        final ArrayNode claimQueries = q.putArray("claims");
        for (final String name : mdocOptions.get(0)) {
            final ObjectNode claim = claimQueries.addObject();
            if (withIds) {
                claim.put("id", claimId(name));
            }
            claim.putArray("path").add(PID_NAMESPACE).add(PID_CLAIMS.get(name));
        }
        if (withIds) {
            putClaimSets(q, mdocOptions);
        }
        return q;
    }

    private static void putClaimSets(final ObjectNode q, final List<List<String>> options) {
        final ArrayNode claimSets = q.putArray("claim_sets");
        for (final List<String> option : options) {
            final ArrayNode ids = claimSets.addArray();
            option.forEach(name -> ids.add(claimId(name)));
        }
    }

    private static ObjectNode credentialQuery(final String id, final String format) {
        final ObjectNode q = JsonNodeFactory.instance.objectNode();
        q.put("id", id);
        q.put("format", format);
        return q;
    }
}
