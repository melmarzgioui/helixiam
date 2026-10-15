/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.dcql;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.helixiam.authorization.federation.wallet.PresentationVerifier;
import io.helixiam.authorization.federation.wallet.VerificationContext;
import io.helixiam.authorization.federation.wallet.VerifiedPresentation;
import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Matches a wallet's {@code vp_token} against the {@code dcql_query} we sent (OpenID4VP §6, §8.1,
 * docs/eudi-wallet-spec-notes.md §1.4, §1.6). The wallet is not trusted to have applied the query (§14.9), so every
 * constraint is re-checked here. Failures are {@link WalletVerificationException}s whose details never carry
 * presentation content or wallet-chosen strings.
 *
 * <p>In this order:
 * <ol>
 *   <li><b>Shape.</b> {@code vp_token} must be a JSON object whose keys are credential query ids and whose values are
 *       non-empty arrays of strings (both supported formats present as strings, Appendix B). Anything else (a bare
 *       string, a non-array or empty-array value, a non-string presentation, an id that is not in the query, more than
 *       one presentation for a query without {@code multiple: true}) is {@code INVALID_RESPONSE}.</li>
 *   <li><b>Credential sets.</b> Without {@code credential_sets} every credential query is required; with them, each
 *       required set needs an option whose ids are all answered. Otherwise {@code DCQL_NOT_SATISFIED}. An answer to a
 *       query that belongs to no satisfied option (e.g. one half of a two-credential option) is <em>refused</em>
 *       ({@code INVALID_RESPONSE}) rather than silently kept or ignored: it is data we did not ask for in that
 *       combination, and accepting part of it would let the wallet decide what the use case is.</li>
 *   <li><b>Verification.</b> Each presentation is verified by the verifier registered for its query's {@code format}
 *       (none registered: {@code INVALID_RESPONSE}), all with the same {@link VerificationContext}; verifier failures
 *       pass through unchanged. The result must be of the query's format and its {@code credentialType} must be
 *       non-null and in the query's {@code meta.vct_values} ({@code dc+sd-jwt}) or equal {@code meta.doctype_value}
 *       ({@code mso_mdoc}); otherwise {@code INVALID_RESPONSE}.</li>
 *   <li><b>Claims.</b> Without {@code claim_sets} every listed claim is requested (§6.4.1) and must be present with
 *       a non-null value; with {@code claim_sets} (Task 21a: the optional subject claims, see
 *       {@link DcqlQueryBuilder}) <em>some</em> option must be fully satisfied, every claim of it present with a
 *       non-null value. Otherwise ({@code null} counts as missing) {@code DCQL_NOT_SATISFIED}. This includes an mdoc
 *       without
 *       {@code issuerSigned.nameSpaces}, which verifies with empty claims (Task 12) but cannot satisfy a query that
 *       requests claims; it is a well-formed, verified credential that lacks what we asked for, hence
 *       {@code DCQL_NOT_SATISFIED} and not {@code INVALID_RESPONSE}.</li>
 *   <li><b>Over-disclosure.</b> Every claim the query lists counts as requested, including those that appear only in
 *       a less preferred or unsatisfied {@code claim_sets} option (the optional subject claims are kept, never
 *       dropped). Disclosed claims the query did not list at all are <em>dropped</em> from the result
 *       (§6.4: wallets must not send them; non-selectively-disclosable ones like {@code sub} arrive anyway). Their
 *       names, never their values, are returned in {@link MatchedPresentations#droppedClaimNames()} and logged at
 *       INFO, sanitised, cut to {@link #MAX_LOGGED_NAME_LENGTH} and, per presentation, capped at
 *       {@link #MAX_DROPPED_NAMES} names plus one {@code (+N more)} entry. A name is the claim's path joined by
 *       {@code /}, e.g. {@code address/locality} or {@code eu.europa.ec.eudi.pid.1/resident_address}.</li>
 * </ol>
 *
 * <p><b>Supported queries.</b> Only what {@link DcqlQueryBuilder} emits (plus {@code multiple}, which the matcher
 * honours) is understood: {@code dc+sd-jwt} and {@code mso_mdoc} queries with {@code id}, {@code format},
 * {@code multiple}, {@code meta}, {@code claims} and {@code claim_sets}; claims with a {@code path} (and an
 * {@code id}, required and unique when {@code claim_sets} is present, §6.3) of string segments only, at most
 * {@link #MAX_PATH_DEPTH} deep, exactly {@code [namespace, element]} for mdoc; {@code claim_sets} as a non-empty array
 * of non-empty arrays of known claim ids; and {@code credential_sets}. SD-JWT paths are applied to the verifier's
 * claims map member by member; integer (array index) and {@code null} (wildcard) segments, claim {@code values},
 * a {@code trusted_authorities} query other than one well-formed {@code aki} query and a malformed {@code claim_sets}
 * are refused with {@link IllegalArgumentException}: the
 * query is ours, so such a query is a programming error, never a wallet error.
 */
public final class DcqlResultMatcher {

    /** Longest dropped-claim name kept and logged (longer ones are cut). */
    public static final int MAX_LOGGED_NAME_LENGTH = 64;
    /** Most dropped-claim names kept and logged per presentation; the rest are counted as {@code (+N more)}. */
    public static final int MAX_DROPPED_NAMES = 32;
    /** Longest accepted claims path. */
    public static final int MAX_PATH_DEPTH = 8;

    private static final Logger LOG = LogManager.getLogger(DcqlResultMatcher.class);
    private static final Pattern QUERY_ID = Pattern.compile("[A-Za-z0-9_-]+");
    private static final Set<String> QUERY_MEMBERS = Set.of("credentials", "credential_sets");
    private static final Set<String> CREDENTIAL_MEMBERS = Set.of("id", "format", "multiple", "meta", "claims",
            "claim_sets", DcqlQueryBuilder.TRUSTED_AUTHORITIES);
    private static final Set<String> TRUSTED_AUTHORITY_MEMBERS = Set.of("type", "values");
    private static final Set<String> CLAIM_MEMBERS = Set.of("id", "path");
    private static final Set<String> SET_MEMBERS = Set.of("options", "required");

    /** {@code claimSets} holds each option's claim paths; {@code null} when the query has no {@code claim_sets}. */
    private record CredentialQuery(String id, String format, boolean multiple, Set<String> vctValues,
            String doctypeValue, List<List<String>> claims, List<List<List<String>>> claimSets) {}

    private record Claims(List<List<String>> paths, List<List<List<String>>> sets) {}

    private record CredentialSet(List<List<String>> options, boolean required) {}

    /** {@code sets} is {@code null} when the query has no {@code credential_sets}. */
    private record Query(Map<String, CredentialQuery> credentials, List<CredentialSet> sets) {}

    /**
     * Verifies and matches {@code vpToken} against {@code dcqlQuery}.
     *
     * @param verifiers presentation verifiers by format ({@code dc+sd-jwt}, {@code mso_mdoc})
     * @return the presentations in query order, each reduced to the requested claims
     * @throws WalletVerificationException when the response is malformed, does not satisfy the query, or fails
     *                                     verification
     * @throws IllegalArgumentException    when {@code dcqlQuery} uses a feature outside what is supported (see above)
     */
    public MatchedPresentations match(final JsonNode vpToken, final ObjectNode dcqlQuery,
            final Map<String, PresentationVerifier> verifiers, final VerificationContext ctx) {
        Objects.requireNonNull(verifiers, "verifiers");
        Objects.requireNonNull(ctx, "ctx");
        final Query query = parse(Objects.requireNonNull(dcqlQuery, "dcqlQuery"));
        final Map<String, List<String>> answers = answers(vpToken, query);
        checkCredentialSets(query, answers.keySet());

        final List<VerifiedPresentation> matched = new ArrayList<>();
        final Set<String> dropped = new LinkedHashSet<>();
        for (final CredentialQuery cq : query.credentials().values()) {
            final List<String> raws = answers.get(cq.id());
            if (raws == null) {
                continue;
            }
            final PresentationVerifier verifier = verifiers.get(cq.format());
            if (verifier == null) {
                throw fail(WalletErrorCode.INVALID_RESPONSE, "no verifier for the credential query's format");
            }
            for (final String raw : raws) {
                try {
                    matched.add(matchOne(cq, verifier.verify(raw, ctx), dropped));
                } catch (final WalletVerificationException e) {
                    // Task 22: tag the failure with this query's format for audit, unless a deeper layer already did.
                    throw e.withFormat(cq.format());
                }
            }
        }
        return new MatchedPresentations(matched, dropped);
    }

    // ------------------------------------------------------------------------------------------- response shape

    private static Map<String, List<String>> answers(final JsonNode vpToken, final Query query) {
        if (vpToken == null || !vpToken.isObject()) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "vp_token is not a JSON object");
        }
        final Map<String, List<String>> answers = new LinkedHashMap<>();
        final Iterator<Map.Entry<String, JsonNode>> fields = vpToken.fields();
        while (fields.hasNext()) {
            final Map.Entry<String, JsonNode> field = fields.next();
            final CredentialQuery cq = query.credentials().get(field.getKey());
            if (cq == null) {
                throw fail(WalletErrorCode.INVALID_RESPONSE, "vp_token has an entry for an unknown credential query");
            }
            final JsonNode value = field.getValue();
            if (!value.isArray() || value.isEmpty()) {
                throw fail(WalletErrorCode.INVALID_RESPONSE, "vp_token entry is not a non-empty array");
            }
            if (value.size() > 1 && !cq.multiple()) {
                throw fail(WalletErrorCode.INVALID_RESPONSE, "vp_token has several presentations for a single query");
            }
            final List<String> raws = new ArrayList<>(value.size());
            for (final JsonNode presentation : value) {
                if (!presentation.isTextual()) {
                    throw fail(WalletErrorCode.INVALID_RESPONSE, "vp_token presentation is not a string");
                }
                raws.add(presentation.textValue());
            }
            answers.put(field.getKey(), raws);
        }
        return answers;
    }

    private static void checkCredentialSets(final Query query, final Set<String> answered) {
        if (query.sets() == null) {
            if (!answered.containsAll(query.credentials().keySet())) {
                throw fail(WalletErrorCode.DCQL_NOT_SATISFIED, "a required credential query was not answered");
            }
            return;
        }
        final Set<String> inSatisfiedOption = new HashSet<>();
        boolean requiredUnsatisfied = false;
        for (final CredentialSet set : query.sets()) {
            boolean satisfied = false;
            for (final List<String> option : set.options()) {
                if (answered.containsAll(option)) {
                    inSatisfiedOption.addAll(option);
                    satisfied = true;
                }
            }
            requiredUnsatisfied |= set.required() && !satisfied;
        }
        if (requiredUnsatisfied) {
            throw fail(WalletErrorCode.DCQL_NOT_SATISFIED, "a required credential set was not satisfied");
        }
        if (!inSatisfiedOption.containsAll(answered)) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "an answered credential query is in no satisfied option");
        }
    }

    // ------------------------------------------------------------------------------------------- one presentation

    private static VerifiedPresentation matchOne(final CredentialQuery cq, final VerifiedPresentation vp,
            final Set<String> dropped) {
        if (!cq.format().equals(vp.format())) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "presentation format differs from its credential query");
        }
        final String type = vp.credentialType();
        final boolean typeMatches = type != null && (DcqlQueryBuilder.SD_JWT_FORMAT.equals(cq.format())
                ? cq.vctValues().contains(type)
                : cq.doctypeValue().equals(type));
        if (!typeMatches) {
            throw fail(WalletErrorCode.INVALID_RESPONSE, "credential type is not the one its query requested");
        }
        final Map<String, Object> claims = vp.claims() == null ? Map.of() : vp.claims();
        final boolean satisfied = cq.claimSets() == null
                ? allPresent(claims, cq.claims())
                : cq.claimSets().stream().anyMatch(option -> allPresent(claims, option));
        if (!satisfied) {
            throw fail(WalletErrorCode.DCQL_NOT_SATISFIED, cq.claimSets() == null
                    ? "a requested claim is missing" : "no claim set of the query is fully satisfied");
        }
        final Set<String> droppedHere = new LinkedHashSet<>();
        final Map<String, Object> kept = keep(claims, cq.claims(), 0, "", droppedHere);
        if (!droppedHere.isEmpty()) {
            final List<String> reported = capped(droppedHere);
            LOG.info("wallet: dropped claims that DCQL query {} ({}) did not request: {}", cq.id(), cq.format(),
                    LogSafe.sanitize(String.join(", ", reported)));
            dropped.addAll(reported);
        }
        return new VerifiedPresentation(vp.format(), vp.credentialType(), kept, vp.issuerSubjectDn(),
                vp.issuerSerialHex(), vp.statusResult());
    }

    /** The first {@link #MAX_DROPPED_NAMES} names, then {@code (+N more)} for the rest. */
    private static List<String> capped(final Set<String> names) {
        final List<String> all = new ArrayList<>(names);
        if (all.size() <= MAX_DROPPED_NAMES) {
            return all;
        }
        final List<String> reported = new ArrayList<>(all.subList(0, MAX_DROPPED_NAMES));
        reported.add("(+" + (all.size() - MAX_DROPPED_NAMES) + " more)");
        return reported;
    }

    private static boolean allPresent(final Map<String, Object> claims, final List<List<String>> paths) {
        return paths.stream().allMatch(path -> present(claims, path));
    }

    /** A JSON null (or CBOR null) value does not satisfy a requested claim. */
    private static boolean present(final Map<String, Object> claims, final List<String> path) {
        Object current = claims;
        for (final String segment : path) {
            if (!(current instanceof Map<?, ?> map)) {
                return false;
            }
            current = map.get(segment);
        }
        return current != null;
    }

    /** The members of {@code source} on a requested path (whole subtrees at a path's end); the rest is dropped. */
    private static Map<String, Object> keep(final Map<?, ?> source, final List<List<String>> paths, final int depth,
            final String prefix, final Set<String> dropped) {
        final Set<String> whole = new HashSet<>();
        final Map<String, List<List<String>>> deeper = new LinkedHashMap<>();
        for (final List<String> path : paths) {
            if (path.size() == depth + 1) {
                whole.add(path.get(depth));
            } else {
                deeper.computeIfAbsent(path.get(depth), k -> new ArrayList<>()).add(path);
            }
        }
        final Map<String, Object> kept = new LinkedHashMap<>();
        for (final Map.Entry<?, ?> entry : source.entrySet()) {
            final String key = String.valueOf(entry.getKey());
            if (whole.contains(key)) {
                kept.put(key, entry.getValue());
            } else if (deeper.containsKey(key) && entry.getValue() instanceof Map<?, ?> nested) {
                kept.put(key, keep(nested, deeper.get(key), depth + 1, prefix + key + "/", dropped));
            } else {
                dropped.add(loggableName(prefix + key));
            }
        }
        return Collections.unmodifiableMap(kept);
    }

    private static String loggableName(final String name) {
        final String safe = LogSafe.sanitize(name);
        return safe.length() <= MAX_LOGGED_NAME_LENGTH ? safe : safe.substring(0, MAX_LOGGED_NAME_LENGTH - 3) + "...";
    }

    // ------------------------------------------------------------------------------------------- our query

    private static Query parse(final ObjectNode query) {
        onlyMembers(query, QUERY_MEMBERS, "dcql_query");
        final JsonNode credentials = query.get("credentials");
        if (credentials == null || !credentials.isArray() || credentials.isEmpty()) {
            throw new IllegalArgumentException("dcql_query.credentials must be a non-empty array");
        }
        final Map<String, CredentialQuery> byId = new LinkedHashMap<>();
        for (final JsonNode node : credentials) {
            final CredentialQuery cq = credentialQuery(node);
            if (byId.put(cq.id(), cq) != null) {
                throw new IllegalArgumentException("credential query id repeated: " + cq.id());
            }
        }
        final JsonNode sets = query.get("credential_sets");
        if (sets == null) {
            return new Query(byId, null);
        }
        if (!sets.isArray() || sets.isEmpty()) {
            throw new IllegalArgumentException("credential_sets must be a non-empty array");
        }
        final List<CredentialSet> parsed = new ArrayList<>();
        for (final JsonNode set : sets) {
            onlyMembers(set, SET_MEMBERS, "credential set");
            final JsonNode options = set.get("options");
            if (options == null || !options.isArray() || options.isEmpty()) {
                throw new IllegalArgumentException("credential set options must be a non-empty array");
            }
            final List<List<String>> parsedOptions = new ArrayList<>();
            for (final JsonNode option : options) {
                if (!option.isArray() || option.isEmpty()) {
                    throw new IllegalArgumentException("credential set option must be a non-empty array");
                }
                final List<String> ids = new ArrayList<>();
                for (final JsonNode id : option) {
                    if (!id.isTextual() || !byId.containsKey(id.textValue())) {
                        throw new IllegalArgumentException("credential set names an unknown credential query");
                    }
                    ids.add(id.textValue());
                }
                parsedOptions.add(List.copyOf(ids));
            }
            final JsonNode required = set.get("required");
            if (required != null && !required.isBoolean()) {
                throw new IllegalArgumentException("credential set required must be a boolean");
            }
            parsed.add(new CredentialSet(List.copyOf(parsedOptions), required == null || required.booleanValue()));
        }
        return new Query(byId, List.copyOf(parsed));
    }

    /**
     * HAIP §5: the builder may add one {@code aki} Trusted Authorities Query (OpenID4VP §6.1.1.1). It is a hint for the
     * wallet only and is not enforced here: the presentation verifiers' PKIX validation to the trust anchors decides
     * which issuers are accepted. Anything but a well-formed {@code aki} query is a programming error.
     */
    private static void checkTrustedAuthorities(final JsonNode node) {
        if (node == null) {
            return;
        }
        if (!node.isArray() || node.isEmpty()) {
            throw new IllegalArgumentException("trusted_authorities must be a non-empty array");
        }
        for (final JsonNode authority : node) {
            onlyMembers(authority, TRUSTED_AUTHORITY_MEMBERS, "trusted authorities query");
            if (!"aki".equals(text(authority.get("type"), "trusted authorities type"))) {
                throw new IllegalArgumentException("only the aki trusted authorities query is supported");
            }
            final JsonNode values = authority.get("values");
            if (values == null || !values.isArray() || values.isEmpty()) {
                throw new IllegalArgumentException("trusted authorities values must be a non-empty array");
            }
            values.forEach(value -> text(value, "trusted authorities value"));
        }
    }

    private static CredentialQuery credentialQuery(final JsonNode node) {
        onlyMembers(node, CREDENTIAL_MEMBERS, "credential query");
        final String id = text(node.get("id"), "credential query id");
        if (!QUERY_ID.matcher(id).matches()) {
            throw new IllegalArgumentException("credential query id is not alphanumeric, '_' or '-'");
        }
        final String format = text(node.get("format"), "credential query format");
        checkTrustedAuthorities(node.get(DcqlQueryBuilder.TRUSTED_AUTHORITIES));
        final JsonNode multiple = node.get("multiple");
        if (multiple != null && !multiple.isBoolean()) {
            throw new IllegalArgumentException("credential query multiple must be a boolean");
        }
        final JsonNode meta = node.get("meta");
        if (meta == null || !meta.isObject()) {
            throw new IllegalArgumentException("credential query meta must be an object");
        }
        Set<String> vctValues = null;
        String doctypeValue = null;
        final boolean mdoc;
        if (DcqlQueryBuilder.SD_JWT_FORMAT.equals(format)) {
            final JsonNode vcts = meta.get("vct_values");
            if (vcts == null || !vcts.isArray() || vcts.isEmpty()) {
                throw new IllegalArgumentException("dc+sd-jwt meta.vct_values must be a non-empty array");
            }
            final Set<String> values = new HashSet<>();
            vcts.forEach(v -> values.add(text(v, "vct_values entry")));
            vctValues = Set.copyOf(values);
            mdoc = false;
        } else if (DcqlQueryBuilder.MDOC_FORMAT.equals(format)) {
            doctypeValue = text(meta.get("doctype_value"), "mso_mdoc meta.doctype_value");
            mdoc = true;
        } else {
            throw new IllegalArgumentException("unsupported credential query format: " + format);
        }
        final Claims claims = claims(node.get("claims"), node.get("claim_sets"), mdoc);
        return new CredentialQuery(id, format, multiple != null && multiple.booleanValue(), vctValues, doctypeValue,
                claims.paths(), claims.sets());
    }

    private static Claims claims(final JsonNode claims, final JsonNode claimSets, final boolean mdoc) {
        if (claims == null) {
            if (claimSets != null) {
                throw new IllegalArgumentException("claim_sets needs claims");
            }
            return new Claims(List.of(), null);
        }
        if (!claims.isArray() || claims.isEmpty()) {
            throw new IllegalArgumentException("claims must be a non-empty array");
        }
        final List<List<String>> paths = new ArrayList<>();
        final Map<String, List<String>> byId = new HashMap<>();
        for (final JsonNode claim : claims) {
            onlyMembers(claim, CLAIM_MEMBERS, "claims query");
            final JsonNode id = claim.get("id");
            if (id != null || claimSets != null) {
                final String claimId = text(id, "claims query id (required with claim_sets)");
                if (!QUERY_ID.matcher(claimId).matches()) {
                    throw new IllegalArgumentException("claims query id is not alphanumeric, '_' or '-'");
                }
                if (byId.containsKey(claimId)) {
                    throw new IllegalArgumentException("claims query id repeated: " + claimId);
                }
                byId.put(claimId, null); // the path is filled in below
            }
            final JsonNode path = claim.get("path");
            if (path == null || !path.isArray() || path.isEmpty() || path.size() > MAX_PATH_DEPTH) {
                throw new IllegalArgumentException("claims path must be an array of 1.." + MAX_PATH_DEPTH + " items");
            }
            if (mdoc && path.size() != 2) {
                throw new IllegalArgumentException("an mdoc claims path is [namespace, element]");
            }
            final List<String> segments = new ArrayList<>();
            path.forEach(s -> segments.add(text(s, "claims path segment (only strings are supported)")));
            paths.add(List.copyOf(segments));
            if (claim.get("id") != null) {
                byId.put(claim.get("id").textValue(), List.copyOf(segments));
            }
        }
        return new Claims(List.copyOf(paths), claimSets == null ? null : claimSets(claimSets, byId));
    }

    private static List<List<List<String>>> claimSets(final JsonNode claimSets, final Map<String, List<String>> byId) {
        if (!claimSets.isArray() || claimSets.isEmpty()) {
            throw new IllegalArgumentException("claim_sets must be a non-empty array");
        }
        final List<List<List<String>>> options = new ArrayList<>();
        for (final JsonNode option : claimSets) {
            if (!option.isArray() || option.isEmpty()) {
                throw new IllegalArgumentException("a claim_sets option must be a non-empty array");
            }
            final List<List<String>> optionPaths = new ArrayList<>();
            for (final JsonNode id : option) {
                if (!id.isTextual() || !byId.containsKey(id.textValue())) {
                    throw new IllegalArgumentException("a claim_sets option names an unknown claim id");
                }
                optionPaths.add(byId.get(id.textValue()));
            }
            options.add(List.copyOf(optionPaths));
        }
        return List.copyOf(options);
    }

    private static void onlyMembers(final JsonNode node, final Set<String> allowed, final String what) {
        if (node == null || !node.isObject()) {
            throw new IllegalArgumentException(what + " must be an object");
        }
        node.fieldNames().forEachRemaining(name -> {
            if (!allowed.contains(name)) {
                throw new IllegalArgumentException(what + " member not supported: " + name);
            }
        });
    }

    private static String text(final JsonNode node, final String what) {
        if (node == null || !node.isTextual() || node.textValue().isEmpty()) {
            throw new IllegalArgumentException(what + " must be a non-empty string");
        }
        return node.textValue();
    }

    private static WalletVerificationException fail(final WalletErrorCode code, final String safeDetail) {
        return new WalletVerificationException(code, safeDetail);
    }
}
