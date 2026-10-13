/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.wallet.dcql.DcqlQueryBuilder;
import io.helixiam.authorization.federation.wallet.dcql.MatchedPresentations;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.text.Normalizer;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Derives the stable wallet subject from a verified PID (spec §8.2, maintainer decision 1: "administrative number,
 * else link"). <b>Security-critical.</b>
 *
 * <h2>Administrative number</h2>
 * When the PID carries {@code personal_administrative_number} and {@code issuing_country} (requested optionally by
 * {@link DcqlQueryBuilder}), the subject is {@link WalletSubject.AdminNumber}:
 * {@code hex(HMAC-SHA256(realmPepper, issuing_country + ":" + personal_administrative_number))}, the country trimmed
 * and upper-cased ({@link Locale#ROOT}, ISO 3166-1 alpha-2), the number trimmed. The country is part of the input
 * because numbers are only unique within their member state. This applies under either strategy: the number is the
 * strongest subject a PID offers. The number is read from the matched presentations directly (Task 20 keeps it out of
 * the brokered attributes), and the number and the country come from the SAME presentation: the first one that
 * carries both (never one presentation's number with another's country). Every disclosed number must be the same, and
 * every complete pair must agree, else {@code INVALID_RESPONSE}. A number without a country in its own presentation
 * is ignored (it is ambiguous).
 *
 * <h2>Attribute tuple</h2>
 * Only when the provider sets {@code subject.acknowledgeWeakSubject=true} (whatever the strategy; the validator also
 * refuses {@code ATTRIBUTE_TUPLE} without it) is the tuple computed at all. Its field set is fixed by CONFIGURATION,
 * never by what a presentation happens to contain, so the same person always gets the same tuple:
 * {@code issuing_country, family_name, given_name, birthdate}, plus {@code place_of_birth.country, .region,
 * .locality} exactly when the provider's {@code pid.requestedClaims} include {@code place_of_birth}. The four base
 * fields are required: one that is missing, or empty after normalisation, makes the tuple unavailable
 * ({@link WalletSubject.Reason#MISSING_IDENTITY_ATTRIBUTES}). When configured, the place-of-birth object must have at
 * least one non-empty part (the Rulebook guarantees "at least one"); all three parts are always encoded, a missing
 * one as the empty string, so the field set never shrinks; a PID without the object is unavailable too. The subject is
 * {@code hex(HMAC-SHA256(realmPepper, encode(fields)))}, each value normalised: Unicode NFC, lower-cased with
 * {@link Locale#ROOT} (no case folding: {@code ß} stays {@code ß}), internal whitespace runs (NBSP and tabs included)
 * collapsed to one space, trimmed. The encoding is unambiguous: the tag {@code helix-wallet-tuple-v1;}, then for each
 * field {@code name=length:value;}, so no two different tuples (e.g. {@code ("ab","c")} and {@code ("a","bc")}, or a
 * value moved between fields) produce the same input; known-answer tests pin it.
 * <ul>
 *   <li>Without a number, the subject is {@link WalletSubject.Tuple}; without the acknowledgement it is
 *       {@link WalletSubject.Reason#WEAK_SUBJECT_NOT_ACKNOWLEDGED}.</li>
 *   <li>With a number, the tuple (when complete) rides along as {@link WalletSubject.AdminNumber#tupleValue()} for
 *       the upgrade path in {@link WalletLinkService#decide}.</li>
 * </ul>
 * <b>Changing {@code place_of_birth} in {@code pid.requestedClaims} changes every tuple subject of the provider and
 * orphans its existing tuple links</b> (the validator has no warnings channel; documented on
 * {@code WalletProviderConfig.Subject} and in docs/eudi-wallet-spec-notes.md). The tuple is a link key only (see
 * {@link WalletLinkService}): it never creates an account and is never matched against names or email.
 *
 * <p>Strategy {@code NONE} (verify-only step-up) is out of this plan:
 * {@link WalletSubject.Reason#STRATEGY_NOT_SUPPORTED}.
 *
 * <h2>Pepper and logging</h2>
 * The pepper is the realm's 256-bit secret from {@link RealmWalletPepper}, fetched only when a subject is actually
 * computed. Only the subject hash is logged; the number, the tuple and the PID values never are.
 */
@Component
public class WalletSubjectResolver {

    private static final Logger LOG = LogManager.getLogger(WalletSubjectResolver.class);
    private static final String HMAC = "HmacSHA256";
    private static final String TUPLE_VERSION = "helix-wallet-tuple-v1;";
    private static final Pattern WHITESPACE = Pattern.compile("\\s+", Pattern.UNICODE_CHARACTER_CLASS);

    /** The tuple fields every tuple has, in their fixed order. */
    private static final List<String> BASE_TUPLE_FIELDS = List.of(DcqlQueryBuilder.ISSUING_COUNTRY_CLAIM,
            "family_name", "given_name", "birthdate");
    /** The requested claim that adds {@link #PLACE_OF_BIRTH_TUPLE_FIELDS} to the tuple. */
    static final String PLACE_OF_BIRTH_CLAIM = "place_of_birth";
    private static final List<String> PLACE_OF_BIRTH_TUPLE_FIELDS = List.of("place_of_birth.country",
            "place_of_birth.region", "place_of_birth.locality");

    private final RealmWalletPepper peppers;

    public WalletSubjectResolver(final RealmWalletPepper peppers) {
        this.peppers = peppers;
    }

    /** {@link #resolve(String, MatchedPresentations, WalletProviderConfig.Subject, List)} for a provider. */
    public WalletSubject resolve(final String realmId, final MatchedPresentations matched,
            final WalletProviderConfig config) {
        return resolve(realmId, matched, config.subject(), config.pid().requestedClaims());
    }

    /**
     * The subject for {@code matched} (Task 14's DCQL result) in {@code realmId} under the provider's subject
     * configuration. Never {@code null}; an unusable PID is {@link WalletSubject.Unavailable}.
     *
     * @param requestedClaims the provider's {@code pid.requestedClaims}: they fix the tuple's field set (see the class
     *                        javadoc)
     * @throws WalletVerificationException {@code INVALID_RESPONSE} when the presentations contradict each other (see
     *                                      {@link WalletAttributeMapper#pidAttributes} and the class javadoc)
     * @throws IllegalStateException       when the realm's pepper cannot be created (see {@link RealmWalletPepper})
     */
    public WalletSubject resolve(final String realmId, final MatchedPresentations matched,
            final WalletProviderConfig.Subject subjectConfig, final List<String> requestedClaims) {
        Objects.requireNonNull(realmId, "realmId");
        Objects.requireNonNull(matched, "matched");
        Objects.requireNonNull(subjectConfig, "subjectConfig");
        Objects.requireNonNull(requestedClaims, "requestedClaims");
        if (subjectConfig.strategy() == WalletProviderConfig.Subject.Strategy.NONE) {
            return unavailable(realmId, WalletSubject.Reason.STRATEGY_NOT_SUPPORTED);
        }
        final Map<String, String> attributes = WalletAttributeMapper.pidAttributes(matched);
        final String adminInput = administrativeNumberInput(matched);
        // The weak tuple is never even computed without the acknowledgement (also not for the upgrade path).
        final String tupleInput = subjectConfig.acknowledgeWeakSubject()
                ? tupleInput(attributes, tupleFields(requestedClaims)) : null;
        if (adminInput != null) {
            final byte[] pepper = peppers.pepper(realmId);
            return resolved(realmId, new WalletSubject.AdminNumber(hmacHex(pepper, adminInput),
                    tupleInput == null ? null : hmacHex(pepper, tupleInput)));
        }
        if (!subjectConfig.acknowledgeWeakSubject()) {
            return unavailable(realmId, WalletSubject.Reason.WEAK_SUBJECT_NOT_ACKNOWLEDGED);
        }
        if (tupleInput == null) {
            return unavailable(realmId, WalletSubject.Reason.MISSING_IDENTITY_ATTRIBUTES);
        }
        return resolved(realmId, new WalletSubject.Tuple(hmacHex(peppers.pepper(realmId), tupleInput)));
    }

    // ------------------------------------------------------------------------------------------- number

    /**
     * {@code COUNTRY:number} from a presentation that carries BOTH (ruling: never pair one presentation's number with
     * another's country); {@code null} when none does. Every number disclosed must be the same, and every complete
     * pair must agree, else {@code INVALID_RESPONSE} (the detail never carries the values).
     */
    private static String administrativeNumberInput(final MatchedPresentations matched) {
        String number = null;
        String pair = null;
        for (final VerifiedPresentation vp : matched.presentations()) {
            final Map<?, ?> claims = pidClaims(vp);
            final String n = text(claims.get(DcqlQueryBuilder.ADMINISTRATIVE_NUMBER_CLAIM));
            if (n == null) {
                continue;
            }
            if (number != null && !number.equals(n)) {
                throw new WalletVerificationException(WalletErrorCode.INVALID_RESPONSE,
                        "the presentations disagree on the administrative number");
            }
            number = n;
            final String country = text(claims.get(DcqlQueryBuilder.ISSUING_COUNTRY_CLAIM));
            if (country == null) {
                continue;
            }
            final String candidate = country.toUpperCase(Locale.ROOT) + ":" + n;
            if (pair != null && !pair.equals(candidate)) {
                throw new WalletVerificationException(WalletErrorCode.INVALID_RESPONSE,
                        "the presentations disagree on the issuing country");
            }
            pair = candidate;
        }
        return pair;
    }

    /** The PID claims of one presentation: the SD-JWT claims, or the mdoc PID namespace. */
    private static Map<?, ?> pidClaims(final VerifiedPresentation vp) {
        final Map<String, Object> claims = vp.claims() == null ? Map.of() : vp.claims();
        if (DcqlQueryBuilder.MDOC_FORMAT.equals(vp.format())) {
            return claims.get(DcqlQueryBuilder.PID_NAMESPACE) instanceof Map<?, ?> elements ? elements : Map.of();
        }
        return DcqlQueryBuilder.SD_JWT_FORMAT.equals(vp.format()) ? claims : Map.of();
    }

    private static String text(final Object raw) {
        if (!(raw instanceof String value)) {
            return null;
        }
        final String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    // ------------------------------------------------------------------------------------------- tuple

    /** The configured tuple fields, in order (ruling: fixed by configuration, never by the presentation). */
    static List<String> tupleFields(final List<String> requestedClaims) {
        if (!requestedClaims.contains(PLACE_OF_BIRTH_CLAIM)) {
            return BASE_TUPLE_FIELDS;
        }
        final List<String> fields = new java.util.ArrayList<>(BASE_TUPLE_FIELDS);
        fields.addAll(PLACE_OF_BIRTH_TUPLE_FIELDS);
        return List.copyOf(fields);
    }

    /**
     * The encoded tuple, or {@code null} when a configured base field is missing or empty after normalisation, or the
     * place of birth is configured but has no non-empty part. Place-of-birth parts are always encoded, a missing one as
     * the empty string (the Rulebook guarantees only "at least one" part).
     */
    private static String tupleInput(final Map<String, String> attributes, final List<String> fields) {
        final StringBuilder input = new StringBuilder(TUPLE_VERSION);
        boolean placeOfBirthPart = false;
        for (final String field : fields) {
            final String raw = attributes.get(field);
            final String value = raw == null ? "" : normalise(raw);
            final boolean placeOfBirth = PLACE_OF_BIRTH_TUPLE_FIELDS.contains(field);
            if (value.isEmpty() && !placeOfBirth) {
                return null;
            }
            placeOfBirthPart |= placeOfBirth && !value.isEmpty();
            input.append(field).append('=').append(value.length()).append(':').append(value).append(';');
        }
        if (fields.containsAll(PLACE_OF_BIRTH_TUPLE_FIELDS) && !placeOfBirthPart) {
            return null;
        }
        return input.toString();
    }

    /** NFC, trim, lower-case ({@link Locale#ROOT}), internal whitespace runs as one space. */
    static String normalise(final String value) {
        final String nfc = Normalizer.normalize(value, Normalizer.Form.NFC).toLowerCase(Locale.ROOT);
        return Normalizer.normalize(WHITESPACE.matcher(nfc).replaceAll(" ").trim(), Normalizer.Form.NFC);
    }

    // ------------------------------------------------------------------------------------------- helpers

    private static String hmacHex(final byte[] pepper, final String input) {
        try {
            final Mac mac = Mac.getInstance(HMAC);
            mac.init(new SecretKeySpec(pepper, HMAC));
            return HexFormat.of().formatHex(mac.doFinal(input.getBytes(StandardCharsets.UTF_8)));
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA256 is unavailable", e);
        }
    }

    private static WalletSubject resolved(final String realmId, final WalletSubject subject) {
        final String kind = subject instanceof WalletSubject.AdminNumber ? "ADMIN_NUMBER" : "TUPLE";
        // Task 22: never the subject value itself — it is the HMAC of the normalised PID attribute(s) ("the subject
        // hash"), which must never reach the logs even though it is not the raw PID value.
        LOG.info("wallet: subject resolved, realm={} kind={}", LogSafe.sanitize(realmId), kind);
        return subject;
    }

    private static WalletSubject unavailable(final String realmId, final WalletSubject.Reason reason) {
        LOG.info("wallet: no subject, realm={} reason={}", LogSafe.sanitize(realmId), reason.code());
        return new WalletSubject.Unavailable(reason);
    }
}
