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
 * the brokered attributes): from the SD-JWT presentation when there is one, else from the mdoc; when both carry it
 * they must agree, else {@code INVALID_RESPONSE}. A number without a country is ignored (it is ambiguous).
 *
 * <h2>Attribute tuple</h2>
 * Without a number, and only when the provider sets {@code subject.acknowledgeWeakSubject=true} (whatever the
 * strategy; the validator also refuses {@code ATTRIBUTE_TUPLE} without it), the subject is
 * {@link WalletSubject.Tuple}: {@code hex(HMAC-SHA256(realmPepper, encode(issuing_country?, family_name, given_name,
 * birthdate, place_of_birth.country?, place_of_birth.region?, place_of_birth.locality?)))}, in that fixed order, each
 * value normalised: Unicode NFC, trimmed, lower-cased with {@link Locale#ROOT}, internal whitespace runs collapsed to
 * one space. The encoding is unambiguous: a version tag, then for each <em>present</em> field its name, its length
 * and its value ({@code name=length:value;}), so no two different tuples (e.g. {@code ("ab","c")} and
 * {@code ("a","bc")}, or a value moved between fields) produce the same input. A tuple without both names and the
 * birth date is {@link WalletSubject.Reason#MISSING_IDENTITY_ATTRIBUTES}; without the acknowledgement it is
 * {@link WalletSubject.Reason#WEAK_SUBJECT_NOT_ACKNOWLEDGED}. The tuple is a link key only (see
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

    /** Tuple fields in their fixed order; the first and the last three are optional. */
    private static final List<String> TUPLE_FIELDS = List.of(DcqlQueryBuilder.ISSUING_COUNTRY_CLAIM, "family_name",
            "given_name", "birthdate", "place_of_birth.country", "place_of_birth.region", "place_of_birth.locality");
    private static final List<String> REQUIRED_TUPLE_FIELDS = List.of("family_name", "given_name", "birthdate");

    private final RealmWalletPepper peppers;

    public WalletSubjectResolver(final RealmWalletPepper peppers) {
        this.peppers = peppers;
    }

    /**
     * The subject for {@code matched} (Task 14's DCQL result) in {@code realmId} under the provider's subject
     * configuration. Never {@code null}; an unusable PID is {@link WalletSubject.Unavailable}.
     *
     * @throws WalletVerificationException {@code INVALID_RESPONSE} when the presentations contradict each other (see
     *                                      {@link WalletAttributeMapper#pidAttributes} and the class javadoc)
     * @throws IllegalStateException       when the realm's pepper cannot be created (see {@link RealmWalletPepper})
     */
    public WalletSubject resolve(final String realmId, final MatchedPresentations matched,
            final WalletProviderConfig.Subject subjectConfig) {
        Objects.requireNonNull(realmId, "realmId");
        Objects.requireNonNull(matched, "matched");
        Objects.requireNonNull(subjectConfig, "subjectConfig");
        if (subjectConfig.strategy() == WalletProviderConfig.Subject.Strategy.NONE) {
            return unavailable(realmId, WalletSubject.Reason.STRATEGY_NOT_SUPPORTED);
        }
        final Map<String, String> attributes = WalletAttributeMapper.pidAttributes(matched);
        final String number = administrativeNumber(matched);
        final String country = attributes.get(DcqlQueryBuilder.ISSUING_COUNTRY_CLAIM);
        if (number != null && country != null && !country.isBlank()) {
            final String input = country.trim().toUpperCase(Locale.ROOT) + ":" + number;
            return resolved(realmId, new WalletSubject.AdminNumber(hmacHex(peppers.pepper(realmId), input)));
        }
        if (!subjectConfig.acknowledgeWeakSubject()) {
            return unavailable(realmId, WalletSubject.Reason.WEAK_SUBJECT_NOT_ACKNOWLEDGED);
        }
        for (final String field : REQUIRED_TUPLE_FIELDS) {
            final String value = attributes.get(field);
            if (value == null || normalise(value).isEmpty()) {
                return unavailable(realmId, WalletSubject.Reason.MISSING_IDENTITY_ATTRIBUTES);
            }
        }
        return resolved(realmId, new WalletSubject.Tuple(hmacHex(peppers.pepper(realmId), tupleInput(attributes))));
    }

    // ------------------------------------------------------------------------------------------- number

    /** The authoritative presentation's number (SD-JWT, else mdoc), trimmed; {@code null} when absent or blank. */
    private static String administrativeNumber(final MatchedPresentations matched) {
        String fromSdJwt = null;
        String fromMdoc = null;
        for (final VerifiedPresentation vp : matched.presentations()) {
            final Map<String, Object> claims = vp.claims() == null ? Map.of() : vp.claims();
            if (DcqlQueryBuilder.SD_JWT_FORMAT.equals(vp.format())) {
                fromSdJwt = text(claims.get(DcqlQueryBuilder.ADMINISTRATIVE_NUMBER_CLAIM));
            } else if (DcqlQueryBuilder.MDOC_FORMAT.equals(vp.format())
                    && claims.get(DcqlQueryBuilder.PID_NAMESPACE) instanceof Map<?, ?> elements) {
                fromMdoc = text(elements.get(DcqlQueryBuilder.ADMINISTRATIVE_NUMBER_CLAIM));
            }
        }
        if (fromSdJwt != null && fromMdoc != null && !fromSdJwt.equals(fromMdoc)) {
            throw new WalletVerificationException(WalletErrorCode.INVALID_RESPONSE,
                    "the sd-jwt and mdoc presentations disagree on the administrative number");
        }
        return fromSdJwt != null ? fromSdJwt : fromMdoc;
    }

    private static String text(final Object raw) {
        if (!(raw instanceof String value)) {
            return null;
        }
        final String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    // ------------------------------------------------------------------------------------------- tuple

    private static String tupleInput(final Map<String, String> attributes) {
        final StringBuilder input = new StringBuilder(TUPLE_VERSION);
        for (final String field : TUPLE_FIELDS) {
            final String raw = attributes.get(field);
            if (raw == null) {
                continue;
            }
            final String value = normalise(raw);
            if (value.isEmpty()) {
                continue;
            }
            input.append(field).append('=').append(value.length()).append(':').append(value).append(';');
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
        final String value = subject instanceof WalletSubject.AdminNumber a ? a.value()
                : ((WalletSubject.Tuple) subject).value();
        LOG.info("wallet: subject resolved, realm={} kind={} subject={}", LogSafe.sanitize(realmId), kind, value);
        return subject;
    }

    private static WalletSubject unavailable(final String realmId, final WalletSubject.Reason reason) {
        LOG.info("wallet: no subject, realm={} reason={}", LogSafe.sanitize(realmId), reason.code());
        return new WalletSubject.Unavailable(reason);
    }
}
