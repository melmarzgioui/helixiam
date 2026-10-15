/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.eid.EidLevelOfAssurance;
import io.helixiam.authorization.federation.eid.EidScheme;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import io.helixiam.authorization.federation.wallet.dcql.DcqlQueryBuilder;
import io.helixiam.authorization.federation.wallet.dcql.MatchedPresentations;

import java.text.Normalizer;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Maps a wallet login's verified PID presentation(s) ({@link MatchedPresentations}, Task 14's DCQL result, already
 * reduced to the requested claims) onto the {@link BrokeredIdentity} attributes and eIDAS level of assurance the
 * federation broker uses — the wallet's counterpart to {@code DefaultAttributeMapper} for OIDC/SAML/eID. Its result
 * is written as {@code VerifiedIdentityJson} (Task 18/19) and read back at {@link WalletIdentityProvider#callback};
 * from there it flows through the SAME {@code IdentityBroker} + {@code AttributeMapperRules} pipeline every other
 * provider uses, so an admin's per-IdP {@code mappers} CSV applies on top of this mapping with no wallet-specific
 * code (it reads {@link BrokeredIdentity#attributes()}, which is exactly what this class produces).
 *
 * <h2>Claim names</h2>
 * Output attribute names are Helix's canonical (SD-JWT VC) claim names from the ARF Annex 3.01 PID Rulebook v1.7
 * (17 July 2026, catalog commit {@code 6d8f7f84}; see docs/eudi-wallet-spec-notes.md §7.2, ARF v3.0.0) — the same
 * names {@code requestedClaims} and {@link DcqlQueryBuilder} use, nested members dotted — so a {@code dc+sd-jwt} and
 * an {@code mso_mdoc} presentation of the same PID produce identical attribute maps. A SD-JWT presentation's claims
 * already use these names (they were requested with them, and Task 14 already dropped whatever the query did not
 * ask for); an mdoc presentation's claims are read from the {@code eu.europa.ec.eudi.pid.1} namespace and translated
 * back via {@link #PID_ATTRIBUTE_ELEMENTS}, the Rulebook's SD-JWT VC claim name &harr; mdoc element id table,
 * restricted to what this mapper maps.
 *
 * <p><b>Mapped:</b> {@code given_name}, {@code family_name}, {@code birthdate} (normalised to {@code YYYY-MM-DD}),
 * {@code nationalities} (always treated as a list — even an mdoc's single-valued {@code nationality} element is one
 * — and joined with {@code ,}, the same convention {@code AttributeMapperRules} examples use for a multi-valued
 * claim), {@code place_of_birth.country/region/locality} (an object in BOTH encodings per the Rulebook — "object
 * (country/region/locality, &ge;1)" for SD-JWT VC, the mdoc map {@code {? "country", ? "region", ? "locality"}} for
 * one shared mdoc element — decomposed the same way {@code address} is, see {@link #PLACE_OF_BIRTH_ELEMENT}),
 * {@code address.formatted/country/region/locality/postal_code/street_address}
 * ({@code address.house_number} has no mdoc element per the Rulebook table — "not listed for mdoc" — so it is
 * SD-JWT VC only), {@code issuing_country}, {@code issuing_authority}, plus the Helix-only {@code
 * helix_wallet_format} and {@code helix_wallet_issuer} below. <b>Not mapped</b> (controller rulings, 2026-10-09):
 * {@code age_over_18} — dropped from the PID mapping even though a provider may still request it — and {@code
 * personal_administrative_number} — it feeds the wallet's subject strategy (Task 21), never the mapped attributes.
 * Any other disclosed claim is simply not in {@link #PID_ATTRIBUTE_ELEMENTS}/the SD-JWT claim set this class reads,
 * so it is never copied; claims the DCQL query did not request at all were already removed before this class ever
 * sees them.
 *
 * <h2>Both formats answered</h2>
 * When the wallet answered with both a {@code dc+sd-jwt} and an {@code mso_mdoc} presentation of the PID,
 * {@code given_name}, {@code family_name} and {@code birthdate} must agree after normalisation — trimmed, Unicode
 * NFC, case preserved (names are never case-folded) — or the login is refused ({@code INVALID_RESPONSE}: no
 * {@link WalletErrorCode} names a cross-format identity conflict, so this is the documented fallback). When they
 * agree, the SD-JWT presentation is authoritative for every other attribute and for {@code helix_wallet_issuer}; the
 * mdoc presentation is used only for that cross-check, never merged into the result.
 *
 * <h2>Level of assurance</h2>
 * {@code loa} is always {@link #LOA_HIGH} ({@code http://eidas.europa.eu/LoA/high}): reaching this mapper already
 * means the presentation's issuer certificate chain validated to one of the provider's configured PID trust
 * anchors, which is the strongest rung Helix's eIDAS ladder has for a remotely presented credential — the same rung
 * a SAML eIDAS high-assurance login gets ({@link EidScheme#EIDAS}; {@link EidScheme#EUDI_WALLET} delegates to its
 * ladder — maintainer decision, see {@code constraints.md}). {@code minimumLoa} is enforced via {@link
 * EidLevelOfAssurance#meetsMinimum}, but that call alone is not enough: with the asserted level fixed at the
 * ladder's top, {@code meetsMinimum} would also return {@code true} for a non-blank minimum
 * {@link EidLevelOfAssurance#rung} does not recognise at all, because an unrecognised rung is {@code 0} — the same
 * value a blank minimum gets, which is deliberately "always met". {@link #satisfiesMinimumLoa} refuses that case
 * explicitly instead of trusting a garbage/unreachable minimum as satisfied; in practice a stored {@code
 * minimumLoa} can never trigger it ({@link WalletConfigValidator} restricts it to a recognised eIDAS rung, so it
 * never exceeds {@code high}), but {@link #map} enforces it defensively rather than relying on that upstream check.
 *
 * <h2>Helix-only attributes</h2>
 * {@code helix_wallet_format} is {@code dc+sd-jwt}, {@code mso_mdoc} or {@code both} — which formats were actually
 * <em>presented</em>, not merely configured; {@code helix_wallet_issuer} is the issuer DN of the validated leaf
 * (the authoritative presentation's, when both were answered). {@code email} is always {@code null} and
 * {@code emailVerified} always {@code false}: a PID carries no email.
 */
public final class WalletAttributeMapper {

    /** The eIDAS rung this mapper always asserts (the ladder's top); see the class javadoc. */
    public static final String LOA_HIGH = "http://eidas.europa.eu/LoA/high";

    /** The single mdoc element holding the whole {@code place_of_birth} object (ARF Annex 3.01 PID Rulebook v1.7;
     *  docs/eudi-wallet-spec-notes.md §7.2: mdoc {@code place_of_birth} is ONE element whose value is the map
     *  {@code {? "country", ? "region", ? "locality"}} — unlike {@code address}, which the Rulebook gives as
     *  separate flat {@code resident_*} elements). Handled outside {@link #PID_ATTRIBUTE_ELEMENTS} because that
     *  table otherwise assumes a flat canonical-dotted-name &rarr; flat-mdoc-element mapping, which this claim
     *  does not fit. */
    private static final String PLACE_OF_BIRTH_ELEMENT = "place_of_birth";

    /** The sub-fields of {@code place_of_birth} in both encodings (notes §7.2: "object (country/region/locality,
     *  &ge;1)"), decomposed into dotted canonical names the same way {@code address.*} is. */
    private static final List<String> PLACE_OF_BIRTH_FIELDS = List.of("country", "region", "locality");

    /** Canonical SD-JWT VC claim name this mapper reads from an SD-JWT presentation &rarr; its mdoc element id in the
     *  {@code eu.europa.ec.eudi.pid.1} namespace (ARF Annex 3.01 PID Rulebook v1.7; docs/eudi-wallet-spec-notes.md
     *  §7.2). Restricted to the claims this mapper copies into Helix attributes — see the class javadoc for what is
     *  deliberately left out. Does NOT include {@code place_of_birth.*}; see {@link #PLACE_OF_BIRTH_ELEMENT}. */
    private static final Map<String, String> PID_ATTRIBUTE_ELEMENTS = pidAttributeElements();

    /** {@link #PID_ATTRIBUTE_ELEMENTS}'s keys, plus {@code address.house_number} (no mdoc element) and the
     *  {@code place_of_birth.*} dotted names (see {@link #PLACE_OF_BIRTH_FIELDS}). */
    private static final Set<String> MAPPED_CLAIMS = mappedClaims();

    /** Cross-checked between an SD-JWT and an mdoc presentation when both are answered; see the class javadoc. */
    private static final List<String> CROSS_CHECKED_CLAIMS = List.of("given_name", "family_name", "birthdate");

    private static final Pattern ISO_DATE = Pattern.compile("\\d{4}-\\d{2}-\\d{2}");

    private WalletAttributeMapper() {
    }

    private static Map<String, String> pidAttributeElements() {
        final Map<String, String> m = new LinkedHashMap<>();
        m.put("given_name", "given_name");
        m.put("family_name", "family_name");
        m.put("birthdate", "birth_date");
        m.put("nationalities", "nationality");
        m.put("address.formatted", "resident_address");
        m.put("address.country", "resident_country");
        m.put("address.region", "resident_state");
        m.put("address.locality", "resident_city");
        m.put("address.postal_code", "resident_postal_code");
        m.put("address.street_address", "resident_street");
        m.put("issuing_country", "issuing_country");
        m.put("issuing_authority", "issuing_authority");
        return Collections.unmodifiableMap(m);
    }

    private static Set<String> mappedClaims() {
        final Set<String> names = new LinkedHashSet<>(PID_ATTRIBUTE_ELEMENTS.keySet());
        names.add("address.house_number");
        for (final String field : PLACE_OF_BIRTH_FIELDS) {
            names.add(PLACE_OF_BIRTH_ELEMENT + "." + field);
        }
        return Collections.unmodifiableSet(names);
    }

    /**
     * Maps {@code matched}'s verified PID presentation(s) onto a {@link BrokeredIdentity}, enforcing
     * {@code minimumLoa} along the way.
     *
     * @param idpAlias        this wallet provider's alias ({@link BrokeredIdentity#idpAlias()})
     * @param externalSubject the identity's linking key; NOT computed here (see the wallet's subject strategy,
     *                        Task 21) — passed straight through to the result
     * @param matched         the DCQL-matched presentation(s) (Task 14); at least one of {@code dc+sd-jwt} /
     *                        {@code mso_mdoc}
     * @param minimumLoa      the provider's configured minimum level of assurance ({@code
     *                        WalletProviderConfig#minimumLoa()}), an eIDAS LoA URI, or {@code null}/blank for "any"
     * @throws WalletVerificationException {@code INVALID_RESPONSE} when there is no presentation to map, a claim's
     *                                      shape is wrong, the SD-JWT and mdoc presentations disagree on name or
     *                                      birthdate, or the asserted level of assurance does not meet
     *                                      {@code minimumLoa}
     */
    public static BrokeredIdentity map(final String idpAlias, final String externalSubject,
            final MatchedPresentations matched, final String minimumLoa) {
        Objects.requireNonNull(matched, "matched");
        if (!satisfiesMinimumLoa(minimumLoa)) {
            throw fail("the asserted level of assurance does not meet the configured minimum");
        }
        return new BrokeredIdentity(idpAlias, externalSubject, null, false, attributes(matched), LOA_HIGH);
    }

    /**
     * The mapped PID attributes of {@code matched} alone (the {@link #map} attributes, cross-format check included),
     * for callers that need the normalised identity without a {@link BrokeredIdentity}, such as
     * {@link WalletSubjectResolver}. {@code personal_administrative_number} is not among them (see the class
     * javadoc).
     *
     * @throws WalletVerificationException {@code INVALID_RESPONSE} as for {@link #map}, minus the LoA check
     */
    /**
     * Whether a requested PID claim ({@code pid.requestedClaims} name) ends up in the mapped attributes: itself, or,
     * for an object claim such as {@code place_of_birth}, as its dotted members. The verify-only release list may only
     * name such claims ({@link WalletVerifiedClaims}).
     */
    public static boolean isMappedClaim(final String requestedClaim) {
        if (requestedClaim == null || requestedClaim.isBlank()) {
            return false;
        }
        return MAPPED_CLAIMS.contains(requestedClaim)
                || MAPPED_CLAIMS.stream().anyMatch(name -> name.startsWith(requestedClaim + "."));
    }

    public static Map<String, String> pidAttributes(final MatchedPresentations matched) {
        return attributes(Objects.requireNonNull(matched, "matched"));
    }

    private static Map<String, String> attributes(final MatchedPresentations matched) {
        VerifiedPresentation sdJwt = null;
        VerifiedPresentation mdoc = null;
        for (final VerifiedPresentation vp : matched.presentations()) {
            if (DcqlQueryBuilder.SD_JWT_FORMAT.equals(vp.format())) {
                sdJwt = vp;
            } else if (DcqlQueryBuilder.MDOC_FORMAT.equals(vp.format())) {
                mdoc = vp;
            }
        }
        if (sdJwt == null && mdoc == null) {
            throw fail("no verified presentation to map");
        }

        final Map<String, String> sdJwtAttrs = sdJwt == null ? Map.of() : fromSdJwt(sdJwt.claims());
        final Map<String, String> mdocAttrs = mdoc == null ? Map.of() : fromMdoc(mdoc.claims());

        final Map<String, String> attributes = new LinkedHashMap<>();
        final String format;
        final String issuerDn;
        if (sdJwt != null && mdoc != null) {
            checkAgreement(sdJwtAttrs, mdocAttrs);
            attributes.putAll(sdJwtAttrs);
            format = "both";
            issuerDn = sdJwt.issuerSubjectDn();
        } else if (sdJwt != null) {
            attributes.putAll(sdJwtAttrs);
            format = DcqlQueryBuilder.SD_JWT_FORMAT;
            issuerDn = sdJwt.issuerSubjectDn();
        } else {
            attributes.putAll(mdocAttrs);
            format = DcqlQueryBuilder.MDOC_FORMAT;
            issuerDn = mdoc.issuerSubjectDn();
        }
        attributes.put("helix_wallet_format", format);
        attributes.put("helix_wallet_issuer", issuerDn);
        return Collections.unmodifiableMap(attributes);
    }

    // ------------------------------------------------------------------------------------------- per-source

    private static Map<String, String> fromSdJwt(final Map<String, Object> claims) {
        final Map<String, String> out = new LinkedHashMap<>();
        for (final String name : MAPPED_CLAIMS) {
            put(out, name, toAttributeValue(name, sdJwtRaw(claims, name)));
        }
        return out;
    }

    private static Object sdJwtRaw(final Map<String, Object> claims, final String name) {
        final int dot = name.indexOf('.');
        if (dot < 0) {
            return claims.get(name);
        }
        final Object nested = claims.get(name.substring(0, dot));
        return nested instanceof Map<?, ?> nestedMap ? nestedMap.get(name.substring(dot + 1)) : null;
    }

    private static Map<String, String> fromMdoc(final Map<String, Object> claims) {
        final Map<String, String> out = new LinkedHashMap<>();
        final Object namespace = claims.get(DcqlQueryBuilder.PID_NAMESPACE);
        if (!(namespace instanceof Map<?, ?> elements)) {
            return out;
        }
        for (final Map.Entry<String, String> entry : PID_ATTRIBUTE_ELEMENTS.entrySet()) {
            put(out, entry.getKey(), toAttributeValue(entry.getKey(), elements.get(entry.getValue())));
        }
        // place_of_birth is one shared mdoc element holding the whole object; decompose it the same way an SD-JWT
        // nested claim is (sdJwtRaw), rather than through the flat canonical->element table above.
        final Object placeOfBirth = elements.get(PLACE_OF_BIRTH_ELEMENT);
        if (placeOfBirth instanceof Map<?, ?> fields) {
            for (final String field : PLACE_OF_BIRTH_FIELDS) {
                final String name = PLACE_OF_BIRTH_ELEMENT + "." + field;
                put(out, name, toAttributeValue(name, fields.get(field)));
            }
        }
        return out;
    }

    private static void put(final Map<String, String> out, final String name, final String value) {
        if (value != null) {
            out.put(name, value);
        }
    }

    // ------------------------------------------------------------------------------------------- values

    /** {@code null} when {@code raw} is absent, or (defensively) shaped unlike a PID claim ever is: not mapped. */
    private static String toAttributeValue(final String name, final Object raw) {
        if (raw == null) {
            return null;
        }
        if ("nationalities".equals(name)) {
            final List<?> values = raw instanceof List<?> list ? list : List.of(raw);
            return values.stream().map(String::valueOf).map(WalletAttributeMapper::normalized)
                    .collect(Collectors.joining(","));
        }
        if (!(raw instanceof String text)) {
            return null;
        }
        final String value = normalized(text);
        if ("birthdate".equals(name) && !ISO_DATE.matcher(value).matches()) {
            throw fail("birthdate is not in YYYY-MM-DD form");
        }
        return value;
    }

    private static String normalized(final String raw) {
        return Normalizer.normalize(raw.trim(), Normalizer.Form.NFC);
    }

    // ------------------------------------------------------------------------------------------- cross-format

    private static void checkAgreement(final Map<String, String> sdJwtAttrs, final Map<String, String> mdocAttrs) {
        for (final String name : CROSS_CHECKED_CLAIMS) {
            final String fromSdJwt = sdJwtAttrs.get(name);
            final String fromMdoc = mdocAttrs.get(name);
            if (fromSdJwt != null && fromMdoc != null && !fromSdJwt.equals(fromMdoc)) {
                throw fail("the sd-jwt and mdoc presentations disagree on " + name);
            }
        }
    }

    // ------------------------------------------------------------------------------------------- level of assurance

    private static boolean satisfiesMinimumLoa(final String minimumLoa) {
        if (minimumLoa == null || minimumLoa.isBlank()) {
            return true;
        }
        return EidLevelOfAssurance.rung(EidScheme.EUDI_WALLET, minimumLoa) > 0
                && EidLevelOfAssurance.meetsMinimum(EidScheme.EUDI_WALLET, LOA_HIGH, minimumLoa);
    }

    private static WalletVerificationException fail(final String safeDetail) {
        return new WalletVerificationException(WalletErrorCode.INVALID_RESPONSE, safeDetail);
    }
}
