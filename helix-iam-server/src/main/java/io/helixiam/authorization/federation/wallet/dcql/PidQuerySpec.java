/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.dcql;

import java.util.List;

/**
 * What a PID request asks for, independent of where it is configured ({@code WalletProviderConfig.Pid#toQuerySpec}).
 *
 * @param sdJwtVcts       accepted SD-JWT VC types, the base {@code urn:eudi:pid:1} plus any national PID types
 *                        (notes §7.1); needed only when {@code dc+sd-jwt} is requested
 * @param mdocDoctype     the mdoc docType, used as given; {@link #DEFAULT_MDOC_DOCTYPE} is the PID one. Needed only
 *                        when {@code mso_mdoc} is requested
 * @param requestedClaims PID claims in Helix's canonical (SD-JWT VC) names, nested members dotted, e.g.
 *                        {@code given_name}, {@code birthdate}, {@code address.street_address}; see
 *                        {@link DcqlQueryBuilder} for the accepted names
 */
public record PidQuerySpec(List<String> sdJwtVcts, String mdocDoctype, List<String> requestedClaims) {

    /** ARF Annex 2 PID_04: the doctype of an ISO/IEC 18013-5 PID. */
    public static final String DEFAULT_MDOC_DOCTYPE = "eu.europa.ec.eudi.pid.1";

    public PidQuerySpec {
        sdJwtVcts = sdJwtVcts == null ? List.of() : List.copyOf(sdJwtVcts);
        requestedClaims = requestedClaims == null ? List.of() : List.copyOf(requestedClaims);
    }
}
