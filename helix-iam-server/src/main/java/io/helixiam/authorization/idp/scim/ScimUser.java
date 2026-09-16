/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.scim;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

/**
 * Helix IAM E7 (SCIM 2.0): a SCIM User resource (RFC 7643 §4.1) — the subset Helix maps onto its own
 * user model: {@code userName}, {@code name.{givenName,familyName}}, {@code emails}, {@code active},
 * {@code groups}, plus {@code id}/{@code meta}. Unknown attributes are tolerated on input.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ScimUser(List<String> schemas, String id, String userName, Name name, List<Email> emails,
                       Boolean active, List<Ref> groups, Meta meta) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Name(String givenName, String familyName, String formatted) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Email(String value, String type, Boolean primary) {
    }

    /** A multi-valued reference (group membership) — {@code value} is the referenced id, {@code display} a label. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Ref(String value, String display) {
    }
}
