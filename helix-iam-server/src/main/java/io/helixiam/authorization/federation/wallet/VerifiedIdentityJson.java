/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;

import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * The stored form of a wallet login's mapped identity, {@code WalletTransaction.verifiedIdentityJson}: written when the
 * response endpoint (Task 18) completes a transaction, read by {@link WalletIdentityProvider#callback} after the
 * response code is redeemed. Task 20 (attribute mapping and LoA) fills it; this class only fixes the shape:
 *
 * <pre>{@code
 * {"v": 1, "externalSubject": "<non-blank>", "email": "<string>"?, "emailVerified": <boolean>,
 *  "attributes": {"<name>": "<string>", ...}, "levelOfAssurance": "<eIDAS LoA URI>"?}
 * }</pre>
 *
 * The provider alias is not stored: the reading provider supplies it. Reading is strict ({@link StrictJson}: no
 * duplicate members) and refuses unknown members, a wrong version, a blank subject and non-string attribute values, so
 * a corrupted record never becomes a login. It never holds the {@code vp_token} or disclosures.
 */
public final class VerifiedIdentityJson {

    /** The shape version this class writes and reads. */
    public static final int VERSION = 1;

    private static final Set<String> MEMBERS = Set.of("v", "externalSubject", "email", "emailVerified", "attributes",
            "levelOfAssurance");

    private VerifiedIdentityJson() {
    }

    /** The JSON for {@code identity} (its {@code idpAlias} is left out). */
    public static String write(final BrokeredIdentity identity) {
        final ObjectNode node = JsonNodeFactory.instance.objectNode();
        node.put("v", VERSION);
        node.put("externalSubject", identity.externalSubject());
        if (identity.email() != null) {
            node.put("email", identity.email());
        }
        node.put("emailVerified", identity.emailVerified());
        final ObjectNode attributes = node.putObject("attributes");
        if (identity.attributes() != null) {
            identity.attributes().forEach(attributes::put);
        }
        if (identity.levelOfAssurance() != null) {
            node.put("levelOfAssurance", identity.levelOfAssurance());
        }
        try {
            return StrictJson.MAPPER.writeValueAsString(node);
        } catch (final JsonProcessingException e) {
            throw new IllegalStateException("Could not encode the verified identity", e);
        }
    }

    /**
     * The identity stored in {@code json}, for the provider {@code idpAlias}.
     *
     * @throws WalletVerificationException {@code INVALID_RESPONSE} when {@code json} is not exactly this shape
     */
    public static BrokeredIdentity read(final String idpAlias, final String json) {
        if (json == null) {
            throw invalid();
        }
        final JsonNode node;
        try {
            node = StrictJson.MAPPER.readTree(json);
        } catch (final JsonProcessingException e) {
            throw invalid();
        }
        if (node == null || !node.isObject()) {
            throw invalid();
        }
        for (final Iterator<String> names = node.fieldNames(); names.hasNext(); ) {
            if (!MEMBERS.contains(names.next())) {
                throw invalid();
            }
        }
        if (!node.path("v").isIntegralNumber() || node.path("v").asInt() != VERSION
                || !node.path("externalSubject").isTextual() || node.path("externalSubject").asText().isBlank()
                || !node.path("emailVerified").isBoolean() || !node.path("attributes").isObject()
                || node.has("email") && !node.get("email").isTextual()
                || node.has("levelOfAssurance") && !node.get("levelOfAssurance").isTextual()) {
            throw invalid();
        }
        final Map<String, String> attributes = new LinkedHashMap<>();
        for (final Iterator<Map.Entry<String, JsonNode>> it = node.get("attributes").fields(); it.hasNext(); ) {
            final Map.Entry<String, JsonNode> entry = it.next();
            if (!entry.getValue().isTextual()) {
                throw invalid();
            }
            attributes.put(entry.getKey(), entry.getValue().asText());
        }
        return new BrokeredIdentity(idpAlias, node.get("externalSubject").asText(),
                node.has("email") ? node.get("email").asText() : null, node.get("emailVerified").asBoolean(),
                Collections.unmodifiableMap(attributes),
                node.has("levelOfAssurance") ? node.get("levelOfAssurance").asText() : null);
    }

    private static WalletVerificationException invalid() {
        return new WalletVerificationException(WalletErrorCode.INVALID_RESPONSE, "stored wallet identity is malformed");
    }
}
