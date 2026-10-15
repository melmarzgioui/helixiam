/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import io.helixiam.common.json.JsonMappers;
import io.helixiam.common.json.JsonNodes;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/** The stored form of verified services ({@code trusted_list_source.services_json}): a JSON array. */
final class ServicesCodec {

    private static final ObjectMapper JSON = JsonMappers.plain();

    private ServicesCodec() {
    }

    static String encode(final List<ListedService> services) {
        final ArrayNode array = JSON.createArrayNode();
        for (final ListedService s : services) {
            final ObjectNode o = array.addObject();
            try {
                o.put("certificate", Base64.getEncoder().encodeToString(s.certificate().getEncoded()));
            } catch (final CertificateEncodingException e) {
                throw new IllegalStateException("a verified certificate could not be encoded", e);
            }
            o.put("serviceType", s.serviceType());
            o.put("serviceName", s.serviceName());
            o.put("provider", s.provider());
            o.put("country", s.country());
            o.put("status", s.status());
        }
        try {
            return JSON.writeValueAsString(array);
        } catch (final JacksonException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The stored services; a row that cannot be read yields none (fail closed), never an exception. */
    static List<ListedService> decode(final String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        final List<ListedService> out = new ArrayList<>();
        try {
            for (final JsonNode n : JSON.readTree(json)) {
                out.add(new ListedService(Etsi119612List.certificate(JsonNodes.text(n.path("certificate"), null)),
                        JsonNodes.text(n.path("serviceType")), text(n, "serviceName"), text(n, "provider"),
                        text(n, "country"), text(n, "status")));
            }
        } catch (final TrustedListException | RuntimeException e) {
            return List.of();
        }
        return List.copyOf(out);
    }

    private static String text(final JsonNode n, final String field) {
        final JsonNode v = n.get(field);
        return v == null || v.isNull() ? null : JsonNodes.text(v);
    }
}
