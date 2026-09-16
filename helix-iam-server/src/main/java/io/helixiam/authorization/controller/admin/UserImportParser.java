/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Helix IAM B10: parses a bulk user-import payload — either a CSV (header row + one user per line) or a
 * JSON array of user objects — into validated {@link Row}s. {@code username} is required; {@code email}
 * and {@code enabled} (default true) are recognised columns/keys; everything else becomes a user attribute
 * (so {@code firstName}/{@code lastName}/{@code department}/… flow through). Pure + side-effect-free.
 */
public final class UserImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** One user to import. {@code password} is optional (null → the importer assigns a temp one + UPDATE_PASSWORD). */
    public record Row(String username, String email, boolean enabled, String password, Map<String, String> attributes) {
    }

    private UserImportParser() {
    }

    public static List<Row> parse(final String payload) {
        if (payload == null || payload.isBlank()) {
            throw new IllegalArgumentException("Import payload is empty.");
        }
        final String trimmed = payload.trim();
        final List<Row> rows = trimmed.startsWith("[") ? parseJson(trimmed) : parseCsv(trimmed);
        if (rows.isEmpty()) {
            throw new IllegalArgumentException("No users found in the import payload.");
        }
        return rows;
    }

    private static List<Row> parseJson(final String json) {
        try {
            final JsonNode array = MAPPER.readTree(json);
            final List<Row> rows = new ArrayList<>();
            for (final JsonNode node : array) {
                final String username = text(node, "username");
                if (username == null) {
                    throw new IllegalArgumentException("Each user must have a username.");
                }
                final Map<String, String> attrs = new LinkedHashMap<>();
                final JsonNode attrNode = node.get("attributes");
                if (attrNode != null && attrNode.isObject()) {
                    attrNode.fields().forEachRemaining(e -> attrs.put(e.getKey(), e.getValue().asText()));
                }
                final JsonNode enabled = node.get("enabled");
                rows.add(new Row(username, text(node, "email"), enabled == null || enabled.asBoolean(),
                        text(node, "password"), attrs));
            }
            return rows;
        } catch (final IllegalArgumentException e) {
            throw e;
        } catch (final Exception e) {
            throw new IllegalArgumentException("Invalid JSON import payload: " + e.getMessage());
        }
    }

    private static List<Row> parseCsv(final String csv) {
        final String[] lines = csv.split("\\r?\\n");
        final List<String> headers = splitCsv(lines[0]);
        final int usernameIdx = indexOf(headers, "username");
        if (usernameIdx < 0) {
            throw new IllegalArgumentException("CSV must have a 'username' column.");
        }
        final List<Row> rows = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            if (lines[i].isBlank()) {
                continue;
            }
            final List<String> cells = splitCsv(lines[i]);
            final String username = cell(cells, usernameIdx);
            if (username == null || username.isBlank()) {
                throw new IllegalArgumentException("Row " + i + " is missing a username.");
            }
            String email = null;
            String password = null;
            boolean enabled = true;
            final Map<String, String> attrs = new LinkedHashMap<>();
            for (int c = 0; c < headers.size(); c++) {
                final String key = headers.get(c).trim();
                final String value = cell(cells, c);
                if (value == null || value.isBlank() || c == usernameIdx) {
                    continue;
                }
                switch (key.toLowerCase(Locale.ROOT)) {
                    case "email" -> email = value;
                    case "password" -> password = value;
                    case "enabled" -> enabled = Boolean.parseBoolean(value);
                    default -> attrs.put(key, value);
                }
            }
            rows.add(new Row(username.trim(), email, enabled, password, attrs));
        }
        return rows;
    }

    private static List<String> splitCsv(final String line) {
        final List<String> out = new ArrayList<>();
        for (final String part : line.split(",", -1)) {
            out.add(part.trim());
        }
        return out;
    }

    private static int indexOf(final List<String> headers, final String name) {
        for (int i = 0; i < headers.size(); i++) {
            if (headers.get(i).trim().equalsIgnoreCase(name)) {
                return i;
            }
        }
        return -1;
    }

    private static String cell(final List<String> cells, final int idx) {
        if (idx < 0 || idx >= cells.size()) {
            return null;
        }
        final String v = cells.get(idx).trim();
        return v.isEmpty() ? null : v;
    }

    private static String text(final JsonNode node, final String field) {
        final JsonNode v = node.get(field);
        if (v == null || v.isNull()) {
            return null;
        }
        final String s = v.asText().trim();
        return s.isEmpty() ? null : s;
    }
}
