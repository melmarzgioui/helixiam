/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Field-level differences between two theme layers — for audit ("fields changed", never values) and validation. */
public final class ThemeDiff {

    private ThemeDiff() {
    }

    /** JSON paths of every leaf that was added, changed or removed (e.g. {@code colors.primary.light}). */
    public static List<String> changedFields(final Theme before, final Theme after) {
        final Set<String> out = new LinkedHashSet<>();
        diff("", ThemeJson.tree(before), ThemeJson.tree(after), out);
        return new ArrayList<>(out);
    }

    private static void diff(final String path, final JsonNode a, final JsonNode b, final Set<String> out) {
        if (a != null && b != null && a.isObject() && b.isObject()) {
            final Set<String> keys = new LinkedHashSet<>();
            a.fieldNames().forEachRemaining(keys::add);
            b.fieldNames().forEachRemaining(keys::add);
            for (final String k : keys) {
                diff(path.isEmpty() ? k : path + "." + k, a.get(k), b.get(k), out);
            }
            return;
        }
        if (a == null || b == null || !a.equals(b)) {
            if ((a != null && a.isObject()) || (b != null && b.isObject())) {
                diff(path, a == null ? JsonNodeFactory.instance.objectNode() : a,
                        b == null ? JsonNodeFactory.instance.objectNode() : b, out);
            } else {
                out.add(path);
            }
        }
    }

    /**
     * A layer holding only what {@code after} sets differently from {@code before} (removed fields are omitted) —
     * what a partial update actually introduces, so it can be validated on its own.
     */
    public static Theme delta(final Theme before, final Theme after) {
        final JsonNode kept = keepChanged(ThemeJson.tree(before), ThemeJson.tree(after));
        return kept == null ? Theme.EMPTY : ThemeJson.read(kept.toString());
    }

    private static JsonNode keepChanged(final JsonNode a, final JsonNode b) {
        if (b == null || b.isNull() || b.equals(a)) {
            return null;
        }
        if (!b.isObject() || a == null || !a.isObject()) {
            return b;
        }
        final ObjectNode out = JsonNodeFactory.instance.objectNode();
        final Iterator<String> names = b.fieldNames();
        while (names.hasNext()) {
            final String k = names.next();
            final JsonNode child = keepChanged(a.get(k), b.get(k));
            if (child != null) {
                out.set(k, child);
            }
        }
        return out.isEmpty() ? null : out;
    }
}
