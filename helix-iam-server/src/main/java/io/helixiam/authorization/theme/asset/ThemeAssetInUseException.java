/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.asset;

import java.util.List;

/** An asset cannot be deleted because theme fields still reference it (the admin API answers 409). */
public class ThemeAssetInUseException extends RuntimeException {

    private final transient List<String> references;

    public ThemeAssetInUseException(final List<String> references) {
        super("The asset is still used by " + String.join(", ", references) + ".");
        this.references = List.copyOf(references);
    }

    /** The referencing fields, e.g. {@code theme.assets.logoUrl} or {@code organizations.{id}.theme.assets.logoUrl}. */
    public List<String> references() {
        return references;
    }
}
