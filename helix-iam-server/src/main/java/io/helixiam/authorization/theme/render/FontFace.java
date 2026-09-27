/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.render;

/**
 * One uploaded font file of a realm, as {@code theme.css} needs it for an {@code @font-face} rule.
 *
 * @param family the family name the theme's {@code typography.fontSans}/{@code fontDisplay} refers to
 * @param url    the same-origin asset path {@code /realms/{realm}/theme/assets/{id}.woff2}
 * @param weight a weight ({@code 400}) or a variable range ({@code 100 900})
 * @param style  {@code normal} or {@code italic}
 */
public record FontFace(String family, String url, String weight, String style) {
}
