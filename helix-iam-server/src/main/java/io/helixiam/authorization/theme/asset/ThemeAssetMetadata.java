/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.asset;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.helixiam.authorization.theme.ThemeUrls;

import java.time.Instant;

/**
 * What is known about an uploaded theme asset, without its bytes. This is the admin list entry, the audit detail
 * source and the realm-export entry.
 *
 * @param id          random id, unique across realms; part of the public URL
 * @param realmId     owning realm (not serialised: the path already names it)
 * @param kind        font or image
 * @param name        font family name, or the image's display name
 * @param ext         {@code woff2}, {@code svg}, {@code png} or {@code webp}
 * @param contentType served content type
 * @param size        bytes
 * @param sha256      hex SHA-256 of the content (the ETag)
 * @param weight      font weight ({@code 400}) or variable range ({@code 100 900}); null for images
 * @param style       {@code normal} or {@code italic}; null for images
 * @param created     upload time
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true) // read-only in exports: an export must re-import
public record ThemeAssetMetadata(String id, @JsonIgnore String realmId, ThemeAssetKind kind, String name, String ext,
                                 String contentType, int size, String sha256, String weight, String style,
                                 Instant created) {

    /** The public path, {@code /realms/{realm}/theme/assets/{id}.{ext}}. */
    @JsonProperty("url")
    public String url() {
        return ThemeUrls.assetPath(realmId, id, ext);
    }
}
