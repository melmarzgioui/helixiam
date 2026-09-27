/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller;

import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.theme.asset.ThemeAssetKind;
import io.helixiam.authorization.theme.asset.ThemeAssetMetadata;
import io.helixiam.authorization.theme.asset.ThemeAssetService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Serves uploaded theme fonts and images at {@code /realms/{realm}/theme/assets/{id}.{ext}} (spec §3), anonymously,
 * because sign-in pages and emails load them before anyone is signed in. {@code RealmRoutingFilter} strips the realm
 * prefix (and 404s an unknown realm), so this maps the flat {@code /theme/assets/{file}} and reads the realm from
 * {@link RealmContextHolder}; {@code SecurityConfig} permits exactly {@code GET}/{@code HEAD} of
 * {@code /theme/assets/*}.
 *
 * <p>An id of another realm, an extension that does not match the stored one, and anything malformed are 404s.
 * Responses carry the stored content type, {@code X-Content-Type-Options: nosniff},
 * {@code Content-Disposition: inline; filename="{id}.{ext}"}, the SHA-256 as a strong {@code ETag} (304 on a match)
 * and a year-long immutable {@code Cache-Control}, since an id's content never changes. An SVG also gets
 * {@code Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox}, so opening it directly
 * can never run anything even if a validator rule were missed.
 */
@RestController
public class ThemeAssetController {

    /** The CSP of a served SVG. */
    public static final String SVG_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox";
    /** The CSP of every other served asset. */
    public static final String ASSET_CSP = "default-src 'none'; sandbox";
    private static final String CACHE = "public, max-age=31536000, immutable";
    private static final Pattern FILE = Pattern.compile("([A-Za-z0-9_-]{1,64})\\.([a-z0-9]{2,5})");

    private final ThemeAssetService assets;

    public ThemeAssetController(final ThemeAssetService assets) {
        this.assets = assets;
    }

    @GetMapping("/theme/assets/{file}")
    public void asset(@PathVariable final String file, final HttpServletRequest request,
                      final HttpServletResponse response) throws IOException {
        final String realm = RealmContextHolder.get();
        final Matcher m = FILE.matcher(file);
        if (realm == null || !m.matches()) {
            notFound(response);
            return;
        }
        final Optional<ThemeAssetMetadata> found = assets.find(realm, m.group(1))
                .filter(a -> a.ext().equals(m.group(2)));
        if (found.isEmpty()) {
            notFound(response);
            return;
        }
        final ThemeAssetMetadata meta = found.get();
        final String etag = "\"" + meta.sha256() + "\"";
        response.setHeader("ETag", etag);
        response.setHeader("Cache-Control", CACHE);
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Content-Security-Policy", "svg".equals(meta.ext()) ? SVG_CSP : ASSET_CSP);
        response.setHeader("Cross-Origin-Resource-Policy", meta.kind() == ThemeAssetKind.FONT ? "same-site" : "cross-origin");
        if (matches(request.getHeader("If-None-Match"), etag)) {
            response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            return;
        }
        final Optional<ThemeAssetService.StoredAsset> content = assets.content(realm, meta.id());
        if (content.isEmpty()) { // deleted in between
            notFound(response);
            return;
        }
        final byte[] bytes = content.get().bytes();
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(meta.contentType());
        response.setHeader("Content-Disposition", "inline; filename=\"" + meta.id() + "." + meta.ext() + "\"");
        response.setContentLength(bytes.length);
        if (!"HEAD".equalsIgnoreCase(request.getMethod())) {
            response.getOutputStream().write(bytes);
        }
    }

    private static boolean matches(final String ifNoneMatch, final String etag) {
        if (ifNoneMatch == null) {
            return false;
        }
        for (final String candidate : ifNoneMatch.split(",")) {
            final String c = candidate.trim();
            if (c.equals("*") || c.equals(etag) || c.equals("W/" + etag)) {
                return true;
            }
        }
        return false;
    }

    private static void notFound(final HttpServletResponse response) throws IOException {
        // setStatus, not sendError: an error dispatch would go through the security chain's /error handling.
        response.setStatus(HttpServletResponse.SC_NOT_FOUND);
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Cache-Control", "no-store");
        response.setContentType("text/plain;charset=UTF-8");
        response.getWriter().write("Not found.");
    }
}
