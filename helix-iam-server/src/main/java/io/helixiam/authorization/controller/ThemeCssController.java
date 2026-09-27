/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller;

import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.theme.render.ThemeStylesheet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * {@code GET /realms/{realm}/theme.css} (spec §2): the realm's generated stylesheet — {@code --hx-*} custom properties,
 * {@code @font-face} rules for its uploaded fonts, then its validated custom CSS. Public (sign-in pages load it before
 * anyone is signed in), realm-scoped by {@code RealmRoutingFilter}, and cacheable: a strong ETag (the SHA-256 of the
 * bytes), {@code Cache-Control: public, max-age=300}, and a 304 for a matching {@code If-None-Match}. Pages link it
 * with {@code ?v=<version>}, so a theme change reaches them at once despite the max-age.
 *
 * <p>{@code ?org=} selects an organization's theme, but only an organization of the path realm; any other value
 * (unknown, or another realm's organization) gets the realm theme.
 */
@RestController
public class ThemeCssController {

    /** Longest {@code ?org=} value looked up; organization ids are far shorter. */
    static final int MAX_ORG_HINT = 128;

    private final ThemeStylesheet stylesheets;

    public ThemeCssController(final ThemeStylesheet stylesheets) {
        this.stylesheets = stylesheets;
    }

    @GetMapping("/theme.css")
    public void themeCss(@RequestParam(name = "org", required = false) final String org,
                         final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        final String realm = RealmContextHolder.get();
        if (realm == null) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND); // setStatus: no /error dispatch
            return;
        }
        final Optional<String> orgHint = Optional.ofNullable(org)
                .filter(o -> !o.isBlank() && o.length() <= MAX_ORG_HINT);
        final ThemeStylesheet.Rendered css = stylesheets.forRealm(realm, orgHint);
        final String etag = "\"" + css.etag() + "\"";
        response.setHeader("ETag", etag);
        response.setHeader("Cache-Control", "public, max-age=300");
        response.setHeader("X-Content-Type-Options", "nosniff");
        if (matches(request.getHeader("If-None-Match"), etag)) {
            response.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            return;
        }
        final byte[] body = css.css().getBytes(StandardCharsets.UTF_8);
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/css; charset=utf-8");
        response.setContentLength(body.length);
        response.getOutputStream().write(body);
    }

    /** RFC 9110 If-None-Match: weak comparison over a list of entity tags, or {@code *}. */
    static boolean matches(final String ifNoneMatch, final String etag) {
        if (ifNoneMatch == null || ifNoneMatch.isBlank()) {
            return false;
        }
        for (final String candidate : ifNoneMatch.split(",")) {
            String tag = candidate.strip();
            if ("*".equals(tag)) {
                return true;
            }
            if (tag.startsWith("W/")) {
                tag = tag.substring(2);
            }
            if (tag.equals(etag)) {
                return true;
            }
        }
        return false;
    }
}
