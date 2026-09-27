/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A browser session logged in to the realm login form as an administrator, for calling {@code /admin/**}
 * the way the console does: session cookie + double-submit CSRF ({@code X-XSRF-TOKEN} header echoing the
 * {@code XSRF-TOKEN} cookie) on every write. Without that header admin writes are rejected (403); without a
 * session {@code /admin/**} answers 401 (never a 302 to the login page).
 *
 * <p>Admin authority: {@code AdminAuthorizationManager} grants a realm's routes to an admin of that realm
 * (authority {@code admin_<realm>}) — the bootstrapped master {@code admin} user qualifies for master.
 */
public final class E2eAdminSession {

    private final E2eHttp http;
    private E2eAdminSession(final E2eHttp http) {
        this.http = http;
    }

    /**
     * Logs {@code username} in via {@code GET/POST /realms/{realm}/login} (password-only path) and returns
     * the authenticated session. Fails if the login bounces back to {@code /login?error…}.
     */
    public static E2eAdminSession login(final E2eHttp http, final String realm, final String username,
                                        final String password) {
        final E2eHttp.Response page = http.get("/realms/" + realm + "/login");
        OidcFlow.expectStatus(page, 200);
        final String action = E2eHttp.formAction(page.body(), "name=\"password\"")
                .orElseThrow(() -> new AssertionError("No login form: " + page));
        final Map<String, String> form = new LinkedHashMap<>(E2eHttp.hiddenInputs(
                E2eHttp.form(page.body(), "name=\"password\"").orElseThrow()));
        form.put("username", username);
        form.put("password", password);
        final E2eHttp.Response result = http.postForm(action, form);
        if (!result.isRedirect() || result.locationStartsWith(http.base() + "realms/" + realm + "/login")) {
            throw new AssertionError("Admin login failed for '" + username + "': " + result);
        }
        // The success handler redirects to sp.base.url (no saved request); nothing to follow.
        return new E2eAdminSession(http);
    }

    /** The underlying browser (cookies: session + XSRF-TOKEN). */
    public E2eHttp http() {
        return http;
    }

    public E2eHttp.Response get(final String path) {
        return http.get(path, "Accept", "application/json");
    }

    public E2eHttp.Response post(final String path, final Object json) {
        return http.sendJson("POST", path, json, withXsrf(path));
    }

    public E2eHttp.Response put(final String path, final Object json) {
        return http.sendJson("PUT", path, json, withXsrf(path));
    }

    public E2eHttp.Response delete(final String path) {
        return http.delete(path, withXsrf(path));
    }

    /** Multipart upload of one file (plus form fields), with the CSRF header. */
    public E2eHttp.Response upload(final String path, final java.util.Map<String, String> fields, final String filename,
                                   final String contentType, final byte[] content) {
        return http.postMultipart(path, fields, "file", filename, contentType, content, withXsrf(path));
    }

    /** POST a raw body (e.g. a zip), with the CSRF header. */
    public E2eHttp.Response postBytes(final String path, final String contentType, final byte[] body) {
        return http.postBytes(path, contentType, body, withXsrf(path));
    }

    /** GET returning raw bytes (e.g. a zip). */
    public E2eHttp.BytesResponse getBytes(final String path) {
        return http.getBytes(path, "Accept", "application/zip, application/json");
    }

    private String[] withXsrf(final String path) {
        if (http.cookieFor("XSRF-TOKEN", path).isEmpty()) {
            // Login rotates the CSRF token, and the cookie is scoped to the request's path; a safe GET on the
            // same path makes the server write the one this write will be checked against.
            http.get(path, "Accept", "application/json");
        }
        final String token = http.cookieFor("XSRF-TOKEN", path)
                .orElseThrow(() -> new AssertionError("No XSRF-TOKEN cookie for " + path));
        return new String[] {"X-XSRF-TOKEN", token, "Accept", "application/json"};
    }
}
