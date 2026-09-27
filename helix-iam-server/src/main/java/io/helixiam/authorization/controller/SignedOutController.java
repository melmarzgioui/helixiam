/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * The realm's "You're signed out" page ({@code /realms/{realm}/signed-out}): where an RP-initiated logout without a
 * {@code post_logout_redirect_uri} ends, instead of the server root. Themed, with a link back to sign in.
 */
@Controller
public class SignedOutController {

    /** The path, relative to the realm. */
    public static final String PATH = "/signed-out";

    @GetMapping(PATH)
    public String signedOut() {
        return "logout/signed-out";
    }
}
