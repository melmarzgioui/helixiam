/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller;

import io.helixiam.authorization.amqp.user.UserAdminDto;
import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.amqp.user.UserAdminRef;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Map;

/**
 * The signed-in user's own profile ({@code /realms/{realm}/me}). It used to render "-" for every field (a
 * placeholder that was never wired up); it now shows the user's stored values, "Not set" only for empty ones.
 */
@Controller
public class ProfileController {

    private final ObjectProvider<UserAdminPublisher> users;

    public ProfileController(final ObjectProvider<UserAdminPublisher> users) {
        this.users = users;
    }

    /** One profile value; null when the user has not set it. */
    public record Profile(String username, String email, String givenName, String familyName, String phone) {
    }

    @GetMapping("/me")
    public String profile(@AuthenticationPrincipal final UserCredentials principal, final Model model) {
        model.addAttribute("profile", load(principal));
        return "me/profile";
    }

    private Profile load(final UserCredentials principal) {
        final UserAdminPublisher publisher = users.getIfAvailable();
        if (principal == null || publisher == null) {
            return new Profile(principal == null ? null : principal.getEmail(), null, null, null, null);
        }
        final UserAdminDto u = publisher.get(new UserAdminRef(RealmContextHolder.get(), principal.getUserId()));
        if (u == null) {
            return new Profile(principal.getEmail(), null, null, null, null);
        }
        final Map<String, String> a = u.attributes() == null ? Map.of() : u.attributes();
        return new Profile(blank(u.username()), blank(u.email()), blank(a.get("given_name")),
                blank(a.get("family_name")), blank(a.get("phone_number")));
    }

    private static String blank(final String v) {
        return v == null || v.isBlank() ? null : v;
    }
}
