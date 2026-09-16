/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ProfileController {


    @GetMapping("/me")
    public String registration(final Model model) {
        model.addAttribute("username", "-");
        model.addAttribute("firstName", "-");
        model.addAttribute("lastName", "-");
        model.addAttribute("mobilePhone", "-");

        return "me/profile";
    }
}
