/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller;

import io.helixiam.authorization.theme.render.ThemePageResolver;
import io.helixiam.authorization.theme.render.ThemeWebConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.ui.Model;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Puts the effective theme of the current realm — overridden field by field by the organization in context, if any —
 * into a page's model as {@code hx} ({@link io.helixiam.authorization.theme.render.ThemePage}). The shared fragment
 * {@code templates/fragments/theme.html} renders the logo, favicon, texts, links and the {@code theme.css} link from
 * it. {@link ThemeWebConfig} adds the same attribute to every page that does not call this; controllers call it only
 * when they build a model before rendering. Best-effort, never throws.
 */
@Component
public class BrandingSupport {

    @Autowired(required = false)
    private ThemePageResolver pages;

    public void apply(final Model model) {
        if (pages == null || model.containsAttribute(ThemeWebConfig.MODEL_ATTRIBUTE)
                || !(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs)) {
            return;
        }
        model.addAttribute(ThemeWebConfig.MODEL_ATTRIBUTE, pages.current(attrs.getRequest()));
    }
}
