/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** Structured theming §6: the page CSP — no inline styles, per-realm image origins, CAPTCHA hosts only when enabled. */
class PageCspPolicyTest {

    @Test
    void withoutARealmTheme_imagesAreSelfAndDataOnly_andNoInlineStylesAnywhere() {
        final String csp = PageCspPolicy.build(Set.of(), null, false);
        assertThat(csp).contains("style-src 'self';", "img-src 'self' data:;", "script-src 'self';", "frame-src 'none';",
                "connect-src 'self';", "form-action 'self'", "frame-ancestors 'none'", "object-src 'none'")
                .doesNotContain("unsafe-inline").doesNotContain("https:;");
    }

    @Test
    void theRealmsOriginsAreListed_sorted_andAnythingThatIsNotAnHttpsOriginIsDropped() {
        final String csp = PageCspPolicy.build(List.of("https://cdn.b.example", "https://cdn.a.example:8443",
                "http://plain.example", "https://x.example/path", "*", "https: 'unsafe-inline'"), null, false);
        assertThat(csp).contains("img-src 'self' data: https://cdn.a.example:8443 https://cdn.b.example;")
                .doesNotContain("plain.example").doesNotContain("/path").doesNotContain("unsafe-inline");
    }

    @Test
    void captchaHostsOnlyForTheEnabledProvider_andSamlPagesMayPostToHttps() {
        assertThat(PageCspPolicy.build(Set.of(), "turnstile", false))
                .contains("script-src 'self' https://challenges.cloudflare.com;",
                        "frame-src https://challenges.cloudflare.com;",
                        "connect-src 'self' https://challenges.cloudflare.com;").doesNotContain("google");
        assertThat(PageCspPolicy.build(Set.of(), "recaptcha", false))
                .contains("script-src 'self' https://www.google.com https://www.gstatic.com;",
                        "frame-src https://www.google.com;").doesNotContain("cloudflare");
        assertThat(PageCspPolicy.build(Set.of(), null, true)).endsWith("form-action 'self' https:");
    }
}
