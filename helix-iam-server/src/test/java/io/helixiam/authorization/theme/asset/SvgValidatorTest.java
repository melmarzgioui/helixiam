/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.asset;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * Spec §3: an uploaded SVG is parsed with a hardened XML parser and REJECTED (never rewritten) when it contains
 * anything that can run script, fetch another resource or change how references resolve. The malicious corpus
 * below covers every rule; the benign corpus holds the shapes real design tools export, which must pass.
 */
class SvgValidatorTest {

    private static final String NS = "xmlns=\"http://www.w3.org/2000/svg\"";
    private static final String XLINK = "xmlns:xlink=\"http://www.w3.org/1999/xlink\"";

    private static Optional<String> check(final String svg) {
        return SvgValidator.problem(svg.getBytes(StandardCharsets.UTF_8));
    }

    private static String svg(final String body) {
        return "<svg " + NS + " " + XLINK + " viewBox=\"0 0 10 10\">" + body + "</svg>";
    }

    static Stream<Arguments> malicious() {
        return Stream.of(
                arguments("script element", svg("<script>alert(1)</script>"), "script"),
                arguments("script in the XHTML namespace",
                        svg("<h:script xmlns:h=\"http://www.w3.org/1999/xhtml\">alert(1)</h:script>"), "script"),
                arguments("script hidden in metadata",
                        svg("<metadata><h:script xmlns:h=\"http://www.w3.org/1999/xhtml\">alert(1)</h:script></metadata>"),
                        "script"),
                arguments("foreignObject",
                        svg("<foreignObject width=\"10\" height=\"10\"><div xmlns=\"http://www.w3.org/1999/xhtml\">x</div>"
                                + "</foreignObject>"), "foreignObject"),
                arguments("onload on the root", "<svg " + NS + " onload=\"alert(1)\"/>", "onload"),
                arguments("upper-case ONCLICK", svg("<rect ONCLICK=\"alert(1)\" width=\"1\" height=\"1\"/>"), "ONCLICK"),
                arguments("onbegin on animate", svg("<animate onbegin=\"alert(1)\" attributeName=\"x\" dur=\"1s\"/>"),
                        "onbegin"),
                arguments("namespaced event attribute",
                        svg("<rect xmlns:ev=\"http://www.w3.org/2001/xml-events\" ev:onclick=\"alert(1)\"/>"), "onclick"),
                arguments("javascript: link", svg("<a href=\"javascript:alert(1)\"><rect width=\"1\" height=\"1\"/></a>"),
                        "href"),
                arguments("entity-encoded javascript: xlink",
                        svg("<a xlink:href=\"jav&#x09;ascript:alert(1)\"><rect/></a>"), "href"),
                arguments("mixed-case javascript: with spaces",
                        svg("<a href=\"  JaVaScRiPt:alert(1)\"><rect/></a>"), "href"),
                arguments("data: link", svg("<a href=\"data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;\"><rect/></a>"),
                        "href"),
                arguments("external link", svg("<a href=\"https://evil.example/\"><rect/></a>"), "href"),
                arguments("image from another origin", svg("<image href=\"https://evil.example/x.png\" width=\"1\"/>"),
                        "image"),
                arguments("image as data: URI", svg("<image href=\"data:image/png;base64,iVBORw0KGgo=\"/>"), "image"),
                arguments("feImage", svg("<filter id=\"f\"><feImage href=\"https://evil.example/x.svg\"/></filter>"),
                        "feImage"),
                arguments("use of another document", svg("<use href=\"https://evil.example/sprite.svg#icon\"/>"), "use"),
                arguments("use of a relative document", svg("<use xlink:href=\"other.svg#x\"/>"), "use"),
                arguments("style attribute url() to another origin",
                        svg("<rect style=\"fill:url(https://evil.example/p.svg#g)\"/>"), "url("),
                arguments("presentation attribute url() to another origin",
                        svg("<rect fill=\"url('https://evil.example/x#g')\"/>"), "url("),
                arguments("style attribute data: url",
                        svg("<rect style=\"background:url(data:image/svg+xml;base64,PHN2Zz4=)\"/>"), "data:"),
                arguments("style element @import", svg("<style>@import url(https://evil.example/x.css);</style>"),
                        "@import"),
                arguments("style element @import hidden by a comment", svg("<style>@im/**/port 'x.css';</style>"),
                        "@import"),
                arguments("style element url() to another origin",
                        svg("<style>rect{fill:url(\"https://evil.example/a\")}</style>"), "url("),
                arguments("style element @font-face from another origin",
                        svg("<style><![CDATA[@font-face{font-family:x;src:url(//evil.example/f.woff2)}]]></style>"), "url("),
                arguments("style element CSS escape", svg("<style>rect{fill:u\\72l(https://evil.example/a)}</style>"),
                        "escape"),
                arguments("style element image-set()",
                        svg("<style>rect{fill:image-set(\"https://evil.example/a.png\" 1x)}</style>"), "image-set("),
                arguments("animate targeting href",
                        svg("<a href=\"#x\"><animate attributeName=\"href\" to=\"javascript:alert(1)\"/><rect/></a>"),
                        "href"),
                arguments("set targeting xlink:href",
                        svg("<a xlink:href=\"#x\"><set attributeName=\"xlink:href\" to=\"#y\"/><rect/></a>"), "href"),
                arguments("animate values with javascript:",
                        svg("<a href=\"#x\"><animate attributeName=\"fill\" values=\"red;javascript:alert(1)\"/></a>"),
                        "javascript:"),
                arguments("XXE through a DOCTYPE",
                        "<?xml version=\"1.0\"?><!DOCTYPE svg [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>"
                                + "<svg " + NS + "><text>&x;</text></svg>", "DOCTYPE"),
                arguments("billion laughs",
                        "<!DOCTYPE svg [<!ENTITY a \"aaaa\"><!ENTITY b \"&a;&a;&a;&a;\">]><svg " + NS + "><text>&b;</text></svg>",
                        "DOCTYPE"),
                arguments("external DTD",
                        "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">"
                                + "<svg " + NS + "/>", "DOCTYPE"),
                arguments("xml-stylesheet processing instruction",
                        "<?xml version=\"1.0\"?><?xml-stylesheet href=\"https://evil.example/x.css\"?><svg " + NS + "/>",
                        "processing instruction"),
                arguments("processing instruction inside the document", svg("<?php echo 1; ?>"), "processing instruction"),
                arguments("XInclude",
                        svg("<xi:include xmlns:xi=\"http://www.w3.org/2001/XInclude\" href=\"file:///etc/passwd\"/>"),
                        "include"),
                arguments("xml:base redirecting fragment references",
                        svg("<g xml:base=\"https://evil.example/doc.svg\"><use href=\"#icon\"/></g>"), "xml:base"),
                arguments("iframe", svg("<iframe src=\"https://evil.example\"/>"), "iframe"),
                arguments("SVG Tiny handler", svg("<handler type=\"application/ecmascript\">alert(1)</handler>"),
                        "handler"),
                arguments("non-SVG root", "<html xmlns=\"http://www.w3.org/1999/xhtml\"><body/></html>", "svg"),
                arguments("root without the SVG namespace", "<svg><rect/></svg>", "svg"),
                arguments("not well-formed", "<svg " + NS + "><rect></svg>", "well-formed"),
                arguments("declared UTF-7", "<?xml version=\"1.0\" encoding=\"UTF-7\"?><svg " + NS + "/>", "UTF-8"),
                arguments("inkscape editor elements outside metadata",
                        svg("<sodipodi:namedview xmlns:sodipodi=\"http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd\"/>"),
                        "namedview"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("malicious")
    void maliciousSvgsAreRejected_namingTheProblem(final String name, final String svg, final String mentions) {
        assertThat(check(svg)).as(name).hasValueSatisfying(p -> assertThat(p).containsIgnoringCase(mentions));
    }

    @Test
    void theCorpusCoversAtLeastFifteenAttacks() {
        assertThat(malicious().count()).isGreaterThanOrEqualTo(15);
    }

    @Test
    void utf16AndInvalidUtf8AreRejected() {
        final byte[] utf16 = ("<svg " + NS + "/>").getBytes(StandardCharsets.UTF_16);
        assertThat(SvgValidator.problem(utf16)).hasValueSatisfying(p -> assertThat(p).contains("UTF-8"));
        final byte[] bad = {'<', 's', 'v', 'g', ' ', (byte) 0xC3, (byte) 0x28, '/', '>'};
        assertThat(SvgValidator.problem(bad)).hasValueSatisfying(p -> assertThat(p).contains("UTF-8"));
        assertThat(SvgValidator.problem(new byte[0])).isPresent();
    }

    static Stream<Arguments> benign() {
        return Stream.of(
                arguments("plain logo", "<svg " + NS + " width=\"24\" height=\"24\" viewBox=\"0 0 24 24\">"
                        + "<path d=\"M0 0h24v24H0z\" fill=\"#1f4d47\"/></svg>"),
                arguments("XML declaration, BOM and comments",
                        "﻿<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n<!-- Generator: Figma -->\n"
                                + "<svg " + NS + " viewBox=\"0 0 1 1\"><title>Monthfold</title><desc>Logo</desc>"
                                + "<rect width=\"1\" height=\"1\"/></svg>"),
                arguments("gradients and fragment references", svg(
                        "<defs><linearGradient id=\"paint0_linear_1_2\" x1=\"0\" y1=\"0\" x2=\"1\" y2=\"1\">"
                                + "<stop offset=\"0\" stop-color=\"#fff\"/><stop offset=\"1\" stop-color=\"#000\"/></linearGradient>"
                                + "<clipPath id=\"c\"><rect width=\"5\" height=\"5\"/></clipPath>"
                                + "<path id=\"p\" d=\"M0 0L1 1\"/></defs>"
                                + "<g clip-path=\"url(#c)\"><rect fill=\"url(#paint0_linear_1_2)\" style=\"fill: url( '#paint0_linear_1_2' )\"/>"
                                + "<use href=\"#p\"/><use xlink:href=\"#p\" x=\"2\"/></g>")),
                arguments("style element with fragment urls and CDATA", svg(
                        "<style><![CDATA[ .a { fill: url(#g); stroke: #1f4d47 } /* brand */ @media (prefers-color-scheme: dark)"
                                + " { .a { fill: #7fb8ac } } ]]></style><rect class=\"a\"/>")),
                arguments("filters and text", svg(
                        "<filter id=\"s\"><feGaussianBlur stdDeviation=\"1\"/><feOffset dx=\"1\"/><feMerge><feMergeNode/>"
                                + "</feMerge></filter><text x=\"1\" y=\"5\" font-family=\"Public Sans\" filter=\"url(#s)\">"
                                + "Mon<tspan font-weight=\"700\">thfold</tspan></text>")),
                arguments("benign animation and an in-document link", svg(
                        "<a href=\"#top\"><g id=\"top\"><animateTransform attributeName=\"transform\" type=\"rotate\" "
                                + "from=\"0 5 5\" to=\"360 5 5\" dur=\"2s\" repeatCount=\"indefinite\"/><circle r=\"2\"/></g></a>"
                                + "<set attributeName=\"fill\" to=\"red\" begin=\"1s\"/>")),
                arguments("Inkscape-style metadata", svg(
                        "<metadata><rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\" "
                                + "xmlns:cc=\"http://creativecommons.org/ns#\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\">"
                                + "<cc:Work rdf:about=\"\"><dc:format>image/svg+xml</dc:format></cc:Work></rdf:RDF></metadata>"
                                + "<rect width=\"1\" height=\"1\"/>")));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("benign")
    void benignSvgsPass(final String name, final String svg) {
        assertThat(check(svg)).as(name).isEmpty();
    }
}
