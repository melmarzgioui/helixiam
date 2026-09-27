/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.asset;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Checks an uploaded SVG (spec §3). The SVG is parsed with a hardened parser (no DTD, no external entities, no
 * XInclude) and is <b>rejected</b>, never rewritten, when it holds anything that could run script, load another
 * resource or change how references resolve:
 * <ul>
 *   <li>a DOCTYPE or any processing instruction (other than the XML declaration); an encoding other than UTF-8;</li>
 *   <li>a root that is not {@code <svg>} in the SVG namespace;</li>
 *   <li>an element outside the SVG allowlist: {@code <script>}, {@code <foreignObject>}, {@code <image>},
 *       {@code <feImage>}, {@code <iframe>}, SVG Tiny {@code <handler>}, XInclude, any XHTML element, editor
 *       elements (the only foreign-namespace content allowed is RDF/Dublin Core/Creative Commons/XMP inside
 *       {@code <metadata>});</li>
 *   <li>any {@code on*} attribute, in any namespace and any case; {@code xml:base}; attributes that hold a URL in
 *       other vocabularies ({@code ping}, {@code formaction}, {@code action}, {@code srcset}, {@code background},
 *       {@code lowsrc}, {@code dynsrc}, {@code poster}, {@code codebase}, {@code cite}, {@code xlink:role},
 *       {@code xlink:arcrole}, …);</li>
 *   <li>an {@code href}/{@code xlink:href}/{@code src} that is not a same-document {@code #fragment} (so
 *       {@code <use>} never references another document);</li>
 *   <li>a {@code javascript:}, {@code vbscript:} or {@code data:} URI anywhere in an attribute (after character
 *       references are decoded and whitespace is removed);</li>
 *   <li>a {@code url()} to anything but {@code #fragment}, in presentation attributes, {@code style} attributes and
 *       {@code <style>} elements, checked on the raw CSS; CSS comments, {@code @import}, CSS escapes,
 *       {@code expression(}, {@code -moz-binding},
 *       {@code behavior:} and the other URL-fetching CSS functions ({@code image-set(}, {@code image(},
 *       {@code cross-fade(}, {@code src(});</li>
 *   <li>{@code <animate>}/{@code <set>} (and the other animation elements) targeting {@code href} or an event
 *       attribute.</li>
 * </ul>
 * Pure and thread-safe; a new parser is built per call.
 */
public final class SvgValidator {

    static final String SVG_NS = "http://www.w3.org/2000/svg";
    private static final String XMLNS_NS = XMLConstants.XMLNS_ATTRIBUTE_NS_URI;
    private static final String XML_NS = XMLConstants.XML_NS_URI;

    /** SVG elements that can be drawn without script or external resources. */
    private static final Set<String> ALLOWED = Set.of(
            "svg", "g", "defs", "symbol", "use", "title", "desc", "metadata", "switch", "a", "view",
            "path", "rect", "circle", "ellipse", "line", "polyline", "polygon",
            "text", "tspan", "textPath",
            "linearGradient", "radialGradient", "stop", "pattern", "clipPath", "mask", "marker",
            "filter", "feBlend", "feColorMatrix", "feComponentTransfer", "feComposite", "feConvolveMatrix",
            "feDiffuseLighting", "feDisplacementMap", "feDistantLight", "feDropShadow", "feFlood", "feFuncA",
            "feFuncB", "feFuncG", "feFuncR", "feGaussianBlur", "feMerge", "feMergeNode", "feMorphology", "feOffset",
            "fePointLight", "feSpecularLighting", "feSpotLight", "feTile", "feTurbulence",
            "style",
            "animate", "animateTransform", "animateMotion", "set", "mpath");

    private static final Set<String> ANIMATION = Set.of("animate", "animatetransform", "animatemotion", "set",
            "animatecolor");

    /** Element names refused with a specific reason, in any namespace. */
    private static final Set<String> ALWAYS_REFUSED = Set.of("script", "foreignobject");

    /** Foreign namespaces allowed inside {@code <metadata>} only (what editors write there). */
    private static final Set<String> METADATA_NAMESPACES = Set.of(
            "http://www.w3.org/1999/02/22-rdf-syntax-ns#", "http://purl.org/dc/elements/1.1/",
            "http://purl.org/dc/terms/", "http://creativecommons.org/ns#", "http://web.resource.org/cc/",
            "adobe:ns:meta/");

    private static final Pattern FRAGMENT = Pattern.compile("#[A-Za-z0-9_][A-Za-z0-9_.:-]{0,255}");
    private static final Pattern DECLARED_ENCODING =
            Pattern.compile("^<\\?xml[^>]*?\\bencoding\\s*=\\s*[\"']([^\"']*)[\"']");
    private static final Pattern DOCTYPE = Pattern.compile("<!DOCTYPE", Pattern.CASE_INSENSITIVE);
    private static final Pattern URL_START = Pattern.compile("url\\s*\\(", Pattern.CASE_INSENSITIVE);
    private static final Pattern CSS_FORBIDDEN = Pattern.compile(
            "@import|expression\\s*\\(|-moz-binding|behavior\\s*:|(?:-webkit-)?image-set\\s*\\(|\\bimage\\s*\\("
                    + "|(?:-webkit-)?cross-fade\\s*\\(|\\bsrc\\s*\\(",
            Pattern.CASE_INSENSITIVE);
    /**
     * Review M2: attributes that hold a URL in some vocabulary (HTML, XLink) and have no legitimate use in an image;
     * refused wherever they appear, whatever their value.
     */
    private static final Set<String> URL_ATTRIBUTES = Set.of("ping", "formaction", "action", "srcset", "background",
            "lowsrc", "dynsrc", "poster", "codebase", "cite", "arcrole", "role", "data", "archive", "longdesc",
            "usemap", "manifest", "icon", "profile", "classid");
    private static final String XLINK_NS = "http://www.w3.org/1999/xlink";

    private static final String[] DANGEROUS_SCHEMES = {"javascript:", "vbscript:", "data:"};

    private SvgValidator() {
    }

    /** The first problem found, or empty when the SVG is acceptable. */
    public static Optional<String> problem(final byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return Optional.of("The SVG is empty.");
        }
        final String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (final CharacterCodingException e) {
            return Optional.of("The SVG must be encoded as UTF-8.");
        }
        final String body = text.startsWith("\uFEFF") ? text.substring(1) : text;
        if (body.indexOf('\0') >= 0) {
            return Optional.of("The SVG must be encoded as UTF-8.");
        }
        final Matcher enc = DECLARED_ENCODING.matcher(body);
        if (enc.find() && !"utf-8".equalsIgnoreCase(enc.group(1).trim())) {
            return Optional.of("The SVG must be encoded as UTF-8 (it declares " + safe(enc.group(1)) + ").");
        }
        if (DOCTYPE.matcher(body).find()) {
            return Optional.of("DOCTYPE declarations are not allowed in an SVG.");
        }
        final Document doc;
        try {
            doc = parser().parse(new InputSource(new StringReader(body)));
        } catch (final SAXException | IOException e) {
            final String msg = e.getMessage() == null ? "" : e.getMessage();
            if (msg.contains("DOCTYPE")) {
                return Optional.of("DOCTYPE declarations are not allowed in an SVG.");
            }
            return Optional.of("The SVG is not well-formed XML.");
        } catch (final ParserConfigurationException e) {
            throw new IllegalStateException("No hardened XML parser available", e);
        }
        return walk(doc);
    }

    private static Optional<String> walk(final Document doc) {
        final Element root = doc.getDocumentElement();
        if (root == null || !SVG_NS.equals(root.getNamespaceURI()) || !"svg".equals(root.getLocalName())) {
            return Optional.of("The root element must be <svg> in the SVG namespace (" + SVG_NS + ").");
        }
        final Deque<Frame> stack = new ArrayDeque<>();
        for (Node n = doc.getFirstChild(); n != null; n = n.getNextSibling()) {
            stack.push(new Frame(n, false));
        }
        while (!stack.isEmpty()) {
            final Frame f = stack.pop();
            final Node node = f.node();
            switch (node.getNodeType()) {
                case Node.PROCESSING_INSTRUCTION_NODE:
                    return Optional.of("Processing instructions are not allowed in an SVG (found <?"
                            + safe(node.getNodeName()) + "?>).");
                case Node.DOCUMENT_TYPE_NODE:
                    return Optional.of("DOCTYPE declarations are not allowed in an SVG.");
                case Node.ENTITY_REFERENCE_NODE:
                case Node.ENTITY_NODE:
                    return Optional.of("Entity references are not allowed in an SVG.");
                case Node.ELEMENT_NODE:
                    final Element el = (Element) node;
                    final Optional<String> problem = element(el, f.inMetadata());
                    if (problem.isPresent()) {
                        return problem;
                    }
                    final boolean childInMetadata = f.inMetadata()
                            || (SVG_NS.equals(el.getNamespaceURI()) && "metadata".equals(el.getLocalName()));
                    for (Node c = el.getFirstChild(); c != null; c = c.getNextSibling()) {
                        stack.push(new Frame(c, childInMetadata));
                    }
                    break;
                default:
                    break; // text, CDATA and comments are inert (a <style> element's text is checked with it)
            }
        }
        return Optional.empty();
    }

    private static Optional<String> element(final Element el, final boolean inMetadata) {
        final String ns = el.getNamespaceURI();
        final String local = el.getLocalName() == null ? el.getNodeName() : el.getLocalName();
        final String lower = local.toLowerCase(Locale.ROOT);
        final String qname = safe(el.getNodeName());
        if (ALWAYS_REFUSED.contains(lower)) {
            return Optional.of("Element <" + qname + "> is not allowed in an SVG (" + (lower.equals("script")
                    ? "script" : "foreignObject embeds HTML") + ").");
        }
        if (SVG_NS.equals(ns)) {
            if (!ALLOWED.contains(local)) {
                return Optional.of("Element <" + qname + "> is not allowed in an SVG"
                        + (lower.equals("image") || lower.equals("feimage") ? " (it loads another resource)." : "."));
            }
        } else if (!inMetadata || ns == null || !(METADATA_NAMESPACES.contains(ns) || ns.startsWith("http://ns.adobe.com/"))) {
            return Optional.of("Element <" + qname + "> is not allowed in an SVG (only SVG elements are allowed; "
                    + "editor metadata may only appear inside <metadata>).");
        }

        final NamedNodeMap attrs = el.getAttributes();
        // Animation targets first, so the message names the rule rather than a value it would set.
        if (ANIMATION.contains(lower) && SVG_NS.equals(ns)) {
            final String target = el.getAttribute("attributeName").trim().toLowerCase(Locale.ROOT);
            if (target.equals("href") || target.endsWith(":href") || target.startsWith("on")
                    || target.equals("style") || target.endsWith(":base")) {
                return Optional.of("<" + qname + "> may not target href, style or an event attribute (it targets "
                        + safe(target) + ").");
            }
        }
        for (int i = 0; i < attrs.getLength(); i++) {
            final Optional<String> problem = attribute(el, (Attr) attrs.item(i), lower);
            if (problem.isPresent()) {
                return problem;
            }
        }
        if (SVG_NS.equals(ns) && "style".equals(local)) {
            return css(el.getTextContent(), "<style>");
        }
        return Optional.empty();
    }

    private static Optional<String> attribute(final Element el, final Attr attr, final String elementLower) {
        final String ans = attr.getNamespaceURI();
        if (XMLNS_NS.equals(ans)) {
            return Optional.empty(); // a namespace declaration
        }
        final String local = (attr.getLocalName() == null ? attr.getName() : attr.getLocalName());
        final String lower = local.toLowerCase(Locale.ROOT);
        final String qname = safe(attr.getName());
        final String value = attr.getValue() == null ? "" : attr.getValue();
        if (lower.startsWith("on")) {
            return Optional.of("Event handler attribute " + qname + " is not allowed in an SVG.");
        }
        if (XML_NS.equals(ans) && "base".equals(lower) || "xml:base".equalsIgnoreCase(attr.getName())) {
            return Optional.of("Attribute xml:base is not allowed in an SVG (it redirects references).");
        }
        if (URL_ATTRIBUTES.contains(lower) && (!lower.equals("role") || XLINK_NS.equals(ans))) {
            // ARIA's plain role="img" stays allowed; xlink:role / xlink:arcrole hold URIs.
            return Optional.of("Attribute " + qname + " holds a URL and is not allowed in an SVG.");
        }
        if (lower.equals("href") || lower.equals("src")) {
            if (!FRAGMENT.matcher(value.trim()).matches()) {
                if ("use".equals(elementLower)) {
                    return Optional.of("<use> may only reference an element in this document (" + qname
                            + " must be #id).");
                }
                return Optional.of("Attribute " + qname + " must reference an element in this document (#id); "
                        + "external, javascript: and data: references are not allowed.");
            }
            return Optional.empty();
        }
        final String compact = compact(value);
        for (final String scheme : DANGEROUS_SCHEMES) {
            if (compact.contains(scheme)) {
                return Optional.of("Attribute " + qname + " contains a javascript:, vbscript: or data: URI.");
            }
        }
        if (lower.equals("style")) {
            return css(value, "the style attribute");
        }
        if (ans == null && value.indexOf('\\') >= 0) {
            // Presentation attributes are CSS values: an escape could spell url( or a scheme.
            return Optional.of("Backslashes are not allowed in attribute " + qname + " of an SVG.");
        }
        if (URL_START.matcher(value).find()) {
            return urls(value, "attribute " + qname);
        }
        return Optional.empty();
    }

    /** Checks CSS from a {@code <style>} element or a {@code style} attribute. */
    static Optional<String> css(final String css, final String where) {
        if (css == null || css.isEmpty()) {
            return Optional.empty();
        }
        if (css.indexOf('\\') >= 0) {
            return Optional.of("CSS escapes (\\) are not allowed in " + where + " of an SVG.");
        }
        // Review I1: no comments at all. Stripping them is not string-aware ("/*" inside a CSS string would hide a
        // url()), so every check below runs on the raw CSS, and comments are refused like in custom CSS.
        if (css.contains("/*")) {
            return Optional.of("CSS comments (/*) are not allowed in " + where + " of an SVG.");
        }
        final Matcher forbidden = CSS_FORBIDDEN.matcher(css);
        if (forbidden.find()) {
            return Optional.of("CSS " + safe(forbidden.group().replaceAll("\\s+", "")) + " is not allowed in "
                    + where + " of an SVG.");
        }
        final String compact = compact(css);
        for (final String scheme : DANGEROUS_SCHEMES) {
            if (compact.contains(scheme)) {
                return Optional.of("CSS in " + where + " contains a javascript:, vbscript: or data: URI.");
            }
        }
        return urls(css, where);
    }

    /** Every {@code url(...)} must be {@code url(#fragment)}. */
    private static Optional<String> urls(final String text, final String where) {
        final Matcher m = URL_START.matcher(text);
        while (m.find()) {
            int i = m.end();
            while (i < text.length() && Character.isWhitespace(text.charAt(i))) {
                i++;
            }
            final String target;
            if (i < text.length() && (text.charAt(i) == '"' || text.charAt(i) == '\'')) {
                final char quote = text.charAt(i);
                final int end = text.indexOf(quote, i + 1);
                if (end < 0) {
                    return Optional.of("Unterminated url() in " + where + " of an SVG.");
                }
                target = text.substring(i + 1, end);
            } else {
                final int end = text.indexOf(')', i);
                if (end < 0) {
                    return Optional.of("Unterminated url() in " + where + " of an SVG.");
                }
                target = text.substring(i, end);
            }
            if (!FRAGMENT.matcher(target.trim()).matches()) {
                return Optional.of("url() in " + where + " may only reference an element in this document "
                        + "(url(#id)); external references are not allowed.");
            }
        }
        return Optional.empty();
    }

    /** Lower-cased with every whitespace and control character removed (how browsers skip them in schemes). */
    private static String compact(final String value) {
        final StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            final char c = value.charAt(i);
            if (c > 0x20 && c != 0x7f && !Character.isWhitespace(c) && !Character.isISOControl(c)) {
                sb.append(c >= 'A' && c <= 'Z' ? (char) (c + 32) : c);
            }
        }
        return sb.toString();
    }

    private static String safe(final String s) {
        if (s == null) {
            return "";
        }
        final String cleaned = s.replaceAll("[^A-Za-z0-9 _.:#()@-]", "?");
        return cleaned.length() > 40 ? cleaned.substring(0, 40) + "…" : cleaned;
    }

    private static DocumentBuilder parser() throws ParserConfigurationException {
        final DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setNamespaceAware(true);
        f.setValidating(false);
        f.setXIncludeAware(false);
        f.setExpandEntityReferences(false);
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
        f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        final DocumentBuilder b = f.newDocumentBuilder();
        b.setEntityResolver((publicId, systemId) -> {
            throw new SAXException("External entities are not allowed.");
        });
        b.setErrorHandler(new ErrorHandler() {
            @Override
            public void warning(final SAXParseException e) {
                // ignored
            }

            @Override
            public void error(final SAXParseException e) throws SAXException {
                throw e;
            }

            @Override
            public void fatalError(final SAXParseException e) throws SAXException {
                throw e;
            }
        });
        return b;
    }

    private record Frame(Node node, boolean inMetadata) {
    }
}
