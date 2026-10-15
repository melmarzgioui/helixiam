/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * A strict DOM parser for published trusted lists, which come from the network: the JDK's built-in parser with no
 * DOCTYPE at all (so no internal or external entities, no entity expansion), no external DTD or schema access, no
 * XInclude, secure processing on, at most {@link #MAX_DEPTH} element levels and a byte cap checked before parsing. A
 * refusal is {@link TrustedListException.Kind#MALFORMED} (or {@code TOO_LARGE}) with a fixed message: the parser's own
 * text, which can quote the input, is never surfaced.
 */
public final class SecureXml {

    /** Most element levels (a trusted list nests about 12 deep; its signature about 8). */
    public static final int MAX_DEPTH = 64;
    /** Largest list read by default (the EU LOTL is about 0.5 MB; national lists a few MB). */
    public static final long DEFAULT_MAX_BYTES = 16L * 1024 * 1024;

    private SecureXml() {
    }

    /**
     * Parses {@code bytes} namespace-aware.
     *
     * @throws TrustedListException {@code TOO_LARGE} over {@code maxBytes}; {@code MALFORMED} for anything else refused
     */
    public static Document parse(final byte[] bytes, final long maxBytes) throws TrustedListException {
        if (bytes == null || bytes.length == 0) {
            throw new TrustedListException(TrustedListException.Kind.MALFORMED, "the list is empty");
        }
        if (bytes.length > maxBytes) {
            throw new TrustedListException(TrustedListException.Kind.TOO_LARGE, "the list is larger than the size cap");
        }
        final Document doc;
        try {
            final DocumentBuilder builder = factory().newDocumentBuilder();
            builder.setEntityResolver((publicId, systemId) -> {
                throw new SAXException("external entity refused");
            });
            builder.setErrorHandler(STRICT);
            doc = builder.parse(new ByteArrayInputStream(bytes));
        } catch (final ParserConfigurationException e) {
            throw new IllegalStateException("The secure XML parser could not be configured", e);
        } catch (final SAXException | IOException | RuntimeException e) {
            throw new TrustedListException(TrustedListException.Kind.MALFORMED,
                    "the list is not a well-formed XML document without a DOCTYPE");
        }
        if (doc.getDoctype() != null) {
            throw new TrustedListException(TrustedListException.Kind.MALFORMED, "the list has a DOCTYPE");
        }
        checkDepth(doc.getDocumentElement());
        return doc;
    }

    private static DocumentBuilderFactory factory() throws ParserConfigurationException {
        // the JDK's own implementation, whatever else is on the classpath: its limits and properties are known
        final DocumentBuilderFactory f = DocumentBuilderFactory.newDefaultInstance();
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
        try {
            f.setAttribute("jdk.xml.maxElementDepth", String.valueOf(MAX_DEPTH));
        } catch (final IllegalArgumentException e) {
            // an older JDK without the property name: checkDepth still bounds the tree
        }
        return f;
    }

    /** Iterative, so a deep tree cannot overflow the stack here either. */
    private static void checkDepth(final Element root) throws TrustedListException {
        final Deque<Node> nodes = new ArrayDeque<>();
        final Deque<Integer> depths = new ArrayDeque<>();
        nodes.push(root);
        depths.push(1);
        while (!nodes.isEmpty()) {
            final Node node = nodes.pop();
            final int depth = depths.pop();
            if (depth > MAX_DEPTH) {
                throw new TrustedListException(TrustedListException.Kind.MALFORMED, "the list is nested too deeply");
            }
            for (Node child = node.getFirstChild(); child != null; child = child.getNextSibling()) {
                if (child.getNodeType() == Node.ELEMENT_NODE) {
                    nodes.push(child);
                    depths.push(depth + 1);
                }
            }
        }
    }

    private static final ErrorHandler STRICT = new ErrorHandler() {
        @Override
        public void warning(final SAXParseException e) {
            // ignored: warnings never change the tree
        }

        @Override
        public void error(final SAXParseException e) throws SAXException {
            throw e;
        }

        @Override
        public void fatalError(final SAXParseException e) throws SAXException {
            throw e;
        }
    };
}
