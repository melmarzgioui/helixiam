/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * The parts of an ETSI TS 119 612 (v2.x) trusted list HelixIAM reads, taken from a root whose signature
 * {@link XmlListSignature} already verified: scheme information (type, territory, sequence, issue time, NextUpdate),
 * the pointers to other lists (for a list of trusted lists) and every service's current information. Service history
 * ({@code ServiceHistory}) is not read: only the current status decides.
 */
record Etsi119612List(String type, String territory, long sequence, Instant issued, Instant nextUpdate,
                      List<Pointer> pointers, List<Service> services) {

    static final String TSL_NS = "http://uri.etsi.org/02231/v2#";
    /** The TSLType of a list of trusted lists ends with this (EU: {@code .../TSLType/EUlistofthelists}). */
    static final String LIST_OF_LISTS_SUFFIX = "listofthelists";
    /** Most certificates read per service or pointer. */
    private static final int MAX_CERTS = 16;

    /** A pointer to another list ({@code OtherTSLPointer}). */
    record Pointer(String location, String type, String territory, String mimeType, List<X509Certificate> signers) {
    }

    /** One service's current information; {@code country} is null when the list's territory applies. */
    record Service(String provider, String name, String type, String status, Instant statusStart, String country,
                   List<X509Certificate> certificates) {
    }

    boolean isListOfLists() {
        return type != null && type.toLowerCase(Locale.ROOT).endsWith(LIST_OF_LISTS_SUFFIX);
    }

    static Etsi119612List read(final Element root) throws TrustedListException {
        if (!TSL_NS.equals(root.getNamespaceURI()) || !"TrustServiceStatusList".equals(root.getLocalName())) {
            throw malformed("the document is not an ETSI TS 119 612 trusted list");
        }
        final Element scheme = child(root, "SchemeInformation");
        if (scheme == null) {
            throw malformed("the list has no SchemeInformation");
        }
        final String type = text(child(scheme, "TSLType"));
        final String territory = text(child(scheme, "SchemeTerritory"));
        final long sequence;
        try {
            sequence = Long.parseLong(text(child(scheme, "TSLSequenceNumber")));
        } catch (final NumberFormatException | NullPointerException e) {
            throw malformed("the list has no valid TSLSequenceNumber");
        }
        final Instant issued = time(text(child(scheme, "ListIssueDateTime")));
        if (issued == null) {
            throw malformed("the list has no valid ListIssueDateTime");
        }
        final Element next = child(scheme, "NextUpdate");
        final Instant nextUpdate = next == null ? null : time(text(child(next, "dateTime")));
        final List<Pointer> pointers = new ArrayList<>();
        final Element pointerList = child(scheme, "PointersToOtherTSL");
        if (pointerList != null) {
            for (final Element p : children(pointerList, "OtherTSLPointer")) {
                pointers.add(pointer(p));
            }
        }
        final List<Service> services = new ArrayList<>();
        final Element providers = child(root, "TrustServiceProviderList");
        if (providers != null) {
            for (final Element tsp : children(providers, "TrustServiceProvider")) {
                final Element info = child(tsp, "TSPInformation");
                final String provider = info == null ? null : name(child(info, "TSPName"));
                final Element tspServices = child(tsp, "TSPServices");
                if (tspServices == null) {
                    continue;
                }
                for (final Element svc : children(tspServices, "TSPService")) {
                    final Element si = child(svc, "ServiceInformation");
                    if (si == null) {
                        continue;
                    }
                    final Element identity = child(si, "ServiceDigitalIdentity");
                    services.add(new Service(provider, name(child(si, "ServiceName")),
                            text(child(si, "ServiceTypeIdentifier")), text(child(si, "ServiceStatus")),
                            time(text(child(si, "StatusStartingTime"))), null,
                            identity == null ? List.of() : certificates(List.of(identity))));
                }
            }
        }
        return new Etsi119612List(type, territory, sequence, issued, nextUpdate, pointers, services);
    }

    private static Pointer pointer(final Element p) throws TrustedListException {
        final String location = text(child(p, "TSLLocation"));
        String type = null;
        String territory = null;
        String mime = null;
        final Element additional = child(p, "AdditionalInformation");
        if (additional != null) {
            for (final Element other : children(additional, "OtherInformation")) {
                for (Node n = other.getFirstChild(); n != null; n = n.getNextSibling()) {
                    if (n.getNodeType() != Node.ELEMENT_NODE) {
                        continue;
                    }
                    switch (n.getLocalName()) {
                        case "TSLType" -> type = text((Element) n);
                        case "SchemeTerritory" -> territory = text((Element) n);
                        case "MimeType" -> mime = text((Element) n);
                        default -> {
                            // SchemeOperatorName, SchemeTypeCommunityRules, ...: not needed
                        }
                    }
                }
            }
        }
        final Element identities = child(p, "ServiceDigitalIdentities");
        final List<X509Certificate> signers = identities == null ? List.of()
                : certificates(children(identities, "ServiceDigitalIdentity"));
        return new Pointer(location, type, territory, mime, signers);
    }

    /** The {@code DigitalId/X509Certificate} values of the given {@code ServiceDigitalIdentity} elements. */
    private static List<X509Certificate> certificates(final List<Element> identities) throws TrustedListException {
        final List<X509Certificate> out = new ArrayList<>();
        for (final Element identity : identities) {
            for (final Element digitalId : children(identity, "DigitalId")) {
                final Element cert = child(digitalId, "X509Certificate");
                if (cert == null) {
                    continue; // a key value, SKI or subject name: not a certificate
                }
                if (out.size() >= MAX_CERTS) {
                    throw malformed("too many certificates in one service");
                }
                out.add(certificate(text(cert)));
            }
        }
        return out;
    }

    static X509Certificate certificate(final String base64) throws TrustedListException {
        try {
            final byte[] der = Base64.getMimeDecoder().decode(base64 == null ? "" : base64);
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (final CertificateException | IllegalArgumentException | ClassCastException e) {
            throw malformed("a listed certificate could not be parsed");
        }
    }

    /** The English {@code Name} child, else the first one. */
    private static String name(final Element names) {
        if (names == null) {
            return null;
        }
        String first = null;
        for (final Element n : children(names, "Name")) {
            final String lang = n.getAttributeNS("http://www.w3.org/XML/1998/namespace", "lang");
            if ("en".equalsIgnoreCase(lang)) {
                return text(n);
            }
            if (first == null) {
                first = text(n);
            }
        }
        return first;
    }

    static Instant time(final String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(value.trim()).toInstant();
        } catch (final DateTimeParseException e) {
            try {
                return Instant.parse(value.trim() + "Z"); // a dateTime without zone (seen in test lists): UTC
            } catch (final DateTimeParseException e2) {
                return null;
            }
        }
    }

    private static Element child(final Element parent, final String local) {
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() == Node.ELEMENT_NODE && TSL_NS.equals(n.getNamespaceURI())
                    && local.equals(n.getLocalName())) {
                return (Element) n;
            }
        }
        return null;
    }

    private static List<Element> children(final Element parent, final String local) {
        final List<Element> out = new ArrayList<>();
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() == Node.ELEMENT_NODE && TSL_NS.equals(n.getNamespaceURI())
                    && local.equals(n.getLocalName())) {
                out.add((Element) n);
            }
        }
        return out;
    }

    private static String text(final Element e) {
        if (e == null) {
            return null;
        }
        final String t = e.getTextContent();
        return t == null ? null : t.trim();
    }

    private static TrustedListException malformed(final String message) {
        return new TrustedListException(TrustedListException.Kind.MALFORMED, message);
    }
}
