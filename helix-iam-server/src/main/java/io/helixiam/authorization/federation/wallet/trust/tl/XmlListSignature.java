/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.security.cert.X509Certificate;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Verifies the enveloped XMLDSig (the core of the XAdES signature ETSI TS 119 612 §5.7 requires) of a parsed trusted
 * list against pinned signer certificates, with Apache Santuario in secure-validation mode. The rules close the usual
 * XML-signature holes:
 * <ul>
 *   <li><b>Only pinned keys.</b> The signature must verify with the public key of one of the configured signer
 *       certificates; the list's own {@code KeyInfo} is never trusted.</li>
 *   <li><b>No signature wrapping.</b> Exactly one {@code ds:Signature} in the document, a direct child of the root;
 *       one of its references must be the whole document ({@code URI=""}) or the root element by its {@code Id}, with
 *       the enveloped-signature transform. The caller then reads the list from that same root. {@code Id} attributes
 *       must be unique, so a reference cannot be pointed at a look-alike element.</li>
 *   <li><b>No reach outside the document, no subsetting.</b> Every reference is same-document ({@code ""} or
 *       {@code #id}); the only transforms allowed are enveloped-signature and canonicalization (no XPath, XSLT or
 *       Base64), so a reference cannot select less than it appears to.</li>
 *   <li><b>Algorithms.</b> Signatures: RSA PKCS#1 v1.5, RSASSA-PSS with MGF1 and a fixed hash (the {@code sha*-rsa-MGF1}
 *       identifiers; the generic, parameterised {@code rsa-pss} identifier is refused) and ECDSA, each with
 *       SHA-256/384/512. Reference digests: SHA-256/384/512 only, checked here (Santuario's secure validation refuses
 *       MD5 but still accepts SHA-1 digests). Secure validation also bounds the number of references and
 *       transforms.</li>
 * </ul>
 */
final class XmlListSignature {

    static final String DSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final Set<String> ALLOWED_TRANSFORMS = Set.of(Transforms.TRANSFORM_ENVELOPED_SIGNATURE,
            Transforms.TRANSFORM_C14N_OMIT_COMMENTS, Transforms.TRANSFORM_C14N_WITH_COMMENTS,
            Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, Transforms.TRANSFORM_C14N_EXCL_WITH_COMMENTS,
            Transforms.TRANSFORM_C14N11_OMIT_COMMENTS, Transforms.TRANSFORM_C14N11_WITH_COMMENTS);
    private static final Set<String> ALLOWED_SIGNATURE_ALGORITHMS = Set.of(
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384,
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256_MGF1,
            XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384_MGF1, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512_MGF1,
            XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA384,
            XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA512);

    /** Reference digests: SHA-256/384/512 only (Santuario's secure validation alone still accepts SHA-1). */
    private static final Set<String> ALLOWED_DIGESTS = Set.of("http://www.w3.org/2001/04/xmlenc#sha256",
            "http://www.w3.org/2001/04/xmldsig-more#sha384", "http://www.w3.org/2001/04/xmlenc#sha512");

    static {
        org.apache.xml.security.Init.init();
    }

    private XmlListSignature() {
    }

    /**
     * Verifies {@code doc}'s signature with one of {@code signers}.
     *
     * @return the pinned signer whose key verified it
     * @throws TrustedListException {@code SIGNATURE} for every refusal (the message names the rule, never content)
     */
    static X509Certificate verify(final Document doc, final List<X509Certificate> signers)
            throws TrustedListException {
        if (signers.isEmpty()) {
            throw signature("no signer certificate is configured");
        }
        final Element root = doc.getDocumentElement();
        registerIds(root);
        final NodeList signatures = doc.getElementsByTagNameNS(DSIG_NS, "Signature");
        if (signatures.getLength() == 0) {
            throw signature("the list is not signed");
        }
        if (signatures.getLength() != 1) {
            throw signature("the list carries more than one signature");
        }
        final Element sigElement = (Element) signatures.item(0);
        if (sigElement.getParentNode() != root) {
            throw signature("the signature is not enveloped in the list root");
        }
        // the algorithm is checked on the DOM first, before Santuario builds anything for it
        final NodeList methods = sigElement.getElementsByTagNameNS(DSIG_NS, "SignatureMethod");
        if (methods.getLength() != 1
                || !ALLOWED_SIGNATURE_ALGORITHMS.contains(((Element) methods.item(0)).getAttribute("Algorithm"))) {
            throw signature("the signature algorithm is not allowed");
        }
        final XMLSignature signature;
        try {
            signature = new XMLSignature(sigElement, "", true);
        } catch (final Exception e) {
            throw signature("the signature could not be read");
        }
        checkSignedInfo(signature.getSignedInfo(), root);
        for (final X509Certificate signer : signers) {
            try {
                if (signature.checkSignatureValue(signer.getPublicKey())) {
                    return signer;
                }
            } catch (final Exception e) {
                // a key of another type or a reference that fails to resolve: not this signer
            }
        }
        throw signature("the signature does not verify with a configured signer certificate");
    }

    private static void checkSignedInfo(final SignedInfo si, final Element root) throws TrustedListException {
        if (!ALLOWED_SIGNATURE_ALGORITHMS.contains(si.getSignatureMethodURI())) {
            throw signature("the signature algorithm is not allowed");
        }
        final String rootId = root.hasAttributeNS(null, "Id") ? root.getAttributeNS(null, "Id") : null;
        boolean coversRoot = false;
        try {
            for (int i = 0; i < si.getLength(); i++) {
                final Reference ref = si.item(i);
                final String uri = ref.getURI();
                if (uri == null || !(uri.isEmpty() || uri.startsWith("#"))) {
                    throw signature("a signature reference points outside the list");
                }
                if (!ALLOWED_DIGESTS.contains(ref.getMessageDigestAlgorithm().getAlgorithmURI())) {
                    throw signature("a signature reference uses a digest algorithm that is not allowed");
                }
                boolean enveloped = false;
                final Transforms transforms = ref.getTransforms();
                for (int t = 0; transforms != null && t < transforms.getLength(); t++) {
                    final String alg = transforms.item(t).getURI();
                    if (!ALLOWED_TRANSFORMS.contains(alg)) {
                        throw signature("a signature reference uses a transform that is not allowed");
                    }
                    enveloped |= Transforms.TRANSFORM_ENVELOPED_SIGNATURE.equals(alg);
                }
                final boolean wholeList = uri.isEmpty() || rootId != null && uri.equals("#" + rootId);
                coversRoot |= wholeList && enveloped;
            }
        } catch (final TrustedListException e) {
            throw e;
        } catch (final Exception e) {
            throw signature("the signature references could not be read");
        }
        if (!coversRoot) {
            throw signature("the signature does not cover the whole list");
        }
    }

    /** Marks every {@code Id} attribute as an XML ID (what Santuario resolves {@code #id} against); unique or refused. */
    private static void registerIds(final Element root) throws TrustedListException {
        final Set<String> seen = new HashSet<>();
        final Deque<Element> todo = new ArrayDeque<>();
        todo.push(root);
        while (!todo.isEmpty()) {
            final Element e = todo.pop();
            final NamedNodeMap attrs = e.getAttributes();
            for (int i = 0; i < attrs.getLength(); i++) {
                final Attr a = (Attr) attrs.item(i);
                final String local = a.getLocalName() == null ? a.getName() : a.getLocalName();
                if (a.getNamespaceURI() == null && "Id".equals(local)) {
                    if (!seen.add(a.getValue())) {
                        throw signature("the list has duplicate Id attributes");
                    }
                    e.setIdAttributeNode(a, true);
                }
            }
            for (Node child = e.getFirstChild(); child != null; child = child.getNextSibling()) {
                if (child.getNodeType() == Node.ELEMENT_NODE) {
                    todo.push((Element) child);
                }
            }
        }
    }

    private static TrustedListException signature(final String message) {
        return new TrustedListException(TrustedListException.Kind.SIGNATURE, message);
    }
}
