/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import org.apache.xml.security.signature.ObjectContainer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds ETSI TS 119 612 trusted lists (a member-state TL or a list of trusted lists) and ETSI TS 119 602 LoTE JSON
 * lists in tests, signed with a throwaway signer: XMLDSig enveloped (with a XAdES-style SignedProperties reference,
 * as the published lists carry) and JWS compact.
 */
public final class TrustedListFixtures {

    public static final String TSL_NS = "http://uri.etsi.org/02231/v2#";
    public static final String ADDITIONAL_NS = "http://uri.etsi.org/02231/v2/additionaltypes#";
    public static final String XADES_NS = "http://uri.etsi.org/01903/v1.3.2#";
    public static final String PID_TYPE = "http://uri.etsi.org/Svc/Svctype/Provider/PID";
    public static final String GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
    public static final String WITHDRAWN = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn";
    public static final String RECOGNISED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel";
    public static final String LOTL_TYPE = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists";
    public static final String GENERIC_TYPE = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric";
    public static final String LOTE_PID_TYPE = "http://uri.etsi.org/19602/SvcType/PID/Issuance";

    private TrustedListFixtures() {
    }

    /** A list signer: a self-signed EC P-256 certificate and its key. */
    public static TestPki.Leaf signer(final String name) {
        return TestPki.selfSignedLeaf("CN=" + name + ", O=Test Scheme Operator, C=EU");
    }

    /** One listed trust service. */
    public record Service(String provider, String name, String type, String status, Instant statusStart,
                          X509Certificate certificate) {

        public static Service granted(final String provider, final X509Certificate certificate) {
            return new Service(provider, provider + " PID issuance", PID_TYPE, GRANTED,
                    Instant.now().minus(30, ChronoUnit.DAYS), certificate);
        }

        public Service withStatus(final String value) {
            return new Service(provider, name, type, value, statusStart, certificate);
        }

        public Service withType(final String value) {
            return new Service(provider, name, value, status, statusStart, certificate);
        }

        public Service startingAt(final Instant value) {
            return new Service(provider, name, type, status, value, certificate);
        }
    }

    /** A pointer from a list of trusted lists to another list. */
    public record Pointer(String location, String tslType, String territory, String mimeType,
                          List<X509Certificate> signers) {

        public static Pointer memberState(final String location, final String territory,
                                          final X509Certificate signer) {
            return new Pointer(location, GENERIC_TYPE, territory, "application/vnd.etsi.tsl+xml", List.of(signer));
        }
    }

    /** What goes into a list. */
    public static final class Spec {
        String type = GENERIC_TYPE;
        String territory = "UT";
        long sequence = 7;
        Instant issued = Instant.now().minus(1, ChronoUnit.HOURS).truncatedTo(ChronoUnit.SECONDS);
        Instant nextUpdate = Instant.now().plus(30, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);
        boolean withNextUpdate = true;
        final List<Service> services = new ArrayList<>();
        final List<Pointer> pointers = new ArrayList<>();

        public static Spec memberState(final String territory) {
            final Spec s = new Spec();
            s.territory = territory;
            return s;
        }

        public static Spec lotl() {
            final Spec s = new Spec();
            s.type = LOTL_TYPE;
            s.territory = "EU";
            return s;
        }

        public Spec service(final Service service) {
            services.add(service);
            return this;
        }

        public Spec pointer(final Pointer pointer) {
            pointers.add(pointer);
            return this;
        }

        public Spec sequence(final long value) {
            sequence = value;
            return this;
        }

        public Spec issued(final Instant value) {
            issued = value.truncatedTo(ChronoUnit.SECONDS);
            return this;
        }

        public Spec nextUpdate(final Instant value) {
            nextUpdate = value == null ? null : value.truncatedTo(ChronoUnit.SECONDS);
            withNextUpdate = value != null;
            return this;
        }
    }

    /** The unsigned XML of {@code spec}. */
    public static String xml(final Spec spec) {
        final StringBuilder sb = new StringBuilder(4096);
        sb.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
                .append("<TrustServiceStatusList xmlns=\"").append(TSL_NS).append("\" xmlns:ns3=\"").append(ADDITIONAL_NS)
                .append("\" Id=\"TrustServiceStatusList\" TSLTag=\"http://uri.etsi.org/19612/TSLTag\">")
                .append("<SchemeInformation><TSLVersionIdentifier>6</TSLVersionIdentifier>")
                .append("<TSLSequenceNumber>").append(spec.sequence).append("</TSLSequenceNumber>")
                .append("<TSLType>").append(spec.type).append("</TSLType>")
                .append("<SchemeOperatorName><Name xml:lang=\"en\">Test Scheme Operator</Name></SchemeOperatorName>")
                .append("<SchemeTerritory>").append(spec.territory).append("</SchemeTerritory>");
        if (!spec.pointers.isEmpty()) {
            sb.append("<PointersToOtherTSL>");
            for (final Pointer p : spec.pointers) {
                sb.append("<OtherTSLPointer><ServiceDigitalIdentities>");
                for (final X509Certificate c : p.signers()) {
                    sb.append("<ServiceDigitalIdentity><DigitalId><X509Certificate>").append(b64(c))
                            .append("</X509Certificate></DigitalId></ServiceDigitalIdentity>");
                }
                sb.append("</ServiceDigitalIdentities><TSLLocation>").append(escape(p.location()))
                        .append("</TSLLocation><AdditionalInformation>")
                        .append("<OtherInformation><TSLType>").append(p.tslType()).append("</TSLType></OtherInformation>")
                        .append("<OtherInformation><SchemeTerritory>").append(p.territory())
                        .append("</SchemeTerritory></OtherInformation>")
                        .append("<OtherInformation><ns3:MimeType>").append(p.mimeType())
                        .append("</ns3:MimeType></OtherInformation>")
                        .append("</AdditionalInformation></OtherTSLPointer>");
            }
            sb.append("</PointersToOtherTSL>");
        }
        sb.append("<ListIssueDateTime>").append(spec.issued).append("</ListIssueDateTime>");
        if (spec.withNextUpdate) {
            sb.append("<NextUpdate><dateTime>").append(spec.nextUpdate).append("</dateTime></NextUpdate>");
        } else {
            sb.append("<NextUpdate/>");
        }
        sb.append("</SchemeInformation>");
        if (!spec.services.isEmpty()) {
            final Map<String, List<Service>> byProvider = new LinkedHashMap<>();
            spec.services.forEach(s -> byProvider.computeIfAbsent(s.provider(), k -> new ArrayList<>()).add(s));
            sb.append("<TrustServiceProviderList>");
            byProvider.forEach((provider, services) -> {
                sb.append("<TrustServiceProvider><TSPInformation><TSPName><Name xml:lang=\"en\">").append(escape(provider))
                        .append("</Name></TSPName></TSPInformation><TSPServices>");
                for (final Service s : services) {
                    sb.append("<TSPService><ServiceInformation><ServiceTypeIdentifier>").append(s.type())
                            .append("</ServiceTypeIdentifier><ServiceName><Name xml:lang=\"en\">").append(escape(s.name()))
                            .append("</Name></ServiceName><ServiceDigitalIdentity><DigitalId><X509Certificate>")
                            .append(b64(s.certificate()))
                            .append("</X509Certificate></DigitalId></ServiceDigitalIdentity><ServiceStatus>")
                            .append(s.status()).append("</ServiceStatus><StatusStartingTime>")
                            .append(s.statusStart().truncatedTo(ChronoUnit.SECONDS))
                            .append("</StatusStartingTime></ServiceInformation>");
                    if (!GRANTED.equals(s.status())) {
                        // the service was granted before: history the parser must not count
                        sb.append("<ServiceHistory><ServiceHistoryInstance><ServiceTypeIdentifier>").append(s.type())
                                .append("</ServiceTypeIdentifier><ServiceName><Name xml:lang=\"en\">")
                                .append(escape(s.name())).append("</Name></ServiceName>")
                                .append("<ServiceDigitalIdentity><DigitalId><X509Certificate>")
                                .append(b64(s.certificate())).append("</X509Certificate></DigitalId>")
                                .append("</ServiceDigitalIdentity><ServiceStatus>").append(GRANTED)
                                .append("</ServiceStatus><StatusStartingTime>2020-01-01T00:00:00Z</StatusStartingTime>")
                                .append("</ServiceHistoryInstance></ServiceHistory>");
                    }
                    sb.append("</TSPService>");
                }
                sb.append("</TSPServices></TrustServiceProvider>");
            });
            sb.append("</TrustServiceProviderList>");
        }
        sb.append("</TrustServiceStatusList>");
        return sb.toString();
    }

    /** {@code spec} signed by {@code signer}: an enveloped XMLDSig over the whole list plus a SignedProperties object. */
    public static byte[] signedXml(final Spec spec, final TestPki.Leaf signer) {
        return sign(xml(spec), signer);
    }

    /** Signs an XML document (its root must carry {@code Id="TrustServiceStatusList"}). */
    public static byte[] sign(final String xml, final TestPki.Leaf signer) {
        try {
            org.apache.xml.security.Init.init();
            final DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setNamespaceAware(true);
            final Document doc = f.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            final Element root = doc.getDocumentElement();
            root.setIdAttributeNS(null, "Id", true);
            final XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256,
                    Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
            root.appendChild(sig.getElement());
            final Transforms whole = new Transforms(doc);
            whole.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
            whole.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
            sig.addDocument("#TrustServiceStatusList", whole, "http://www.w3.org/2001/04/xmlenc#sha256");
            // XAdES-style signed properties, referenced by Id like the published lists do
            final ObjectContainer object = new ObjectContainer(doc);
            final Element qualifying = doc.createElementNS(XADES_NS, "xades:QualifyingProperties");
            final Element signedProps = doc.createElementNS(XADES_NS, "xades:SignedProperties");
            signedProps.setAttributeNS(null, "Id", "xades-signed-properties");
            signedProps.setIdAttributeNS(null, "Id", true);
            final Element signingTime = doc.createElementNS(XADES_NS, "xades:SigningTime");
            signingTime.setTextContent(Instant.now().truncatedTo(ChronoUnit.SECONDS).toString());
            signedProps.appendChild(signingTime);
            qualifying.appendChild(signedProps);
            object.appendChild(qualifying);
            sig.appendObject(object);
            final Transforms props = new Transforms(doc);
            props.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
            sig.addDocument("#xades-signed-properties", props, "http://www.w3.org/2001/04/xmlenc#sha256", null,
                    "http://uri.etsi.org/01903#SignedProperties");
            sig.addKeyInfo(signer.certificate());
            sig.sign(signer.privateKey());
            return serialize(doc);
        } catch (final Exception e) {
            throw new IllegalStateException("could not sign the test list", e);
        }
    }

    static byte[] serialize(final Document doc) {
        try {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            TransformerFactory.newInstance().newTransformer().transform(new DOMSource(doc), new StreamResult(out));
            return out.toByteArray();
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ------------------------------------------------------------------------------------------------ LoTE (119 602)

    /** One LoTE trusted entity with one service. */
    public record LoteEntity(String name, String country, String serviceName, String serviceType,
                             X509Certificate certificate) {

        public static LoteEntity pid(final String name, final String country, final X509Certificate cert) {
            return new LoteEntity(name, country, name + " PID", LOTE_PID_TYPE, cert);
        }
    }

    /** A LoTE JSON payload ({@code {"LoTE": ...}}). */
    public static String loteJson(final long sequence, final Instant nextUpdate, final List<LoteEntity> entities) {
        final StringBuilder sb = new StringBuilder();
        sb.append("{\"LoTE\":{\"ListAndSchemeInformation\":{\"LoTEVersionIdentifier\":1,\"LoTESequenceNumber\":")
                .append(sequence)
                .append(",\"LoTEType\":\"http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList\"")
                .append(",\"SchemeOperatorName\":[{\"lang\":\"en\",\"value\":\"Test Commission\"}]")
                .append(",\"SchemeTerritory\":\"EU\",\"ListIssueDateTime\":\"")
                .append(Instant.now().minus(1, ChronoUnit.HOURS).truncatedTo(ChronoUnit.SECONDS)).append('"');
        if (nextUpdate != null) {
            sb.append(",\"NextUpdate\":\"").append(nextUpdate.truncatedTo(ChronoUnit.SECONDS)).append('"');
        }
        sb.append("},\"TrustedEntitiesList\":[");
        for (int i = 0; i < entities.size(); i++) {
            final LoteEntity e = entities.get(i);
            if (i > 0) {
                sb.append(',');
            }
            sb.append("{\"TrustedEntityInformation\":{\"TEName\":[{\"lang\":\"en\",\"value\":\"").append(e.name())
                    .append("\"}],\"TEAddress\":{\"TEPostalAddress\":[{\"lang\":\"en\",\"Country\":\"")
                    .append(e.country()).append("\"}]}},\"TrustedEntityServices\":[{\"ServiceInformation\":{")
                    .append("\"ServiceName\":[{\"lang\":\"en\",\"value\":\"").append(e.serviceName()).append("\"}],")
                    .append("\"ServiceDigitalIdentity\":{\"X509Certificates\":[{\"val\":\"").append(b64(e.certificate()))
                    .append("\"}]},\"ServiceTypeIdentifier\":\"").append(e.serviceType()).append("\"}}]}");
        }
        sb.append("]}}");
        return sb.toString();
    }

    /** {@code json} as a JWS compact serialization (ES256, x5c), like the published LoTE JSON lists (JAdES). */
    public static byte[] signedLote(final String json, final TestPki.Leaf signer) {
        try {
            final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("jose"))
                    .contentType("json").x509CertChain(List.of(Base64.encode(signer.certificate().getEncoded())))
                    .build();
            final JWSObject jws = new JWSObject(header, new Payload(json));
            jws.sign(new ECDSASigner((ECPrivateKey) signer.privateKey()));
            return jws.serialize().getBytes(StandardCharsets.US_ASCII);
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String b64(final X509Certificate c) {
        try {
            return java.util.Base64.getEncoder().encodeToString(c.getEncoded());
        } catch (final CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String escape(final String v) {
        return v.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
