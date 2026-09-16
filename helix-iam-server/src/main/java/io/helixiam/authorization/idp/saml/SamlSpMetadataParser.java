/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.saml;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.security.credential.UsageType;
import org.springframework.stereotype.Component;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Helix IAM (WSO2-class onboarding): parses an uploaded SP {@code <EntityDescriptor>} (SAML metadata XML)
 * into the fields Helix needs to register the relying party — so an admin pastes/drops the SP's metadata and
 * the RP form auto-fills instead of typing entityId/ACS/cert/NameID by hand.
 */
@Component
public class SamlSpMetadataParser {

    static {
        try {
            InitializationService.initialize();
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to initialize OpenSAML", e);
        }
    }

    /** The RP fields extracted from an SP's metadata. */
    public record ParsedSp(String entityId, String assertionConsumerServiceUrl, List<String> additionalAcsUrls,
                           String singleLogoutServiceUrl, String signingCertificate, String nameIdFormat,
                           boolean wantAssertionsSigned) {
    }

    public ParsedSp parse(final String metadataXml) {
        try {
            final ParserPool pool = XMLObjectProviderRegistrySupport.getParserPool();
            final Element element = pool.parse(new ByteArrayInputStream(metadataXml.getBytes(StandardCharsets.UTF_8)))
                    .getDocumentElement();
            final Unmarshaller unmarshaller = XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
                    .getUnmarshaller(element);
            final EntityDescriptor ed = (EntityDescriptor) unmarshaller.unmarshall(element);
            final SPSSODescriptor sp = ed.getSPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");
            if (sp == null) {
                throw new IllegalStateException("Metadata has no SPSSODescriptor");
            }

            // ACS list: the default (or first), then the rest as additional.
            String defaultAcs = null;
            final List<String> extraAcs = new ArrayList<>();
            for (final AssertionConsumerService acs : sp.getAssertionConsumerServices()) {
                if (acs.getLocation() == null) {
                    continue;
                }
                if (defaultAcs == null && (acs.isDefault() != null && acs.isDefault())) {
                    defaultAcs = acs.getLocation();
                } else if (defaultAcs == null) {
                    defaultAcs = acs.getLocation();
                } else {
                    extraAcs.add(acs.getLocation());
                }
            }

            final String slo = sp.getSingleLogoutServices().stream()
                    .map(SingleLogoutService::getLocation).filter(l -> l != null).findFirst().orElse(null);

            final String nameIdFormat = sp.getNameIDFormats().stream()
                    .map(NameIDFormat::getURI).filter(f -> f != null).findFirst().orElse(null);

            final String cert = sp.getKeyDescriptors().stream()
                    .filter(kd -> kd.getUse() == null || kd.getUse() == UsageType.SIGNING)
                    .map(SamlSpMetadataParser::firstCert).filter(c -> c != null).findFirst().orElse(null);

            final boolean wantSigned = sp.getWantAssertionsSigned() != null && sp.getWantAssertionsSigned();

            return new ParsedSp(ed.getEntityID(), defaultAcs, extraAcs, slo, cert, nameIdFormat, wantSigned);
        } catch (final Exception e) {
            throw new IllegalStateException("Invalid SP metadata: " + e.getMessage(), e);
        }
    }

    private static String firstCert(final KeyDescriptor kd) {
        if (kd.getKeyInfo() == null) {
            return null;
        }
        return kd.getKeyInfo().getX509Datas().stream()
                .flatMap(d -> d.getX509Certificates().stream())
                .map(org.opensaml.xmlsec.signature.X509Certificate::getValue)
                .filter(v -> v != null && !v.isBlank())
                .map(v -> "-----BEGIN CERTIFICATE-----\n" + v.replaceAll("\\s", "") + "\n-----END CERTIFICATE-----")
                .findFirst().orElse(null);
    }
}
