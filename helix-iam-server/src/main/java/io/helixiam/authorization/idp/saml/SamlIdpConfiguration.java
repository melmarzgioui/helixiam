package io.helixiam.authorization.idp.saml;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Helix IAM E7.1: binds {@link SamlIdpProperties}. The SAML IdP endpoints ({@link SamlIdpController})
 * are gated on {@code helix.idp.saml.enabled=true}; the issuer + request parser are plain components.
 */
@Configuration
@EnableConfigurationProperties(SamlIdpProperties.class)
public class SamlIdpConfiguration {
}
