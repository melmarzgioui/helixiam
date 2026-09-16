package io.helixiam.authorization.idp.saml;

import io.helixiam.authorization.amqp.saml.SamlRelyingPartyConfig;
import io.helixiam.authorization.amqp.saml.SamlRelyingPartyConfigPublisher;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Helix IAM: loads persisted SAML relying parties from the identity-domain store over AMQP, so the
 * SAML IdP resolves the calling SP from the DB the admin console writes to (no restart, no config file).
 */
@Component
public class AmqpSamlRelyingPartyConfigSource implements SamlRelyingPartyConfigSource {

    private final SamlRelyingPartyConfigPublisher publisher;

    public AmqpSamlRelyingPartyConfigSource(final SamlRelyingPartyConfigPublisher publisher) {
        this.publisher = publisher;
    }

    @Override
    public List<SamlRelyingPartyConfig> load(final String realmId) {
        return publisher.list(realmId);
    }
}
