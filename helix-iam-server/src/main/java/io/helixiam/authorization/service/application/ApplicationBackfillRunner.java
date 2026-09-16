package io.helixiam.authorization.service.application;

import io.helixiam.authorization.domain.ServiceProviderOAuthClient;
import io.helixiam.authorization.domain.application.ApplicationEntity;
import io.helixiam.authorization.domain.saml.SamlRelyingPartyEntity;
import io.helixiam.authorization.repository.ServiceProviderRepository;
import io.helixiam.authorization.repository.application.ApplicationRepository;
import io.helixiam.authorization.repository.saml.SamlRelyingPartyRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Helix IAM (Application model): on startup, wraps every existing OIDC client and SAML relying party that
 * isn't yet linked to an Application into one — named after the client_id / entity_id, copying the child's
 * subject claim + login flow up so behaviour is byte-identical (precedence is {@code app ?? client}). OIDC
 * runs before SAML so a same-named pair links to one application. Fully idempotent (guarded on
 * {@code application_id IS NULL} + get-or-create), so re-running is a no-op.
 */
@Component
@Order(50)
public class ApplicationBackfillRunner implements ApplicationRunner {

    private static final Logger LOG = LogManager.getLogger(ApplicationBackfillRunner.class);

    private final ServiceProviderRepository clients;
    private final SamlRelyingPartyRepository relyingParties;
    private final ApplicationRepository applications;

    public ApplicationBackfillRunner(final ServiceProviderRepository clients,
                                     final SamlRelyingPartyRepository relyingParties,
                                     final ApplicationRepository applications) {
        this.clients = clients;
        this.relyingParties = relyingParties;
        this.applications = applications;
    }

    @Override
    @Transactional
    public void run(final ApplicationArguments args) {
        int linked = 0;
        for (final ServiceProviderOAuthClient client : clients.findAll()) {
            if (Boolean.TRUE.equals(client.getDeleted()) || client.getApplicationId() != null) {
                continue;
            }
            final String realm = client.getRealmId() == null ? "master" : client.getRealmId();
            // name is the stable id (the client_id); the human label, if any, becomes the display name.
            final boolean hasLabel = client.getName() != null && !client.getName().isBlank();
            final String appName = hasLabel ? client.getName() : client.getClientId();
            final String displayName = hasLabel ? client.getName() : null;
            final ApplicationEntity app = getOrCreate(realm, appName, displayName,
                    client.getSubjectClaim(), client.getAuthFlowAlias());
            client.setApplicationId(app.getId());
            clients.save(client);
            linked++;
        }
        for (final SamlRelyingPartyEntity rp : relyingParties.findAll()) {
            if (rp.getApplicationId() != null) {
                continue;
            }
            final String realm = rp.getRealmId() == null ? "master" : rp.getRealmId();
            final ApplicationEntity app = getOrCreate(realm, rp.getEntityId(), null, null, null);
            rp.setApplicationId(app.getId());
            relyingParties.save(rp);
            linked++;
        }
        if (linked > 0) {
            LOG.info("Application backfill: linked {} protocol record(s) to their Application", linked);
        }
    }

    /** Get the (realm, name) application, or create it seeding the display name, subject claim + login flow. */
    private ApplicationEntity getOrCreate(final String realm, final String name, final String displayName,
                                          final String subjectClaim, final String authFlowAlias) {
        final String id = ApplicationEntity.key(realm, name);
        return applications.findById(id).orElseGet(() -> {
            final ApplicationEntity app = new ApplicationEntity();
            app.setId(id);
            app.setRealmId(realm);
            app.setName(name);
            app.setDisplayName(displayName);
            app.setSubjectClaim(subjectClaim);
            app.setAuthFlowAlias(authFlowAlias);
            app.setEnabled(true);
            return applications.save(app);
        });
    }
}
