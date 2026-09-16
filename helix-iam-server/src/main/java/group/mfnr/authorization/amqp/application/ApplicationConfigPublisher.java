package group.mfnr.authorization.amqp.application;


import java.util.List;

/**
 * Helix IAM: the admin API's + resolvers' seam onto the identity-domain Application store (owned by the
 * subscriber). JSON-marshalled two-copy DTOs, like the SAML-RP + federation exchanges.
 */
public interface ApplicationConfigPublisher {

    String EXCHANGE_AUTHORIZATION_APPLICATION_CONFIG = "exchange-authorization-application-config";
    String APPLICATION_SAVE = "authorization.application.save";
    String APPLICATION_LIST = "authorization.application.list";
    String APPLICATION_GET = "authorization.application.get";
    String APPLICATION_DELETE = "authorization.application.delete";

    /** Create or update an application; returns the persisted state. */
    ApplicationConfig save(final ApplicationConfig config);

    /** All applications for a realm. */
    List<ApplicationConfig> list(final String realmId);

    /** A single application, or {@code null} if none. */
    ApplicationConfig get(final ApplicationRef ref);

    /** Remove an application; {@code false} if it did not exist. */
    Boolean delete(final ApplicationRef ref);
}
