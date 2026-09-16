package group.mfnr.authorization.domain.provisioning;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.util.UUID;

/**
 * Helix IAM E11: a Dynamic Client Registration (RFC 7591/7592). Binds a dynamically-registered OAuth
 * client to its registration_access_token (stored hashed) so the registration can later be read /
 * updated / deleted (RFC 7592) by the holder of that token. One row per registered client.
 */
@Entity
@Table(name = "dcr_registration")
public class DcrRegistration {

    @Id
    @Column(name = "registration_id")
    private String registrationId;

    @Column(name = "realm_id")
    private String realmId;

    /** Surrogate id of the OAuth client created via the client-admin path. */
    @Column(name = "client_internal_id")
    private String clientInternalId;

    @Column(name = "client_id")
    private String clientId;

    /** SHA-256 hex of the registration_access_token (RFC 7592 management credential). */
    @Column(name = "registration_token_hash")
    private String registrationTokenHash;

    public DcrRegistration() {
    }

    public DcrRegistration(final String realmId, final String clientInternalId, final String clientId,
                           final String registrationTokenHash) {
        this.registrationId = UUID.randomUUID().toString();
        this.realmId = realmId;
        this.clientInternalId = clientInternalId;
        this.clientId = clientId;
        this.registrationTokenHash = registrationTokenHash;
    }

    public String getRegistrationId() {
        return registrationId;
    }

    public void setRegistrationId(final String registrationId) {
        this.registrationId = registrationId;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(final String realmId) {
        this.realmId = realmId;
    }

    public String getClientInternalId() {
        return clientInternalId;
    }

    public void setClientInternalId(final String clientInternalId) {
        this.clientInternalId = clientInternalId;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(final String clientId) {
        this.clientId = clientId;
    }

    public String getRegistrationTokenHash() {
        return registrationTokenHash;
    }

    public void setRegistrationTokenHash(final String registrationTokenHash) {
        this.registrationTokenHash = registrationTokenHash;
    }
}
