package group.mfnr.authorization.domain.provisioning;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Helix IAM E11/E7: per-realm provisioning configuration — the SCIM 2.0 inbound provisioning bearer
 * token (stored hashed, never in clear) and the Dynamic Client Registration policy (open vs gated by an
 * initial access token, default GATED so registration is not world-open). One row per realm.
 *
 * <p>Additive store, keyed by realm id (== tenant id); does not touch the {@code realm_config} row.
 */
@Entity
@Table(name = "realm_provisioning_config")
public class RealmProvisioningConfig {

    /** {@code true} = open registration (no initial access token); default {@code false} = GATED. */
    public static final boolean DEFAULT_DCR_OPEN = false;

    @Id
    @Column(name = "realm_id")
    private String realmId;

    /** SHA-256 hex of the realm's SCIM provisioning token; {@code null} = SCIM disabled (reject all). */
    @Column(name = "scim_token_hash")
    private String scimTokenHash;

    @Column(name = "dcr_open")
    private boolean dcrOpen = DEFAULT_DCR_OPEN;

    public RealmProvisioningConfig() {
    }

    public static RealmProvisioningConfig defaults(final String realmId) {
        final RealmProvisioningConfig config = new RealmProvisioningConfig();
        config.realmId = realmId;
        return config;
    }

    public String getRealmId() {
        return realmId;
    }

    public void setRealmId(final String realmId) {
        this.realmId = realmId;
    }

    public String getScimTokenHash() {
        return scimTokenHash;
    }

    public void setScimTokenHash(final String scimTokenHash) {
        this.scimTokenHash = scimTokenHash;
    }

    public boolean isDcrOpen() {
        return dcrOpen;
    }

    public void setDcrOpen(final boolean dcrOpen) {
        this.dcrOpen = dcrOpen;
    }
}
