package group.mfnr.authorization.domain.scope;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.util.UUID;

/** Helix IAM E8.5: a supported claim type (the catalogue entry) for a realm. */
@Entity
@Table(name = "claim_def")
public class ClaimDef {

    @Id
    @Column(name = "claim_id")
    private String claimId;

    @Column(name = "tenant_id")
    private String tenantId;

    @Column(name = "claim_key")
    private String claimKey;

    @Column(name = "label")
    private String label;

    @Column(name = "placeholder")
    private String placeholder;

    @Column(name = "mandatory")
    private boolean mandatory;

    public ClaimDef() {
    }

    public ClaimDef(final String tenantId, final String claimKey, final String label, final String placeholder,
                    final boolean mandatory) {
        this.claimId = UUID.randomUUID().toString();
        this.tenantId = tenantId;
        this.claimKey = claimKey;
        this.label = label;
        this.placeholder = placeholder;
        this.mandatory = mandatory;
    }

    public String getClaimId() {
        return claimId;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getClaimKey() {
        return claimKey;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(final String label) {
        this.label = label;
    }

    public String getPlaceholder() {
        return placeholder;
    }

    public void setPlaceholder(final String placeholder) {
        this.placeholder = placeholder;
    }

    public boolean isMandatory() {
        return mandatory;
    }

    public void setMandatory(final boolean mandatory) {
        this.mandatory = mandatory;
    }
}
