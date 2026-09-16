package group.mfnr.authorization.domain.scope;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.util.UUID;

/** Helix IAM E8.5: a claim mapped into a {@link ClientScope}. */
@Entity
@Table(name = "scope_claim")
public class ScopeClaim {

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "scope_id")
    private String scopeId;

    @Column(name = "claim_id")
    private String claimId;

    public ScopeClaim() {
    }

    public ScopeClaim(final String scopeId, final String claimId) {
        this.id = UUID.randomUUID().toString();
        this.scopeId = scopeId;
        this.claimId = claimId;
    }

    public String getId() {
        return id;
    }

    public String getScopeId() {
        return scopeId;
    }

    public String getClaimId() {
        return claimId;
    }
}
