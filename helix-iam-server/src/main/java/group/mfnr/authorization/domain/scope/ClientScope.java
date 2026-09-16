package group.mfnr.authorization.domain.scope;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.util.UUID;

/** Helix IAM E8.5: a client scope — a named bundle of claims a client can request, per realm. */
@Entity
@Table(name = "client_scope")
public class ClientScope {

    @Id
    @Column(name = "scope_id")
    private String scopeId;

    @Column(name = "tenant_id")
    private String tenantId;

    @Column(name = "name")
    private String name;

    @Column(name = "description")
    private String description;

    public ClientScope() {
    }

    public ClientScope(final String tenantId, final String name, final String description) {
        this.scopeId = UUID.randomUUID().toString();
        this.tenantId = tenantId;
        this.name = name;
        this.description = description;
    }

    public String getScopeId() {
        return scopeId;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getName() {
        return name;
    }

    public void setName(final String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(final String description) {
        this.description = description;
    }
}
