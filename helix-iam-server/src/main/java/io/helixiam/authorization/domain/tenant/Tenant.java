package io.helixiam.authorization.domain.tenant;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Entity
@Table(name = "tenant")
@EntityListeners(AuditingEntityListener.class)
public class Tenant {

    @Id
    @Column(name = "tenant_id")
    @JsonProperty
    private String tenantId;

    @Column(name = "name")
    private String name;

    @CreationTimestamp
    @Column(name = "creation_date", updatable = false)
    private Date creationDate;

    @OneToMany(fetch = FetchType.EAGER)
    @JoinColumn(name = "tenant_id", updatable = false, insertable = false)
    private List<TenantUser> tenantUsers = new ArrayList<>();

    @LastModifiedDate
    @Column(name = "modify_date")
    private Date modifyDate;


    public void setTenantId(final String tenantId) {
        this.tenantId = tenantId;
    }

    public void setName(final String name) {
        this.name = name;
    }
}
