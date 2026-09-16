package io.helixiam.authorization.domain.tenant;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.helixiam.authorization.domain.user.UserRoles;
import jakarta.persistence.*;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.util.*;

@Entity
@Table(name = "tenant_user")
@EntityListeners(AuditingEntityListener.class)
public class TenantUser {
    @Id
    @Column(name = "tenant_user_id")
    @GeneratedValue(strategy = GenerationType.UUID)
    @JsonProperty
    private String tenantUserId;

    @Column(name = "tenant_id")
    private String tenantId;
    @Column(name = "user_id")
    private String userId;

    @JsonProperty
    @ElementCollection(fetch = FetchType.EAGER)
    @MapKeyColumn(name="name", updatable = false, insertable = false)
    @Column(name="value", updatable = false, insertable = false)
    @CollectionTable(name="user_profile", joinColumns=@JoinColumn(name="user_id", referencedColumnName = "user_id", insertable = false, updatable = false))
    private Map<String, String> userAttributes;


    @JsonProperty
    @OneToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_in_role",
            joinColumns = {@JoinColumn(name = "tenant_user_id")},
            inverseJoinColumns = {@JoinColumn(name = "role_id")}
    )
    private List<UserRoles> roles = new ArrayList<>();

    public void setTenantId(final String tenantId) {
        this.tenantId = tenantId;
    }

    public void setUserId(final String userId) {
        this.userId = userId;
    }

    public String getTenantId() {
        return tenantId;
    }

    public String getUserId() {
        return userId;
    }

    public String getTenantUserId() {
        return tenantUserId;
    }

    public List<UserRoles> getRoles() {
        return roles;
    }

    public Map<String, String> getUserAttributes() {
        return userAttributes;
    }
}
