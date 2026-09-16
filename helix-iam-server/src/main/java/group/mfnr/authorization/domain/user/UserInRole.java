package group.mfnr.authorization.domain.user;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;

import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "user_in_role")
@IdClass(UserInRole.class)
public class UserInRole implements Serializable {

    @Column(name = "role_id")
    @JsonProperty
    private String roleId;

    @Column(name = "user_id")
    @Id
    @JsonProperty
    private String userId;

    @Column(name = "tenant_user_id")
    @Id
    @JsonProperty
    private String tenantUserId;

    public UserInRole() {

    }
    public UserInRole(final String roleId, final String userId, final String tenantUserId) {
        this.roleId = roleId;
        this.userId = userId;
        this.tenantUserId = tenantUserId;
    }



    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserInRole that = (UserInRole) o;
        return Objects.equals(roleId, that.roleId) && Objects.equals(tenantUserId, that.userId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(roleId, userId);
    }

    @Override
    public String toString() {
        return roleId;
    }
}
