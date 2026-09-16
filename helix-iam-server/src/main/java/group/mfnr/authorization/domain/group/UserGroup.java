package group.mfnr.authorization.domain.group;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.util.UUID;

/**
 * Helix IAM E8.5-S4: a realm-scoped user group. Groups nest via {@code parentId} (null at top level);
 * members inherit the group's role mappings ({@link UserGroupRole}).
 */
@Entity
@Table(name = "user_group")
public class UserGroup {

    @Id
    @Column(name = "group_id")
    private String groupId;

    @Column(name = "name")
    private String name;

    @Column(name = "parent_id")
    private String parentId;

    @Column(name = "tenant_id")
    private String tenantId;

    public UserGroup() {
    }

    public UserGroup(final String name, final String parentId, final String tenantId) {
        this.groupId = UUID.randomUUID().toString();
        this.name = name;
        this.parentId = parentId;
        this.tenantId = tenantId;
    }

    public String getGroupId() {
        return groupId;
    }

    public void setGroupId(final String groupId) {
        this.groupId = groupId;
    }

    public String getName() {
        return name;
    }

    public void setName(final String name) {
        this.name = name;
    }

    public String getParentId() {
        return parentId;
    }

    public void setParentId(final String parentId) {
        this.parentId = parentId;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(final String tenantId) {
        this.tenantId = tenantId;
    }
}
