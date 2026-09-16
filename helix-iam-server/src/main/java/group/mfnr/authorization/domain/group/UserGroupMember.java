package group.mfnr.authorization.domain.group;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.util.UUID;

/** Helix IAM E8.5-S4: a user's membership in a {@link UserGroup}. */
@Entity
@Table(name = "user_group_member")
public class UserGroupMember {

    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "group_id")
    private String groupId;

    @Column(name = "user_id")
    private String userId;

    public UserGroupMember() {
    }

    public UserGroupMember(final String groupId, final String userId) {
        this.id = UUID.randomUUID().toString();
        this.groupId = groupId;
        this.userId = userId;
    }

    public String getId() {
        return id;
    }

    public String getGroupId() {
        return groupId;
    }

    public String getUserId() {
        return userId;
    }
}
