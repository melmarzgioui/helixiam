package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.group.GroupAdminPublisher;
import io.helixiam.authorization.amqp.group.GroupDto;
import io.helixiam.authorization.amqp.group.GroupMemberDto;
import io.helixiam.authorization.amqp.group.GroupRef;
import io.helixiam.authorization.amqp.group.GroupWriteDto;
import io.helixiam.authorization.amqp.role.RoleDto;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Helix IAM E8.5-S4: admin REST API for a realm's user groups — hierarchical groups, membership and
 * group→role mappings, the backend behind the console's Groups screen. Realm comes from the path.
 */
@RestController
@RequestMapping("/admin/realms/{realmId}/groups")
public class GroupAdminController {

    private final GroupAdminPublisher publisher;

    public GroupAdminController(final GroupAdminPublisher publisher) {
        this.publisher = publisher;
    }

    @GetMapping
    public List<GroupDto> list(@PathVariable final String realmId) {
        return publisher.list(realmId);
    }

    @PostMapping
    public ResponseEntity<GroupDto> create(@PathVariable final String realmId, @Valid @RequestBody final GroupRequest request) {
        final GroupDto saved = publisher.create(new GroupWriteDto(realmId, null, request.name(), blankToNull(request.parentId())));
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    @PutMapping("/{groupId}")
    public ResponseEntity<GroupDto> update(@PathVariable final String realmId, @PathVariable final String groupId,
                                           @Valid @RequestBody final GroupRequest request) {
        final GroupDto saved = publisher.update(new GroupWriteDto(realmId, groupId, request.name(), blankToNull(request.parentId())));
        return saved == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(saved);
    }

    @DeleteMapping("/{groupId}")
    public ResponseEntity<Void> delete(@PathVariable final String realmId, @PathVariable final String groupId) {
        return Boolean.TRUE.equals(publisher.delete(new GroupRef(realmId, groupId, null, null)))
                ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    @GetMapping("/{groupId}/members")
    public List<GroupMemberDto> members(@PathVariable final String realmId, @PathVariable final String groupId) {
        return publisher.members(new GroupRef(realmId, groupId, null, null));
    }

    @PutMapping("/{groupId}/members/{userId}")
    public ResponseEntity<Void> addMember(@PathVariable final String realmId, @PathVariable final String groupId,
                                          @PathVariable final String userId) {
        return Boolean.TRUE.equals(publisher.addMember(new GroupRef(realmId, groupId, userId, null)))
                ? ResponseEntity.noContent().build() : ResponseEntity.status(HttpStatus.CONFLICT).build();
    }

    @DeleteMapping("/{groupId}/members/{userId}")
    public ResponseEntity<Void> removeMember(@PathVariable final String realmId, @PathVariable final String groupId,
                                             @PathVariable final String userId) {
        return Boolean.TRUE.equals(publisher.removeMember(new GroupRef(realmId, groupId, userId, null)))
                ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    @GetMapping("/{groupId}/roles")
    public List<RoleDto> roles(@PathVariable final String realmId, @PathVariable final String groupId) {
        return publisher.roles(new GroupRef(realmId, groupId, null, null));
    }

    @PutMapping("/{groupId}/roles/{roleId}")
    public ResponseEntity<Void> assignRole(@PathVariable final String realmId, @PathVariable final String groupId,
                                           @PathVariable final String roleId) {
        return Boolean.TRUE.equals(publisher.assignRole(new GroupRef(realmId, groupId, null, roleId)))
                ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    @DeleteMapping("/{groupId}/roles/{roleId}")
    public ResponseEntity<Void> unassignRole(@PathVariable final String realmId, @PathVariable final String groupId,
                                             @PathVariable final String roleId) {
        return Boolean.TRUE.equals(publisher.unassignRole(new GroupRef(realmId, groupId, null, roleId)))
                ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    private static String blankToNull(final String value) {
        return value == null || value.isBlank() ? null : value;
    }

    /** Create/rename body. */
    public record GroupRequest(@NotBlank(message = "Group name is required.") String name, String parentId) {
    }
}
