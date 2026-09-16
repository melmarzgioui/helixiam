package group.mfnr.authorization.controller.admin;

import group.mfnr.authorization.amqp.adminrbac.AdminPermissionDto;
import group.mfnr.authorization.amqp.adminrbac.AdminRbacPublisher;
import group.mfnr.authorization.amqp.adminrbac.AdminRoleGrantWriteDto;
import group.mfnr.authorization.amqp.adminrbac.AdminRoleGrantsDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Helix IAM: admin-RBAC REST API — catalogue, role grants, set (realm forced from path, never thrown). */
class AdminRoleControllerTest {

    private AdminRbacPublisher publisher;
    private AdminRoleController controller;

    @BeforeEach
    void setUp() {
        publisher = mock(AdminRbacPublisher.class);
        controller = new AdminRoleController(publisher);
    }

    @Test
    void permissions_returnsCatalogue() {
        when(publisher.catalog("gov")).thenReturn(List.of(new AdminPermissionDto("manage-users", "Manage users")));
        assertThat(controller.permissions("gov")).extracting(AdminPermissionDto::key).containsExactly("manage-users");
    }

    @Test
    void roles_delegatesToPublisherForThatRealm() {
        final AdminRoleGrantsDto row = new AdminRoleGrantsDto("gov", "r-1", "user-admin", List.of("manage-users"));
        when(publisher.roles("gov")).thenReturn(List.of(row));
        assertThat(controller.roles("gov")).containsExactly(row);
    }

    @Test
    void setPermissions_buildsWriteFromPath_andReturns200() {
        when(publisher.set(any(AdminRoleGrantWriteDto.class))).thenAnswer(inv -> {
            final AdminRoleGrantWriteDto w = inv.getArgument(0);
            return new AdminRoleGrantsDto(w.realmId(), w.roleId(), "user-admin", w.permissions());
        });

        final ResponseEntity<?> response = controller.setPermissions("gov", "r-1",
                new AdminRoleController.AdminRoleGrantsRequest(List.of("manage-users", "view-users")));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        final ArgumentCaptor<AdminRoleGrantWriteDto> captor = ArgumentCaptor.forClass(AdminRoleGrantWriteDto.class);
        verify(publisher).set(captor.capture());
        assertThat(captor.getValue().realmId()).isEqualTo("gov");
        assertThat(captor.getValue().roleId()).isEqualTo("r-1");
        assertThat(captor.getValue().permissions()).containsExactly("manage-users", "view-users");
    }

    @Test
    void setPermissions_returns400_whenSubscriberRejects_neverThrows() {
        when(publisher.set(any(AdminRoleGrantWriteDto.class))).thenReturn(null);
        final ResponseEntity<?> response = controller.setPermissions("gov", "ghost",
                new AdminRoleController.AdminRoleGrantsRequest(List.of("manage-users")));
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
}
